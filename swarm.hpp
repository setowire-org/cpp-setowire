#pragma once

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
using SockFd = SOCKET;
#else
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
using SockFd = int;
static constexpr SockFd INVALID_SOCKET = -1;
#endif

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <curl/curl.h>
#include "constants.hpp"
#include "crypto.hpp"
#include "dht_lib.hpp"
#include "framing.hpp"
#include "peer.hpp"
#include "structs.hpp"

static inline std::string jsonStr(const std::string& k, const std::string& v) {
    return "\"" + k + "\":\"" + v + "\"";
}
static inline std::string jsonInt(const std::string& k, int v) {
    return "\"" + k + "\":" + std::to_string(v);
}

static inline std::string jsonGet(const std::string& json, const std::string& key) {
    auto kq = "\"" + key + "\"";
    auto p  = json.find(kq);
    if (p == std::string::npos) return {};
    p = json.find(':', p + kq.size());
    if (p == std::string::npos) return {};
    p++;
    while (p < json.size() && json[p] == ' ') p++;
    if (p >= json.size()) return {};
    if (json[p] == '"') {
        auto e = json.find('"', p + 1);
        return (e == std::string::npos) ? "" : json.substr(p + 1, e - p - 1);
    }
    auto e = json.find_first_of(",}", p);
    return (e == std::string::npos) ? json.substr(p) : json.substr(p, e - p);
}

static inline int jsonGetInt(const std::string& json, const std::string& key, int def = 0) {
    auto v = jsonGet(json, key);
    if (v.empty()) return def;
    try { return std::stoi(v); } catch (...) { return def; }
}

struct PeerInfo {
    std::string id;
    std::string ip;
    uint16_t    port    = 0;
    std::string lip;
    uint16_t    lport   = 0;
    std::string nat;
    int64_t     lastSeen = 0;
};

struct SwarmOpts {
    std::vector<uint8_t>      seed;
    int                       maxPeers     = MAX_PEERS;
    bool                      relay        = false;
    std::vector<std::string>  bootstrap;
    std::vector<std::string>  seeds;
    std::vector<std::string>  pipingServers;
    bool                      exclusivePiping = false;
    std::vector<std::string>  bootstrapHttp;
    std::function<void(const std::vector<PeerInfo>&)>   onSavePeers;
    std::function<std::vector<PeerInfo>()>              onLoadPeers;
};

class Swarm {
public:
    std::string natType       = "unknown";
    std::string publicAddress;
    std::string _id;

    std::function<void(Peer*, const PeerInfo&)>            onConnection;
    std::function<void(const std::vector<uint8_t>&, Peer*)> onData;
    std::function<void(const std::string&)>                onDisconnect;
    std::function<void(const std::string&, const std::vector<uint8_t>&)> onSync;
    std::function<void()>                                  onNat;
    std::function<void(const std::vector<PeerInfo>&)>      onSavePeers;
    std::function<std::vector<PeerInfo>()>                 onLoadPeers;

    explicit Swarm(const SwarmOpts& opts = {})
        : _maxPeers(opts.maxPeers)
        , _isRelay(opts.relay)
        , _bloom(BLOOM_BITS, BLOOM_HASHES)
        , _gossipSeen(GOSSIP_MAX, GOSSIP_TTL)
        , _store(SYNC_CACHE_MAX)
        , _payloadCache(8192)
        , _meshD(D_DEFAULT)
    {
        if (!opts.pipingServers.empty()) {
            std::set<std::string> s(opts.pipingServers.begin(), opts.pipingServers.end());
            if (!opts.exclusivePiping)
                s.insert(PIPING_SERVERS.begin(), PIPING_SERVERS.end());
            _pipingServers.assign(s.begin(), s.end());
        } else {
            _pipingServers = PIPING_SERVERS;
        }

        _bootstrapNodes = opts.bootstrap;

        {
            auto extra = opts.bootstrapHttp;
            extra.insert(extra.end(),
                         HARDCODED_HTTP_BOOTSTRAP.begin(), HARDCODED_HTTP_BOOTSTRAP.end());
            _bootstrapHttp = std::move(extra);
        }

        {
            auto extra = opts.seeds;
            extra.insert(extra.end(), HARDCODED_SEEDS.begin(), HARDCODED_SEEDS.end());
            _hardcodedSeeds = std::move(extra);
        }

        _myX25519 = generateX25519(opts.seed.empty() ? nullptr : &opts.seed);
        {
            uint8_t hash[SHA256_DIGEST_LENGTH];
            SHA256(_myX25519.pubRaw.data(), _myX25519.pubRaw.size(), hash);
            char hex[41];
            for (int i = 0; i < 20; i++) snprintf(hex + i * 2, 3, "%02x", hash[i]);
            _id = std::string(hex, 40);
        }

        _localIp = _getLocalIp();

        onSavePeers = opts.onSavePeers;
        onLoadPeers = opts.onLoadPeers;
        _loadPeerCache();

        _init();
    }

    ~Swarm() { destroy(); }

    std::vector<Peer*> peers() const {
        std::vector<Peer*> v;
        v.reserve(_peers.size());
        for (auto& [_, p] : _peers) v.push_back(p.get());
        return v;
    }

    int size() const { return (int)_peers.size(); }

    std::vector<Peer*> meshPeers() const {
        std::vector<Peer*> v;
        for (auto& [_, p] : _peers)
            if (p->inMesh) v.push_back(p.get());
        return v;
    }

    void store(const std::string& key, const std::vector<uint8_t>& value) {
        _store.add(key, value);
        _announceHave({ key });
    }

    std::optional<std::vector<uint8_t>> fetchLocal(const std::string& key) const {
        return _store.get(key);
    }

    void fetchAsync(const std::string& key,
                    std::function<void(const std::vector<uint8_t>&)> onFound,
                    std::function<void()> onTimeout = {},
                    int timeoutMs = SYNC_TIMEOUT)
    {
        auto local = _store.get(key);
        if (local) { onFound(*local); return; }

        _wantPending[key] = { std::move(onFound), onTimeout ? std::move(onTimeout) : []{} };
        _sendWantAll(key);

        std::thread([this, key, timeoutMs]{
            std::this_thread::sleep_for(std::chrono::milliseconds(timeoutMs));
            auto it = _wantPending.find(key);
            if (it != _wantPending.end()) {
                auto cb = std::move(it->second.reject);
                _wantPending.erase(it);
                if (cb) cb();
            }
        }).detach();
    }

    int broadcast(const std::vector<uint8_t>& data) {
        int n = 0;
        for (auto& [_, p] : _peers) {
            if (p->_session && p->_open) { p->_enqueue(data); n++; }
        }
        return n;
    }

    void join(const std::string& topicHex, bool announce = true, bool lookup = true) {
        uint8_t h[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const uint8_t*>(topicHex.data()), topicHex.size(), h);
        char hex[41];
        for (int i = 0; i < 20; i++) snprintf(hex + i * 2, 3, "%02x", h[i]);
        _topicHash = std::string(hex, 24);

        _startDHT(announce, lookup);
        _startPiping(announce, lookup);
        _dialHardcodedSeeds();
        _dialPeerCache();
        _startBootstrapAnnounce();
    }

    void destroy() {
        if (_destroyed) return;
        _destroyed = true;

        std::vector<uint8_t> goaway = { F_GOAWAY };
        for (auto& [_, p] : _peers) {
            p->writeCtrl(goaway);
            p->destroy();
        }
        _peers.clear();
        _addrToId.clear();

        _closeSockets();
        _stopTimers();
    }

    void _floodMesh(const std::vector<uint8_t>& plain, const std::string& excludeId) {
        for (auto* p : meshPeers()) {
            if (p->id != excludeId && p->_session && p->_open)
                p->_enqueue(plain);
        }
    }

    BloomFilter _bloom;
    std::unordered_map<std::string, std::string> _addrToId;

private:

    bool        _destroyed  = false;
    int         _maxPeers;
    bool        _isRelay;
    std::string _localIp;
    uint16_t    _lport      = 0;
    std::string _topicHash;

    X25519KeyPair _myX25519;

    std::unordered_map<std::string, std::unique_ptr<Peer>> _peers;
    std::unordered_set<std::string>                        _dialing;

    std::unordered_map<std::string, PeerInfo> _relays;
    std::unordered_map<std::string, int64_t>  _relayBans;
    bool _isRelayNode = false;

    std::vector<std::string> _pipingServers;
    std::vector<std::string> _bootstrapNodes;
    std::vector<std::string> _bootstrapHttp;
    std::vector<std::string> _hardcodedSeeds;
    std::unordered_map<std::string, PeerInfo> _peerCache;

    struct ExtAddr { std::string ip; uint16_t port; };
    std::optional<ExtAddr> _ext;

    LRU<int>                       _gossipSeen;
    int                            _meshD;
    int64_t                        _lastMeshAdapt = 0;
    int64_t                        _lastPex       = 0;
    int64_t                        _lastCacheEmit = 0;
    std::vector<std::vector<uint8_t>> _ihaveBuf;

    LRU<std::vector<uint8_t>> _store;
    PayloadCache               _payloadCache;

    struct WantEntry {
        std::function<void(const std::vector<uint8_t>&)> resolve;
        std::function<void()>                            reject;
    };
    std::unordered_map<std::string, WantEntry> _wantPending;

    struct ChunkAssembly {
        int total = 0;
        std::map<int, std::vector<uint8_t>> pieces;
    };
    std::unordered_map<std::string, ChunkAssembly> _chunkAssembly;

    struct ReliableTx {
        int              total = 0;
        std::vector<int> acked;
        bool             done  = false;
    };
    std::unordered_map<std::string, ReliableTx> _reliableTx;

    SockFd _sock      = INVALID_SOCKET;
    SockFd _mcastSock = INVALID_SOCKET;

    std::thread             _recvThread;
    std::thread             _heartbeatThread;
    std::thread             _batchThread;

    BatchSender _batch{ UdpSendFn{[this](const std::string& ip, uint16_t port,
                                          const std::vector<uint8_t>& buf) {
        _udpSend(ip, port, buf);
    }} };

    std::mt19937 _rng{ std::random_device{}() };

    void _init() {
        _sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (_sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = 0;
        if (bind(_sock, (sockaddr*)&addr, sizeof(addr)) < 0) return;

        socklen_t len = sizeof(addr);
        getsockname(_sock, (sockaddr*)&addr, &len);
        _lport = ntohs(addr.sin_port);

        _recvThread = std::thread([this]{ _recvLoop(); });

        _heartbeatThread = std::thread([this]{
            while (!_destroyed) {
                std::this_thread::sleep_for(std::chrono::milliseconds(HEARTBEAT_MS));
                if (!_destroyed) _heartbeat();
            }
        });

        _batchThread = std::thread([this]{
            while (!_destroyed) {
                std::this_thread::sleep_for(std::chrono::milliseconds(BATCH_INTERVAL));
                if (!_destroyed) _batch.flush();
            }
        });

        _discoverNat();

        _startLan();
    }

    void _udpSend(const std::string& ip, uint16_t port, const std::vector<uint8_t>& buf) {
        if (_sock == INVALID_SOCKET || buf.empty()) return;
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_port   = htons(port);
        inet_pton(AF_INET, ip.c_str(), &dst.sin_addr);
        sendto(_sock, (const char*)buf.data(), (int)buf.size(), 0,
               (sockaddr*)&dst, sizeof(dst));
    }

    void _recvLoop() {
        std::vector<uint8_t> buf(65536);
        while (!_destroyed) {
            sockaddr_in src{};
            socklen_t   srcLen = sizeof(src);
            int n = recvfrom(_sock, (char*)buf.data(), (int)buf.size(), 0,
                             (sockaddr*)&src, &srcLen);
            if (n <= 0) continue;
            char ipBuf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src.sin_addr, ipBuf, sizeof(ipBuf));
            std::string ip(ipBuf);
            uint16_t    port = ntohs(src.sin_port);
            _onUdp(ip, port, std::vector<uint8_t>(buf.begin(), buf.begin() + n));
        }
    }

    void _closeSockets() {
        if (_sock != INVALID_SOCKET) {
#ifdef _WIN32
            closesocket(_sock);
#else
            close(_sock);
#endif
            _sock = INVALID_SOCKET;
        }
    }

    void _stopTimers() {
        if (_recvThread.joinable())     _recvThread.detach();
        if (_heartbeatThread.joinable()) _heartbeatThread.detach();
        if (_batchThread.joinable())    _batchThread.detach();
    }

    void _onUdp(const std::string& ip, uint16_t port, const std::vector<uint8_t>& buf) {
        if (buf.empty()) return;
        const std::string addr = ip + ":" + std::to_string(port);
        const uint8_t     type = buf[0];

        if (type == F_BATCH) {
            if (buf.size() < 2) return;
            int count = buf[1];
            int off   = 2;
            for (int i = 0; i < count && off + 2 <= (int)buf.size(); i++) {
                int len = (buf[off] << 8) | buf[off + 1];
                off += 2;
                if (off + len > (int)buf.size()) break;
                _onUdp(ip, port, std::vector<uint8_t>(buf.begin() + off, buf.begin() + off + len));
                off += len;
            }
            return;
        }

        if (type == 0xA1) { _onHello(ip, port, buf);    return; }
        if (type == 0xA2) { _onHelloAck(ip, port, buf); return; }

        if (type == F_RELAY_ANN) { _onRelayAnn(ip, port, buf); return; }
        if (type == F_RELAY_REQ) { _onRelayReq(ip, port, buf); return; }
        if (type == F_RELAY_FWD) { _onRelayFwd(ip, port, buf); return; }

        if (type == F_PEX) { _onPex(ip, port, buf); return; }

        if (type == F_LAN) { _onLan(ip, port, buf); return; }

        auto* peer = _peerByAddr(addr);
        if (!peer) return;

        peer->_touch(addr);

        switch (type) {
        case F_PING: _onPing(peer, ip, port, buf); break;
        case F_PONG: _onPong(peer, buf);            break;
        case F_DATA: _onData(peer, buf);            break;
        case F_FRAG: _onFrag(peer, buf);            break;
        case F_GOAWAY:
            _drop(peer->id);
            if (onDisconnect) onDisconnect(peer->id);
            break;
        case F_HAVE: _onHave(peer, buf); break;
        case F_WANT: _onWant(peer, buf); break;
        case F_CHUNK: _onChunk(peer, buf); break;
        case F_CHUNK_ACK: _onChunkAck(peer, buf); break;
        default: break;
        }
    }

    std::string _id16() const { return _id.substr(0, 16); }

    void _sendHello(const std::string& ip, uint16_t port) {
        std::vector<uint8_t> frame;
        frame.reserve(1 + 8 + 32);
        frame.push_back(0xA1);
        auto idBytes = _hexToBytes(_id16());
        frame.insert(frame.end(), idBytes.begin(), idBytes.end());
        frame.insert(frame.end(), _myX25519.pubRaw.begin(), _myX25519.pubRaw.end());
        _udpSend(ip, port, frame);
    }

    void _onHello(const std::string& ip, uint16_t port, const std::vector<uint8_t>& buf) {
        if ((int)buf.size() < 1 + 8 + 32) return;
        std::string peerId = _bytesToHex(buf.data() + 1, 8);
        if (peerId == _id16()) return;

        std::vector<uint8_t> theirPub(buf.begin() + 9, buf.begin() + 41);
        const std::string addr = ip + ":" + std::to_string(port);

        std::vector<uint8_t> ack;
        ack.reserve(1 + 8 + 32);
        ack.push_back(0xA2);
        auto idBytes = _hexToBytes(_id16());
        ack.insert(ack.end(), idBytes.begin(), idBytes.end());
        ack.insert(ack.end(), _myX25519.pubRaw.begin(), _myX25519.pubRaw.end());
        _udpSend(ip, port, ack);

        _finishHandshake(peerId, addr, theirPub);
    }

    void _onHelloAck(const std::string& ip, uint16_t port, const std::vector<uint8_t>& buf) {
        if ((int)buf.size() < 1 + 8 + 32) return;
        std::string peerId = _bytesToHex(buf.data() + 1, 8);
        if (peerId == _id16()) return;

        std::vector<uint8_t> theirPub(buf.begin() + 9, buf.begin() + 41);
        const std::string addr = ip + ":" + std::to_string(port);
        _finishHandshake(peerId, addr, theirPub);
    }

    void _finishHandshake(const std::string& peerId, const std::string& addr,
                          const std::vector<uint8_t>& theirPub)
    {
        if (_peers.count(peerId)) {
            _peers[peerId]->_touch(addr);
            return;
        }
        if ((int)_peers.size() >= _maxPeers) return;

        auto session = deriveSession(_myX25519.privateKey, theirPub);

        const bool iAmLo = (_id16() < peerId);
        if (!iAmLo) {
            std::swap(session.sendKey, session.recvKey);
        }

        auto* swarm = this;
        auto peer = std::make_unique<Peer>(
            this, peerId, addr,
            [this](const std::string& ip, uint16_t port, const std::vector<uint8_t>& b){
                _batch.send(ip, port, b);
            },
            [](uint8_t* buf, int len){ RAND_bytes(buf, len); },
            [swarm, peerId](const std::vector<uint8_t>& plain){
                auto msgKey = xorHash(plain);
                if (swarm->_bloom.seen(msgKey)) return;
                auto* p = swarm->_peers.count(peerId) ? swarm->_peers[peerId].get() : nullptr;
                if (!p) return;
                if (swarm->onData) swarm->onData(plain, p);
                swarm->_floodMesh(plain, peerId);
            }
        );

        peer->_theirPubRaw = theirPub;
        peer->_session     = std::move(session);
        peer->_touch(addr);

        _addrToId[addr] = peerId;
        _dialing.erase(peerId);
        _dialing.erase(addr);

        Peer* rawPtr = peer.get();
        _peers[peerId] = std::move(peer);
        _addToMesh(rawPtr);
        _gossipPeer(addr, peerId);
        _sendHaveSummary(rawPtr);

        PeerInfo info{ peerId, addr.substr(0, addr.rfind(':')),
                       (uint16_t)std::stoi(addr.substr(addr.rfind(':') + 1)) };
        if (onConnection) onConnection(rawPtr, info);

        if (_isRelay || RELAY_NAT_OPEN.count(natType))
            _announceRelay();
    }

    void _onPing(Peer* peer, const std::string& ip, uint16_t port,
                 const std::vector<uint8_t>& buf)
    {
        if (buf.size() < 9) return;
        std::vector<uint8_t> pong(buf.size());
        pong[0] = F_PONG;
        std::copy(buf.begin() + 1, buf.end(), pong.begin() + 1);
        _udpSend(ip, port, pong);
    }

    void _onPong(Peer* peer, const std::vector<uint8_t>& buf) {
        if (buf.size() < 9) return;
        uint64_t sent = 0;
        for (int i = 0; i < 8; i++) sent = (sent << 8) | buf[1 + i];
        double rtt = (double)(now_ms() - (int64_t)sent);
        if (rtt > 0 && rtt < 10000)
            peer->_touch(peer->_best, rtt);
        peer->_onAck();
    }

    void _onData(Peer* peer, const std::vector<uint8_t>& buf) {
        if (!peer->_session) return;
        auto plain = decrypt(*peer->_session, std::vector<uint8_t>(buf.begin() + 1, buf.end()));
        if (!plain || plain->empty()) return;

        peer->_onAck();
        peer->_scoreUp();

        const std::string msgKey = xorHash(*plain);
        _payloadCache.set(msgKey, buf);
        {
            std::vector<uint8_t> mkBytes(msgKey.begin(), msgKey.end());
            _ihaveBuf.push_back(mkBytes);
        }

        if ((*plain)[0] == 0x7B) {
            try {
                std::string js(plain->begin(), plain->end());
                if (js.find("\"_gossip\"") != std::string::npos) {
                    PeerInfo info = _parseInfo(js);
                    if (!info.id.empty()) _meet(info);
                    return;
                }
            } catch (...) {}
        }

        if ((int)plain->size() < 4) return;
        uint32_t seq = ((uint32_t)(*plain)[0] << 24) | ((uint32_t)(*plain)[1] << 16)
                     | ((uint32_t)(*plain)[2] <<  8) |  (uint32_t)(*plain)[3];
        std::vector<uint8_t> payload(plain->begin() + 4, plain->end());
        peer->_jitter.push(seq, payload);
    }

    void _onFrag(Peer* peer, const std::vector<uint8_t>& buf) {
        if ((int)buf.size() < 1 + FRAG_HDR) return;
        const uint8_t* hdr     = buf.data() + 1;
        std::string    fragId  = _bytesToHex(hdr, 8);
        int            fragIdx = (hdr[8] << 8) | hdr[9];
        int            total   = (hdr[10] << 8) | hdr[11];
        std::vector<uint8_t> data(buf.begin() + 1 + FRAG_HDR, buf.end());
        auto assembled = peer->_fragger.add(fragId, fragIdx, total, data);
        if (assembled) _onData(peer, _prependByte(F_DATA, *assembled));
    }

    void _sendHaveSummary(Peer* peer) {
        auto allKeys = _store.keys();
        if (allKeys.empty()) return;
        if ((int)allKeys.size() > HAVE_BATCH)
            allKeys.resize(HAVE_BATCH);
        _sendHaveKeys(peer, allKeys);
    }

    void _sendHaveKeys(Peer* peer, const std::vector<std::string>& keys) {
        if (keys.empty()) return;
        int cnt = std::min((int)keys.size(), HAVE_BATCH);
        std::vector<uint8_t> frame = { F_HAVE, (uint8_t)cnt };
        for (int i = 0; i < cnt; i++) {
            auto& k = keys[i];
            std::vector<uint8_t> kb(k.begin(), k.end());
            frame.push_back((uint8_t)kb.size());
            frame.insert(frame.end(), kb.begin(), kb.end());
        }
        peer->writeCtrl(frame);
    }

    void _announceHave(const std::vector<std::string>& keys) {
        if (keys.empty()) return;

        for (auto& k : keys) {
            std::vector<uint8_t> kbuf(k.begin(), k.end());
            _ihaveBuf.push_back(kbuf);
        }

        for (auto* p : meshPeers()) {
            if (p->_session && p->_open) _sendHaveKeys(p, keys);
        }
    }

    void _emitIhave() {
        if (_ihaveBuf.empty()) return;
        int take = std::min((int)_ihaveBuf.size(), IHAVE_MAX);
        std::vector<std::vector<uint8_t>> ids(
            _ihaveBuf.end() - take, _ihaveBuf.end());
        _ihaveBuf.erase(_ihaveBuf.end() - take, _ihaveBuf.end());

        std::vector<Peer*> targets;
        for (auto& [_, p] : _peers) {
            if (!p->inMesh && p->_session && p->_open)
                targets.push_back(p.get());
            if ((int)targets.size() >= D_GOSSIP) break;
        }
        if (targets.empty()) return;

        std::vector<uint8_t> payload = { 0x07 };
        for (auto& id : ids)
            payload.insert(payload.end(), id.begin(), id.end());

        for (auto* p : targets) p->writeCtrl(payload);
    }

    void _onHave(Peer* peer, const std::vector<uint8_t>& buf) {
        if (buf.size() < 2) return;
        int count = buf[1];
        int off   = 2;
        for (int i = 0; i < count && off < (int)buf.size(); i++) {
            int klen = buf[off++];
            if (off + klen > (int)buf.size()) break;
            std::string key(buf.begin() + off, buf.begin() + off + klen);
            off += klen;
            if (_wantPending.count(key)) {
                std::vector<uint8_t> frame = { F_WANT, (uint8_t)key.size() };
                frame.insert(frame.end(), key.begin(), key.end());
                peer->writeCtrl(frame);
            }
        }
    }

    void _sendWant(Peer* peer, const std::string& key) {
        std::vector<uint8_t> frame = { F_WANT, (uint8_t)key.size() };
        frame.insert(frame.end(), key.begin(), key.end());
        peer->writeCtrl(frame);
    }

    void _sendWantAll(const std::string& key) {
        std::vector<uint8_t> frame = { F_WANT, (uint8_t)key.size() };
        frame.insert(frame.end(), key.begin(), key.end());
        for (auto& [_, p] : _peers) {
            if (p->_session && p->_open) p->writeCtrl(frame);
        }
    }

    void _onWant(Peer* peer, const std::vector<uint8_t>& buf) {
        if ((int)buf.size() < 2) return;
        int klen = buf[1];
        if (2 + klen > (int)buf.size()) return;
        std::string key(buf.begin() + 2, buf.begin() + 2 + klen);
        auto val = _store.get(key);
        if (!val) return;

        std::vector<uint8_t> kb(key.begin(), key.end());

        if ((int)val->size() <= SYNC_CHUNK_SIZE) {
            std::vector<uint8_t> msg = { F_CHUNK, (uint8_t)kb.size() };
            msg.insert(msg.end(), kb.begin(), kb.end());
            msg.push_back((uint8_t)(val->size() >> 8));
            msg.push_back((uint8_t)(val->size() & 0xFF));
            msg.insert(msg.end(), val->begin(), val->end());
            peer->writeCtrl(msg);
            return;
        }

        int total = ((int)val->size() + SYNC_CHUNK_SIZE - 1) / SYNC_CHUNK_SIZE;
        std::string txKey = key + ":" + peer->id;
        if (_reliableTx.count(txKey)) return;
        auto& tx = _reliableTx[txKey];
        tx.total = total;
        tx.acked.assign(total, 0);

        for (int i = 0; i < total && i < 8; i++) {
            int start = i * SYNC_CHUNK_SIZE;
            int end   = std::min(start + SYNC_CHUNK_SIZE, (int)val->size());
            std::vector<uint8_t> chunk = { F_CHUNK, (uint8_t)kb.size() };
            chunk.insert(chunk.end(), kb.begin(), kb.end());
            chunk.push_back(0xFF); chunk.push_back(0xFF);
            chunk.push_back((uint8_t)(i >> 8));   chunk.push_back((uint8_t)(i & 0xFF));
            chunk.push_back((uint8_t)(total >> 8)); chunk.push_back((uint8_t)(total & 0xFF));
            chunk.insert(chunk.end(), val->begin() + start, val->begin() + end);
            peer->writeCtrl(chunk);
        }
    }

    void _onChunk(Peer* peer, const std::vector<uint8_t>& buf) {
        if ((int)buf.size() < 4) return;
        int o    = 1;
        int klen = buf[o++];
        if (o + klen + 2 > (int)buf.size()) return;
        std::string key(buf.begin() + o, buf.begin() + o + klen); o += klen;
        uint16_t vlen = ((uint16_t)buf[o] << 8) | buf[o + 1]; o += 2;

        if (vlen != 0xFFFF) {
            if (o + vlen > (int)buf.size()) return;
            std::vector<uint8_t> val(buf.begin() + o, buf.begin() + o + vlen);
            _store.add(key, val);
            if (onSync) onSync(key, val);
            auto it = _wantPending.find(key);
            if (it != _wantPending.end()) {
                it->second.resolve(val);
                _wantPending.erase(it);
            }
        } else {
            if (o + 4 > (int)buf.size()) return;
            uint16_t idx   = ((uint16_t)buf[o] << 8) | buf[o + 1]; o += 2;
            uint16_t total = ((uint16_t)buf[o] << 8) | buf[o + 1]; o += 2;
            std::vector<uint8_t> data(buf.begin() + o, buf.end());

            std::vector<uint8_t> ack;
            ack.push_back(F_CHUNK_ACK);
            ack.push_back((uint8_t)key.size());
            ack.insert(ack.end(), key.begin(), key.end());
            ack.push_back(idx >> 8);
            ack.push_back(idx & 0xFF);
            peer->writeCtrl(ack);

            auto& asm_ = _chunkAssembly[key];
            asm_.total = total;
            asm_.pieces[idx] = data;
            if ((int)asm_.pieces.size() == total) {
                std::vector<uint8_t> assembled;
                for (int i = 0; i < total; i++) {
                    auto& piece = asm_.pieces[i];
                    assembled.insert(assembled.end(), piece.begin(), piece.end());
                }
                _chunkAssembly.erase(key);
                _store.add(key, assembled);
                if (onSync) onSync(key, assembled);
                auto it = _wantPending.find(key);
                if (it != _wantPending.end()) {
                    it->second.resolve(assembled);
                    _wantPending.erase(it);
                }
            }
        }
    }

    void _onChunkAck(Peer* peer, const std::vector<uint8_t>& buf) {
        if ((int)buf.size() < 5) return;
        int o    = 1;
        int klen = buf[o++];
        if (o + klen + 2 > (int)buf.size()) return;
        std::string key(buf.begin() + o, buf.begin() + o + klen); o += klen;
        uint16_t idx = ((uint16_t)buf[o] << 8) | buf[o + 1];

        auto it = _reliableTx.find(key + ":" + peer->id);
        if (it == _reliableTx.end() || it->second.done) return;
        auto& tx = it->second;
        if (idx < (int)tx.acked.size()) {
            tx.acked[idx] = 1;
            bool allDone = true;
            for (int i = 0; i < (int)tx.acked.size(); i++)
                if (i < tx.total && !tx.acked[i]) { allDone = false; break; }
            if (allDone) { tx.done = true; _reliableTx.erase(it); }
        }
        peer->_onAck();
    }

    void _announceRelay() {
        auto idBytes = _hexToBytes(_id16());
        std::vector<uint8_t> frame = { F_RELAY_ANN };
        frame.insert(frame.end(), idBytes.begin(), idBytes.end());
        const std::string ip   = _ext ? _ext->ip : _localIp;
        const uint16_t    port = _ext ? _ext->port : _lport;
        frame.push_back((uint8_t)ip.size());
        frame.insert(frame.end(), ip.begin(), ip.end());
        frame.push_back(port >> 8);
        frame.push_back(port & 0xFF);
        for (auto& [_, p] : _peers) {
            if (p->_session && p->_open) p->writeCtrl(frame);
        }
    }

    void _onRelayAnn(const std::string&, uint16_t, const std::vector<uint8_t>& buf) {
        if ((int)buf.size() < 1 + 8 + 1 + 1 + 2) return;
        std::string relayId = _bytesToHex(buf.data() + 1, 8);
        int off = 1 + 8;
        int ipLen = buf[off++];
        if (off + ipLen + 2 > (int)buf.size()) return;
        std::string relayIp(buf.begin() + off, buf.begin() + off + ipLen);
        off += ipLen;
        uint16_t relayPort = ((uint16_t)buf[off] << 8) | buf[off + 1];

        auto ban = _relayBans.find(relayId);
        if (ban != _relayBans.end() && (now_ms() - ban->second) < RELAY_BAN_MS) return;

        if ((int)_relays.size() >= RELAY_MAX) {
            std::string oldest;
            int64_t oldestTs = INT64_MAX;
            for (auto& [rid, ri] : _relays)
                if (ri.lastSeen < oldestTs) { oldestTs = ri.lastSeen; oldest = rid; }
            if (!oldest.empty()) _relays.erase(oldest);
        }
        _relays[relayId] = { relayId, relayIp, relayPort, {}, 0, {}, now_ms() };
    }

    void _onRelayReq(const std::string& ip, uint16_t port, const std::vector<uint8_t>& buf) {
        if (!_isRelay) return;
        if ((int)buf.size() < 1 + 8 + 8 + 1 + 1 + 2) return;
        int o = 1;
        const std::string fromId = _bytesToHex(buf.data() + o, 8); o += 8;
        const std::string toId   = _bytesToHex(buf.data() + o, 8); o += 8;
        int ipLen = buf[o++];
        if (o + ipLen + 2 > (int)buf.size()) return;
        const std::string fromIp(buf.begin() + o, buf.begin() + o + ipLen); o += ipLen;
        const uint16_t fromPort = ((uint16_t)buf[o] << 8) | buf[o + 1];

        auto it = _peers.find(toId);
        if (it == _peers.end()) return;

        auto fromIdBytes = _hexToBytes(fromId);
        auto fromIpBytes = std::vector<uint8_t>(fromIp.begin(), fromIp.end());
        std::vector<uint8_t> fwd = { F_RELAY_FWD };
        fwd.insert(fwd.end(), fromIdBytes.begin(), fromIdBytes.end());
        fwd.push_back((uint8_t)fromIpBytes.size());
        fwd.insert(fwd.end(), fromIpBytes.begin(), fromIpBytes.end());
        fwd.push_back(fromPort >> 8);
        fwd.push_back(fromPort & 0xFF);
        it->second->writeCtrl(fwd);
    }

    void _onRelayFwd(const std::string&, uint16_t, const std::vector<uint8_t>& buf) {
        if ((int)buf.size() < 1 + 8 + 1 + 1 + 2) return;
        int o = 1;
        const std::string fromId = _bytesToHex(buf.data() + o, 8); o += 8;
        int ipLen = buf[o++];
        if (o + ipLen + 2 > (int)buf.size()) return;
        const std::string ip(buf.begin() + o, buf.begin() + o + ipLen); o += ipLen;
        const uint16_t port = ((uint16_t)buf[o] << 8) | buf[o + 1];
        if (fromId == _id16()) return;
        if (!_peers.count(fromId)) _dial(ip, port, fromId, "", 0);
    }

    void _onPex(const std::string& /*ip*/, uint16_t /*port*/, const std::vector<uint8_t>& buf) {
        if (buf.size() < 3) return;
        int count = buf[1];
        int o = 2;
        for (int i = 0; i < count && o < (int)buf.size(); i++) {
            int idLen = buf[o++];
            if (o + idLen > (int)buf.size()) break;
            std::string id = _bytesToHex(buf.data() + o, idLen); o += idLen;
            if (o >= (int)buf.size()) break;
            int ipLen = buf[o++];
            if (o + ipLen + 2 > (int)buf.size()) break;
            std::string ip(buf.begin() + o, buf.begin() + o + ipLen); o += ipLen;
            uint16_t port = ((uint16_t)buf[o] << 8) | buf[o + 1]; o += 2;

            if (id == _id16() || id == _id) continue;
            if (_peers.count(id)) continue;
            PeerInfo info; info.id = id; info.ip = ip; info.port = port;
            _peerCache[ip + ":" + std::to_string(port)] = info;
            _dial(ip, port, id, "", 0);
        }
    }

    void _sendPex(Peer* peer) {
        auto ps = peers();
        std::vector<Peer*> known;
        for (auto* p : ps) {
            if (p == peer || !p->_session || !p->_open || p->_best.empty()) continue;
            known.push_back(p);
            if ((int)known.size() >= PEX_MAX) break;
        }
        if (known.empty()) return;

        std::vector<uint8_t> frame = { F_PEX, (uint8_t)known.size() };
        for (auto* p : known) {
            auto colon = p->_best.rfind(':');
            std::string pip  = p->_best.substr(0, colon);
            uint16_t    pport = (uint16_t)std::stoi(p->_best.substr(colon + 1));
            auto idBytes = _hexToBytes(p->id);
            auto ipBytes = std::vector<uint8_t>(pip.begin(), pip.end());
            frame.push_back((uint8_t)idBytes.size());
            frame.insert(frame.end(), idBytes.begin(), idBytes.end());
            frame.push_back((uint8_t)ipBytes.size());
            frame.insert(frame.end(), ipBytes.begin(), ipBytes.end());
            frame.push_back(pport >> 8);
            frame.push_back(pport & 0xFF);
        }
        peer->writeCtrl(frame);
    }

    void _sendLanBeaconVia(SockFd s) {
        if (s == INVALID_SOCKET) return;
        std::string tH = _topicHash.empty() ? "" : _topicHash;
        std::string pl = _id + ":" + _localIp + ":" + std::to_string(_lport) + ":" + tH;
        std::vector<uint8_t> f = { F_LAN };
        f.insert(f.end(), pl.begin(), pl.end());
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_port   = htons(MCAST_PORT);
        inet_pton(AF_INET, MCAST_ADDR.c_str(), &dst.sin_addr);
        sendto(s, (const char*)f.data(), (int)f.size(), 0, (sockaddr*)&dst, sizeof(dst));
    }

    void _sendLanBeacon() {
        SockFd s = (_mcastSock != INVALID_SOCKET) ? _mcastSock : _sock;
        _sendLanBeaconVia(s);
    }

    void _startLan() {
        _mcastSock = socket(AF_INET, SOCK_DGRAM, 0);
        if (_mcastSock == INVALID_SOCKET) return;

        int yes = 1;
        setsockopt(_mcastSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
#ifdef SO_REUSEPORT
        setsockopt(_mcastSock, SOL_SOCKET, SO_REUSEPORT, (const char*)&yes, sizeof(yes));
#endif

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(MCAST_PORT);
        if (bind(_mcastSock, (sockaddr*)&addr, sizeof(addr)) < 0) {
            fprintf(stderr, "[LAN] bind port %d failed: %s\n", MCAST_PORT, strerror(errno));
#ifdef _WIN32
            closesocket(_mcastSock);
#else
            close(_mcastSock);
#endif
            _mcastSock = INVALID_SOCKET;
            _sendLanBeaconVia(_sock);
            std::thread([this]{
                while (!_destroyed) {
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    if (!_destroyed) _sendLanBeaconVia(_sock);
                }
            }).detach();
            return;
        }

        ip_mreq mreq{};
        inet_pton(AF_INET, MCAST_ADDR.c_str(), &mreq.imr_multiaddr);
        mreq.imr_interface.s_addr = INADDR_ANY;
        int rc = setsockopt(_mcastSock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   (const char*)&mreq, sizeof(mreq));
        if (rc < 0)
            fprintf(stderr, "[LAN] IP_ADD_MEMBERSHIP failed: %s\n", strerror(errno));

        std::thread([this]{
            std::vector<uint8_t> buf(4096);
            while (!_destroyed) {
                sockaddr_in src{};
                socklen_t srcLen = sizeof(src);
                int n = recvfrom(_mcastSock, (char*)buf.data(), (int)buf.size(), 0,
                                 (sockaddr*)&src, &srcLen);
                if (n <= 0) continue;
                char ipBuf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &src.sin_addr, ipBuf, sizeof(ipBuf));
                std::string ip(ipBuf);
                if (n >= 1 && buf[0] == F_LAN)
                    _onLan(ip, ntohs(src.sin_port),
                           std::vector<uint8_t>(buf.begin(), buf.begin() + n));
            }
        }).detach();

        _sendLanBeacon();
        std::thread([this]{
            while (!_destroyed) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                if (!_destroyed) _sendLanBeacon();
            }
        }).detach();
    }

    void _onLan(const std::string& ip, uint16_t /*port*/, const std::vector<uint8_t>& buf) {
        if (buf.size() < 2) return;
        std::string payload(buf.begin() + 1, buf.end());

        auto p1 = payload.find(':');
        if (p1 == std::string::npos) return;
        std::string peerId = payload.substr(0, p1);

        auto p2 = payload.find(':', p1 + 1);
        if (p2 == std::string::npos) return;
        std::string peerLip = payload.substr(p1 + 1, p2 - p1 - 1);

        auto p3 = payload.find(':', p2 + 1);
        std::string portStr, peerTopic;
        if (p3 == std::string::npos) {
            portStr   = payload.substr(p2 + 1);
            peerTopic = "";
        } else {
            portStr   = payload.substr(p2 + 1, p3 - p2 - 1);
            peerTopic = payload.substr(p3 + 1);
        }

        if (peerId == _id) return;
        if (!peerTopic.empty() && !_topicHash.empty() && peerTopic != _topicHash) return;
        if (_peers.count(peerId) || _dialing.count(peerId)) return;

        uint16_t pport = 0;
        try { pport = (uint16_t)std::stoi(portStr); } catch (...) { return; }

        _dial(ip, pport, peerId, "", 0);
    }

    std::unique_ptr<SimpleDHT> _dht;

    void _startDHT(bool announce, bool lookup) {
        SimpleDHTCallbacks cb;
        cb.sendUdp  = [this](const std::string& ip, uint16_t port, const std::string& json){
            std::vector<uint8_t> buf(json.begin(), json.end());
            _udpSend(ip, port, buf);
        };
        cb.randomId = [this](){
            uint8_t b[20]; RAND_bytes(b, 20);
            return _bytesToHex(b, 20);
        };
        cb.sha1hex  = [](const std::string& s){
            uint8_t h[SHA_DIGEST_LENGTH];
            SHA1(reinterpret_cast<const uint8_t*>(s.data()), s.size(), h);
            char hex[41];
            for (int i = 0; i < 20; i++) snprintf(hex + i * 2, 3, "%02x", h[i]);
            return std::string(hex, 40);
        };

        _dht = std::make_unique<SimpleDHT>(cb, _id.substr(0, 40));

        for (auto& hostport : _bootstrapNodes) {
            auto c = hostport.rfind(':');
            if (c == std::string::npos) continue;
            std::string host = hostport.substr(0, c);
            uint16_t    port = (uint16_t)std::stoi(hostport.substr(c + 1));
            _dht->addNode({ "", host, port });
        }

        if (announce) {
            std::string me = _meJson();
            _dht->put("topic:" + _topicHash + ":" + _id, me);
        }

        if (lookup) {
            for (auto& [key, raw] : _dht->storage) {
                PeerInfo info = _parseInfo(raw);
                if (!info.id.empty() && info.id != _id) _meet(info);
            }
        }
    }

    static size_t _curlWrite(char* ptr, size_t size, size_t nmemb, void* userdata) {
        auto* s = static_cast<std::string*>(userdata);
        s->append(ptr, size * nmemb);
        return size * nmemb;
    }

    static std::string _httpGet(const std::string& url, long timeoutMs = 8000) {
        CURL* c = curl_easy_init();
        if (!c) return {};
        std::string body;
        curl_easy_setopt(c, CURLOPT_URL, url.c_str());
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, _curlWrite);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
        curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, timeoutMs);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_perform(c);
        curl_easy_cleanup(c);
        return body;
    }

    static void _httpPost(const std::string& url, const std::string& json,
                          long timeoutMs = 8000) {
        CURL* c = curl_easy_init();
        if (!c) return;
        std::string sink;
        curl_slist* hdrs = nullptr;
        hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
        curl_easy_setopt(c, CURLOPT_URL, url.c_str());
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, json.c_str());
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, _curlWrite);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &sink);
        curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, timeoutMs);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_perform(c);
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(c);
    }

    void _startPiping(bool announce, bool lookup) {
        const std::string announcePath = "/p2p-" + _topicHash + "-announce";
        const std::string inbox        = "/p2p-" + _topicHash + "-" + _id;

        if (announce) {
            std::thread([this, announcePath]{
                for (int i = 0; i < 50 && !_ext && !_destroyed; i++)
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));

                auto doAnnounce = [&]{
                    if (_destroyed) return;
                    const std::string me = _meJson();
                    for (auto& host : _pipingServers) {
                        if (_destroyed) return;
                        _httpPost("https://" + host + announcePath, me);
                    }
                };

                doAnnounce();
                std::this_thread::sleep_for(std::chrono::milliseconds(2000));
                doAnnounce();
                std::this_thread::sleep_for(std::chrono::milliseconds(3000));
                doAnnounce();

                while (!_destroyed) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(ANNOUNCE_MS));
                    if (_destroyed) return;
                    doAnnounce();
                }
            }).detach();
        }

        if (lookup) {
            for (auto& host : _pipingServers) {
                std::thread([this, host, announcePath, announce]{
                    while (!_destroyed) {
                        std::string body = _httpGet("https://" + host + announcePath, 120000);
                        if (!body.empty()) {
                            PeerInfo info = _parseInfo(body);
                            if (!info.id.empty() && info.id != _id16()) {
                                if (announce && !info.id.empty()) {
                                    const std::string theirInbox = "/p2p-" + _topicHash + "-" + info.id;
                                    std::thread([this, host, theirInbox]{
                                        _httpPost("https://" + host + theirInbox, _meJson());
                                    }).detach();
                                }
                                _meet(info);
                            }
                        }
                        if (!_destroyed)
                            std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    }
                }).detach();
            }

            for (auto& host : _pipingServers) {
                std::thread([this, host, inbox]{
                    while (!_destroyed) {
                        std::string body = _httpGet("https://" + host + inbox, 120000);
                        if (!body.empty()) {
                            PeerInfo info = _parseInfo(body);
                            if (!info.id.empty() && info.id != _id16()) _meet(info);
                        }
                        if (!_destroyed)
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                }).detach();
            }
        }
    }

    void _startBootstrapAnnounce() {
        std::thread([this]{
            for (int i = 0; i < 30 && !_ext && !_destroyed; i++)
                std::this_thread::sleep_for(std::chrono::milliseconds(500));

            _queryBootstrapHttp();

            while (!_destroyed) {
                std::this_thread::sleep_for(std::chrono::milliseconds(3 * 60 * 1000));
                if (!_destroyed) _queryBootstrapHttp();
            }
        }).detach();
    }

    void _queryBootstrapHttp() {
        const std::string announceIp   = _ext ? _ext->ip   : _localIp;
        const uint16_t    announcePort = _ext ? _ext->port : _lport;

        for (auto& base : _bootstrapHttp) {
            if (_destroyed) return;

            if (announcePort) {
                std::string body = "{" + jsonStr("id", _id) + ","
                                 + jsonStr("ip", announceIp) + ","
                                 + jsonInt("port", announcePort) + "}";
                std::thread([base, body]{
                    _httpPost(base + "/announce", body);
                }).detach();
            }

            std::thread([this, base]{
                std::string resp = _httpGet(base + "/peers");
                if (resp.empty()) return;
                size_t pos = 0;
                while ((pos = resp.find('{', pos)) != std::string::npos) {
                    auto end = resp.find('}', pos);
                    if (end == std::string::npos) break;
                    std::string obj = resp.substr(pos, end - pos + 1);
                    PeerInfo info;
                    info.id   = jsonGet(obj, "id");
                    if (info.id.size() > 16) info.id = info.id.substr(0, 16);
                    info.ip   = jsonGet(obj, "ip");
                    info.port = (uint16_t)jsonGetInt(obj, "port");
                    if (!info.ip.empty() && info.port) {
                        _peerCache[info.ip + ":" + std::to_string(info.port)] = info;
                        if (info.id.empty() || !_peers.count(info.id))
                            _dial(info.ip, info.port, info.id, "", 0);
                    }
                    pos = end + 1;
                }
            }).detach();
        }
    }

    void _heartbeat() {
        const int64_t t = now_ms();

        std::vector<std::string> dead;
        for (auto& [pid, p] : _peers) {
            if (t - p->_seen > PEER_TIMEOUT) dead.push_back(pid);
            else if (t - p->_lastPong > 5000 && !p->_lossSignaled) {
                p->_lossSignaled = true;
                p->_onLoss();
            }
        }
        for (auto& pid : dead) {
            _drop(pid);
            if (onDisconnect) onDisconnect(pid);
        }

        _maintainMesh();
        _adaptMeshDegree();
        _emitIhave();

        auto idBytes = _hexToBytes(_id);
        for (auto& [_, p] : _peers) {
            std::vector<uint8_t> ping(9 + idBytes.size());
            ping[0] = F_PING;
            uint64_t ts = (uint64_t)now_ms();
            for (int i = 0; i < 8; i++) ping[1 + i] = (ts >> (56 - 8 * i)) & 0xFF;
            std::copy(idBytes.begin(), idBytes.end(), ping.begin() + 9);
            p->_lastPingSent = now_ms();
            const auto colon = p->_best.rfind(':');
            _udpSend(p->_best.substr(0, colon),
                     (uint16_t)std::stoi(p->_best.substr(colon + 1)), ping);
        }

        if (t - _lastPex > PEX_INTERVAL) {
            _lastPex = t;
            for (auto& [_, p] : _peers)
                if (p->_session && p->_open) _sendPex(p.get());
        }

        if (t - _lastCacheEmit > PEER_CACHE_EMIT_MS) {
            _lastCacheEmit = t;
            _emitPeerCache();
        }
    }

    void _addToMesh(Peer* peer) {
        if ((int)meshPeers().size() < _meshD) {
            peer->inMesh    = true;
            peer->_meshTime = now_ms();
        }
    }

    void _maintainMesh() {
        auto mesh    = meshPeers();
        std::vector<Peer*> nonMesh;
        for (auto& [_, p] : _peers)
            if (!p->inMesh && p->_session) nonMesh.push_back(p.get());

        if ((int)mesh.size() > D_HIGH) {
            std::sort(mesh.begin(), mesh.end(), [](Peer* a, Peer* b){ return a->score < b->score; });
            for (int i = 0; i < (int)mesh.size() - _meshD; i++) mesh[i]->inMesh = false;
        }
        if ((int)mesh.size() < D_LOW && !nonMesh.empty()) {
            std::sort(nonMesh.begin(), nonMesh.end(), [](Peer* a, Peer* b){ return a->score > b->score; });
            int need = _meshD - (int)mesh.size();
            for (int i = 0; i < need && i < (int)nonMesh.size(); i++) {
                nonMesh[i]->inMesh    = true;
                nonMesh[i]->_meshTime = now_ms();
            }
        }
    }

    void _adaptMeshDegree() {
        if (now_ms() - _lastMeshAdapt < 5000) return;
        _lastMeshAdapt = now_ms();
        auto ps = peers();
        if (ps.empty()) return;
        double avgRtt = 0;
        for (auto* p : ps) avgRtt += p->rtt;
        avgRtt /= ps.size();
        if      (avgRtt > 200 && _meshD > D_MIN) _meshD--;
        else if (avgRtt < 50  && _meshD < D_MAX && (int)ps.size() > _meshD + 2) _meshD++;

        std::vector<Peer*> candidates;
        for (auto* p : ps) {
            if (!p->inMesh && p->bandwidth > 50000.0)
                candidates.push_back(p);
        }
        std::sort(candidates.begin(), candidates.end(),
                  [](Peer* a, Peer* b){ return a->bandwidth > b->bandwidth; });
        for (int i = 0; i < 2 && i < (int)candidates.size(); i++) {
            candidates[i]->inMesh    = true;
            candidates[i]->_meshTime = now_ms();
        }
    }

    void _checkBecomeRelay() {
        if (_isRelay) return;
        if (!_ext) return;
        if (!RELAY_NAT_OPEN.count(natType) && natType != "full_cone") return;
        _isRelay = true;
        _announceRelay();
        _announceRelayDHT();
        std::thread([this]{
            while (!_destroyed) {
                std::this_thread::sleep_for(std::chrono::milliseconds(RELAY_ANN_MS));
                if (_destroyed) return;
                _announceRelay();
                _announceRelayDHT();
            }
        }).detach();
    }

    void _announceRelayDHT() {
        if (!_dht || !_ext || _topicHash.empty()) return;
        std::string val = "{" + jsonStr("id", _id) + ","
                        + jsonStr("ip", _ext->ip) + ","
                        + jsonInt("port", _ext->port) + "}";
        _dht->put("relay:" + _topicHash + ":" + _id, val);
    }

    void _dial(const std::string& ip, uint16_t port,
               const std::string& id, const std::string& lip, uint16_t lport)
    {
        const std::string key = id.empty() ? (ip + ":" + std::to_string(port)) : id;
        if (_dialing.count(key)) return;
        if (!id.empty() && _peers.count(id)) return;
        _dialing.insert(key);

        for (int i = 0; i < PUNCH_TRIES; i++) {
            auto delay = std::chrono::milliseconds(i * PUNCH_INTERVAL);
            std::thread([this, ip, port, delay]{
                std::this_thread::sleep_for(delay);
                if (!_destroyed) _sendHello(ip, port);
            }).detach();
        }
        if (!lip.empty() && lport) {
            for (int i = 0; i < PUNCH_TRIES; i++) {
                auto delay = std::chrono::milliseconds(i * PUNCH_INTERVAL);
                std::thread([this, lip, lport, delay]{
                    std::this_thread::sleep_for(delay);
                    if (!_destroyed) _sendHello(lip, lport);
                }).detach();
            }
        }

        std::thread([this, key, id]{
            std::this_thread::sleep_for(
                std::chrono::milliseconds(PUNCH_TRIES * PUNCH_INTERVAL + 3000));
            if (!_peers.count(id)) _dialing.erase(key);
        }).detach();
    }

    void _meet(const PeerInfo& info) {
        if (info.id.empty()) return;
        std::string shortId = (info.id.size() > 16) ? info.id.substr(0, 16) : info.id;
        if (shortId == _id16()) return;
        if (info.ip.empty() || !info.port) return;
        _dial(info.ip, info.port, shortId, info.lip, info.lport);
    }

    void _gossipPeer(const std::string& addr, const std::string& newId) {
        if (_gossipSeen.seen(newId)) return;
        std::string payload = "{\"_gossip\":true,\"id\":\"" + newId + "\","
                              "\"ip\":\"" + addr.substr(0, addr.rfind(':')) + "\","
                              "\"port\":" + addr.substr(addr.rfind(':') + 1) + "}";
        std::vector<uint8_t> buf(payload.begin(), payload.end());
        for (auto& [pid, p] : _peers) {
            if (pid != newId && p->_session && p->_open) p->_enqueue(buf);
        }
    }

    void _drop(const std::string& pid) {
        auto it = _peers.find(pid);
        if (it != _peers.end()) {
            it->second->destroy();
            _peers.erase(it);
        }
        _dialing.erase(pid);
    }

    void _dialPeerCache() {
        std::vector<PeerInfo> entries;
        for (auto& [_, e] : _peerCache) entries.push_back(e);
        std::sort(entries.begin(), entries.end(),
                  [](const PeerInfo& a, const PeerInfo& b){ return a.lastSeen > b.lastSeen; });
        for (int i = 0; i < 30 && i < (int)entries.size(); i++) {
            auto& e = entries[i];
            if (!e.id.empty() && _peers.count(e.id)) continue;
            _dial(e.ip, e.port, e.id, e.lip, e.lport);
        }
    }

    void _emitPeerCache() {
        for (auto& [_, p] : _peers) {
            if (!p->_session || !p->_open) continue;
            const auto colon = p->_best.rfind(':');
            PeerInfo info{ p->id, p->_best.substr(0, colon),
                           (uint16_t)std::stoi(p->_best.substr(colon + 1)) };
            info.lastSeen = now_ms();
            _peerCache[p->_best] = info;
        }
        std::vector<PeerInfo> list;
        list.reserve(_peerCache.size());
        for (auto& [_, e] : _peerCache) list.push_back(e);
        std::sort(list.begin(), list.end(),
                  [](const PeerInfo& a, const PeerInfo& b){ return a.lastSeen > b.lastSeen; });
        if (list.size() > 200) list.resize(200);
        if (onSavePeers) {
            try { onSavePeers(list); } catch (...) {}
        }
    }

    void _loadPeerCache() {
        if (!onLoadPeers) return;
        try {
            auto list = onLoadPeers();
            for (auto& entry : list) {
                if (!entry.ip.empty() && entry.port)
                    _peerCache[entry.ip + ":" + std::to_string(entry.port)] = entry;
            }
        } catch (...) {}
    }

    void _dialHardcodedSeeds() {
        for (auto& hostport : _hardcodedSeeds) {
            auto c = hostport.rfind(':');
            if (c == std::string::npos) continue;
            std::string host = hostport.substr(0, c);
            uint16_t    port = (uint16_t)std::stoi(hostport.substr(c + 1));
            _dial(host, port, "", "", 0);
        }
    }

    void _discoverNat() {
        std::thread([this]{
            for (auto& stun : STUN_HOSTS) {
                if (_destroyed || _ext) break;
                std::string ip;
                uint16_t    port = 0;
                if (_stunQuery(stun.host, stun.port, ip, port)) {
                    _ext = ExtAddr{ ip, port };
                    natType = "unknown";
                    publicAddress = ip + ":" + std::to_string(port);
                    if (onNat) onNat();
                    _checkBecomeRelay();
                    break;
                }
            }
        }).detach();
    }

    bool _stunQuery(const std::string& host, uint16_t port,
                    std::string& outIp, uint16_t& outPort)
    {
        SockFd s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s == INVALID_SOCKET) return false;

#ifdef _WIN32
        DWORD tv = STUN_FAST_TIMEOUT;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#else
        struct timeval tv{ 0, STUN_FAST_TIMEOUT * 1000 };
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

        addrinfo hints{}, *res = nullptr;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
#ifdef _WIN32
            closesocket(s);
#else
            close(s);
#endif
            return false;
        }

        uint8_t req[20] = {};
        req[1] = 0x01;
        req[2] = 0x00; req[3] = 0x00;
        req[4] = 0x21; req[5] = 0x12; req[6] = 0xA4; req[7] = 0x42;
        RAND_bytes(req + 8, 12);

        sendto(s, (const char*)req, 20, 0, res->ai_addr, (socklen_t)res->ai_addrlen);
        freeaddrinfo(res);

        uint8_t buf[512] = {};
        sockaddr_in src{};
        socklen_t srcLen = sizeof(src);
        int n = recvfrom(s, (char*)buf, sizeof(buf), 0, (sockaddr*)&src, &srcLen);
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
        if (n < 20) return false;

        int off = 20;
        while (off + 4 <= n) {
            int atype = (buf[off] << 8) | buf[off + 1];
            int alen  = (buf[off + 2] << 8) | buf[off + 3];
            off += 4;
            if (off + alen > n) break;

            if ((atype == 0x0001 || atype == 0x0020) && alen >= 8) {
                uint16_t p = (buf[off + 2] << 8) | buf[off + 3];
                uint32_t a = (buf[off + 4] << 24) | (buf[off + 5] << 16)
                           | (buf[off + 6] <<  8) |  buf[off + 7];
                if (atype == 0x0020) {
                    p ^= 0x2112;
                    a ^= 0x2112A442;
                }
                char ipBuf[INET_ADDRSTRLEN];
                struct in_addr ia; ia.s_addr = htonl(a);
                inet_ntop(AF_INET, &ia, ipBuf, sizeof(ipBuf));
                outIp   = ipBuf;
                outPort = p;
                return true;
            }
            off += alen;
        }
        return false;
    }

    Peer* _peerByAddr(const std::string& addr) {
        auto it = _addrToId.find(addr);
        if (it == _addrToId.end()) return nullptr;
        auto pit = _peers.find(it->second);
        return (pit == _peers.end()) ? nullptr : pit->second.get();
    }

    std::string _meJson() const {
        std::string ip   = _ext ? _ext->ip   : _localIp;
        int         port = _ext ? _ext->port : _lport;
        return "{" + jsonStr("id", _id) + "," + jsonStr("ip", ip) + ","
             + jsonInt("port", port) + "," + jsonStr("lip", _localIp) + ","
             + jsonInt("lport", _lport) + "," + jsonStr("nat", natType) + "}";
    }

    PeerInfo _parseInfo(const std::string& json) const {
        PeerInfo info;
        std::string rawId = jsonGet(json, "id");
        info.id    = (rawId.size() > 16) ? rawId.substr(0, 16) : rawId;
        info.ip    = jsonGet(json, "ip");
        info.port  = (uint16_t)jsonGetInt(json, "port");
        info.lip   = jsonGet(json, "lip");
        info.lport = (uint16_t)jsonGetInt(json, "lport");
        info.nat   = jsonGet(json, "nat");
        return info;
    }

    static std::string _getLocalIp() {
        SockFd s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s == INVALID_SOCKET) return "127.0.0.1";
        sockaddr_in dst{};
        dst.sin_family      = AF_INET;
        dst.sin_port        = htons(53);
        inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);
        connect(s, (sockaddr*)&dst, sizeof(dst));
        sockaddr_in local{};
        socklen_t len = sizeof(local);
        getsockname(s, (sockaddr*)&local, &len);
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &local.sin_addr, buf, sizeof(buf));
        return std::string(buf);
    }

    static std::string _bytesToHex(const uint8_t* data, int len) {
        std::string s(len * 2, '0');
        for (int i = 0; i < len; i++) snprintf(&s[i * 2], 3, "%02x", data[i]);
        return s;
    }

    static std::vector<uint8_t> _hexToBytes(const std::string& hex) {
        std::vector<uint8_t> v(hex.size() / 2);
        for (int i = 0; i < (int)v.size(); i++)
            v[i] = (uint8_t)std::stoi(hex.substr(i * 2, 2), nullptr, 16);
        return v;
    }

    static std::vector<uint8_t> _prependByte(uint8_t b, const std::vector<uint8_t>& data) {
        std::vector<uint8_t> v;
        v.reserve(1 + data.size());
        v.push_back(b);
        v.insert(v.end(), data.begin(), data.end());
        return v;
    }
};

inline void Peer::_swarmAddrSet(const std::string& addr, const std::string& peerId) {
    if (_swarm) _swarm->_addrToId[addr] = peerId;
}
inline void Peer::_swarmAddrErase(const std::string& addr) {
    if (_swarm) _swarm->_addrToId.erase(addr);
}
