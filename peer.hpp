#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>
#include "constants.hpp"
#include "crypto.hpp"
#include "framing.hpp"
#include "structs.hpp"

class Swarm;

class Peer {
public:
    std::string id;
    std::string remoteAddress;
    bool        inMesh    = false;
    int64_t     _meshTime = 0;
    int         score     = 0;
    double      rtt       = RTT_INIT;
    double      bandwidth = 0.0;

    std::optional<SessionKeys> _session;
    std::vector<uint8_t>       _theirPubRaw;

    Swarm*                                                                          _swarm = nullptr;
    std::function<void(const std::string&, uint16_t, const std::vector<uint8_t>&)> _sendUdp;

    bool    _open         = true;
    int64_t _seen         = 0;
    int64_t _lastPingSent = 0;
    int64_t _lastPong     = 0;
    bool    _lossSignaled = false;

    std::map<std::string, double> _addrs;
    std::string                   _best;

    RingBuffer<std::vector<uint8_t>> _ctrlQueue;
    RingBuffer<std::vector<uint8_t>> _dataQueue;
    bool _draining = false;

    FragmentAssembler _fragger;
    JitterBuffer      _jitter;

    uint32_t _sendSeq = 0;

    int     _cwnd     = CWND_INIT;
    int     _inflight = 0;
    int64_t _lastLoss = 0;

    double  _tokens   = RATE_BURST;
    int64_t _lastRate = 0;

    int64_t _bytesSent    = 0;
    int64_t _bytesWindow  = 0;

    std::function<void(uint8_t*, int)> _randBytes;

    Peer(Swarm* swarm, const std::string& peerId, const std::string& addr,
         std::function<void(const std::string&, uint16_t, const std::vector<uint8_t>&)> sendUdp,
         std::function<void(uint8_t*, int)> randBytes,
         std::function<void(const std::vector<uint8_t>&)> onData)
        : id(peerId)
        , remoteAddress(addr)
        , _swarm(swarm)
        , _sendUdp(std::move(sendUdp))
        , _seen(now_ms())
        , _lastPong(now_ms())
        , _lastRate(now_ms())
        , _bytesWindow(now_ms())
        , _addrs()
        , _best(addr)
        , _ctrlQueue(QUEUE_CTRL)
        , _dataQueue(QUEUE_DATA)
        , _jitter(std::move(onData))
        , _randBytes(std::move(randBytes))
    {
        _addrs[addr] = RTT_INIT;
    }

    bool writeCtrl(const std::vector<uint8_t>& data) {
        if (!_open) return false;
        _ctrlQueue.push(data);
        if (!_draining) _drain();
        return true;
    }

    bool write(const std::vector<uint8_t>& data) {
        if (!_open || !_session) return false;
        _dataQueue.push(data);
        if (!_draining) _drain();
        return true;
    }

    void _enqueue(const std::vector<uint8_t>& raw) { write(raw); }

    void _drain() {
        _draining = true;

        while (!_ctrlQueue.empty()) {
            auto raw = _ctrlQueue.shift();
            if (raw) _sendRaw(*raw);
        }

        while (!_dataQueue.empty() && _inflight < _cwnd) {
            auto raw = _dataQueue.shift();
            if (!raw) break;
            _sendEncrypted(*raw);
        }

        _draining = false;
    }

    void _sendEncrypted(const std::vector<uint8_t>& plain) {
        if (!_session) return;

        const int64_t now   = now_ms();
        const double  delta = (now - _lastRate) / 1000.0;
        _tokens   = std::min((double)RATE_BURST, _tokens + delta * RATE_PER_SEC);
        _lastRate = now;
        if (_tokens < 1.0) {
            _dataQueue.push(plain);
            return;
        }
        _tokens--;

        auto fragResult = fragmentPayload(plain, _randBytes);
        if (fragResult) {
            for (auto& frag : fragResult->frags) {
                std::vector<uint8_t> wrapped;
                wrapped.reserve(1 + frag.size());
                wrapped.push_back(F_FRAG);
                wrapped.insert(wrapped.end(), frag.begin(), frag.end());
                _sendRaw(wrapped);
            }
            return;
        }

        std::vector<uint8_t> seqBuf(4 + plain.size());
        seqBuf[0] = (_sendSeq >> 24) & 0xFF;
        seqBuf[1] = (_sendSeq >> 16) & 0xFF;
        seqBuf[2] = (_sendSeq >>  8) & 0xFF;
        seqBuf[3] =  _sendSeq        & 0xFF;
        _sendSeq++;
        std::copy(plain.begin(), plain.end(), seqBuf.begin() + 4);

        const auto ct = encrypt(*_session, seqBuf);
        std::vector<uint8_t> frame;
        frame.reserve(1 + ct.size());
        frame.push_back(F_DATA);
        frame.insert(frame.end(), ct.begin(), ct.end());
        _sendRaw(frame);
        _inflight++;

        _bytesSent += (int64_t)frame.size();
        const double elapsed = (now_ms() - _bytesWindow) / 1000.0;
        if (elapsed >= 1.0) {
            bandwidth      = _bytesSent / elapsed;
            _bytesSent     = 0;
            _bytesWindow   = now_ms();
        }
    }

    void _sendRaw(const std::vector<uint8_t>& buf) {
        const auto colon = _best.rfind(':');
        const std::string ip   = _best.substr(0, colon);
        const uint16_t    port = (uint16_t)std::stoi(_best.substr(colon + 1));
        _sendUdp(ip, port, buf);
    }

    void _sendRawNow(const std::vector<uint8_t>& buf) { _sendRaw(buf); }

    void _onAck() {
        if (_inflight > 0) _inflight--;
        if (_cwnd < CWND_MAX) _cwnd = std::min(CWND_MAX, _cwnd + 1);
        if (!_dataQueue.empty()) _drain();
    }

    void _onLoss() {
        const int64_t now = now_ms();
        if (now - _lastLoss < 1000) return;
        _lastLoss = now;
        _cwnd     = std::max(1, (int)std::floor(_cwnd * CWND_DECAY));
        _inflight = std::min(_inflight, _cwnd);
    }

    void _touch(const std::string& addr, double inRtt = 0.0) {
        _seen         = now_ms();
        _lastPong     = now_ms();
        _lossSignaled = false;

        if (!addr.empty()) {
            const double r = (inRtt > 0.0) ? inRtt : rtt;
            _addrs[addr] = r;

            if ((int)_addrs.size() > MAX_ADDRS_PEER) {
                std::string worst;
                double worstRtt = -1.0;
                for (auto& [a, rt] : _addrs) {
                    if (rt > worstRtt) { worstRtt = rt; worst = a; }
                }
                if (!worst.empty() && worst != addr) {
                    _addrs.erase(worst);
                    if (_swarm) _swarmAddrErase(worst);
                }
            }

            if (inRtt > 0.0)
                rtt = rtt + RTT_ALPHA * (inRtt - rtt);

            std::string best     = addr;
            double      bestRtt  = r;
            for (auto& [a, rt] : _addrs) {
                if (rt < bestRtt) { bestRtt = rt; best = a; }
            }
            _best         = best;
            remoteAddress = best;

            if (_swarm) _swarmAddrSet(addr, id);
        }
    }

    void _scoreUp(int n = 1)   { score = std::min(1000, score + n); }
    void _scoreDown(int n = 2) { score = std::max(-1000, score - n); }

    void destroy() {
        _open = false;

        if (_swarm) {
            for (auto& [addr, _] : _addrs)
                _swarmAddrErase(addr);
        }
        _fragger.clear();
        _jitter.clear();
        _ctrlQueue.clear();
        _dataQueue.clear();
    }

private:

    void _swarmAddrSet(const std::string& addr, const std::string& peerId);
    void _swarmAddrErase(const std::string& addr);
};
