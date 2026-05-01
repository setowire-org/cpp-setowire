#pragma once

#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>
#include "constants.hpp"

inline std::string xorHash(const std::vector<uint8_t>& buf) {
    uint32_t a = 0x811C9DC5u, b = 0x811C9DC5u;
    for (size_t i = 0; i < buf.size(); i++) {
        if (i & 1) { b ^= buf[i]; b *= 0x01000193u; }
        else        { a ^= buf[i]; a *= 0x01000193u; }
    }
    char out[17];
    snprintf(out, sizeof(out), "%08x%08x", a, b);
    return std::string(out, 16);
}

inline std::optional<std::vector<uint8_t>> fragmentPayload_tryAssemble(
    std::map<int, std::vector<uint8_t>>& pieces, int total)
{
    if ((int)pieces.size() != total) return std::nullopt;
    std::vector<uint8_t> out;
    for (int i = 0; i < total; i++) {
        auto& p = pieces[i];
        out.insert(out.end(), p.begin(), p.end());
    }
    return out;
}

struct FragEntry {
    int                              total;
    std::map<int, std::vector<uint8_t>> pieces;
    int64_t                          createdAt;
};

class FragmentAssembler {
public:
    std::optional<std::vector<uint8_t>> add(
        const std::string& fragId, int fragIdx, int fragTotal,
        const std::vector<uint8_t>& data)
    {
        auto& entry    = _pending[fragId];
        entry.total    = fragTotal;
        entry.createdAt = entry.createdAt ? entry.createdAt : now_ms();
        entry.pieces[fragIdx] = data;

        if ((int)entry.pieces.size() == fragTotal) {
            auto result = fragmentPayload_tryAssemble(entry.pieces, fragTotal);
            _pending.erase(fragId);
            return result;
        }
        return std::nullopt;
    }

    void evict() {
        const int64_t now = now_ms();
        for (auto it = _pending.begin(); it != _pending.end(); ) {
            if (now - it->second.createdAt > FRAG_TIMEOUT) it = _pending.erase(it);
            else ++it;
        }
    }

    void clear() { _pending.clear(); }

private:
    std::map<std::string, FragEntry> _pending;

    static int64_t now_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
};

struct FragmentResult {
    std::string                          fragId;
    int                                  total;
    std::vector<std::vector<uint8_t>>    frags;
};

inline std::optional<FragmentResult> fragmentPayload(
    const std::vector<uint8_t>& payload,
    const std::function<void(uint8_t*, int)>& randBytes)
{
    if ((int)payload.size() <= MAX_PAYLOAD) return std::nullopt;

    uint8_t fragIdBuf[8];
    randBytes(fragIdBuf, 8);
    char fragIdHex[17];
    for (int i = 0; i < 8; i++) snprintf(fragIdHex + i * 2, 3, "%02x", fragIdBuf[i]);
    std::string fragId(fragIdHex, 16);

    int total = ((int)payload.size() + FRAG_DATA_MAX - 1) / FRAG_DATA_MAX;
    std::vector<std::vector<uint8_t>> frags;
    frags.reserve(total);

    for (int i = 0; i < total; i++) {
        int start = i * FRAG_DATA_MAX;
        int end   = std::min(start + FRAG_DATA_MAX, (int)payload.size());

        std::vector<uint8_t> frag(FRAG_HDR + (end - start));
        memcpy(frag.data(), fragIdBuf, 8);
        frag[8] = (uint8_t)(i >> 8);  frag[9]  = (uint8_t)(i & 0xFF);
        frag[10]= (uint8_t)(total>>8); frag[11] = (uint8_t)(total & 0xFF);
        memcpy(frag.data() + FRAG_HDR, payload.data() + start, end - start);
        frags.push_back(std::move(frag));
    }

    return FragmentResult{ fragId, total, std::move(frags) };
}

class JitterBuffer {
public:
    explicit JitterBuffer(std::function<void(const std::vector<uint8_t>&)> onDeliver)
        : _deliver(std::move(onDeliver)), _next(0) {}

    void push(uint32_t seq, const std::vector<uint8_t>& data) {
        if (seq < _next) return;
        if (seq == _next) {
            _deliver(data);
            _next++;
            _flush();
        } else {
            _buf[seq] = data;
        }
    }

    void flush_stale(uint32_t upTo) {
        while (_buf.count(upTo)) {
            _deliver(_buf[upTo]);
            _buf.erase(upTo);
            _next = upTo + 1;
            upTo++;
        }
    }

    void clear() { _buf.clear(); }

private:
    std::function<void(const std::vector<uint8_t>&)> _deliver;
    std::map<uint32_t, std::vector<uint8_t>>         _buf;
    uint32_t                                          _next;

    void _flush() {
        while (_buf.count(_next)) {
            _deliver(_buf[_next]);
            _buf.erase(_next);
            _next++;
        }
    }
};

struct UdpSendFn {
    std::function<void(const std::string&, uint16_t, const std::vector<uint8_t>&)> send;
};

class BatchSender {
public:
    explicit BatchSender(UdpSendFn udp) : _udp(std::move(udp)) {}

    void send(const std::string& ip, uint16_t port, const std::vector<uint8_t>& buf) {
        auto key = ip + ":" + std::to_string(port);
        _pending[key].push_back(buf);
    }

    void sendNow(const std::string& ip, uint16_t port, const std::vector<uint8_t>& buf) {
        _udp.send(ip, port, buf);
    }

    void flush() {
        for (auto& [key, bufs] : _pending) {
            auto colon = key.rfind(':');
            std::string ip   = key.substr(0, colon);
            uint16_t    port = (uint16_t)std::stoi(key.substr(colon + 1));

            std::vector<std::vector<uint8_t>> batch;
            int size = 0;

            for (auto& b : bufs) {
                if (size + (int)b.size() + 2 > BATCH_MTU && !batch.empty()) {
                    _sendBatch(ip, port, batch);
                    batch.clear(); size = 0;
                }
                batch.push_back(b);
                size += (int)b.size() + 2;
            }
            if (!batch.empty()) _sendBatch(ip, port, batch);
        }
        _pending.clear();
    }

private:
    UdpSendFn _udp;
    std::map<std::string, std::vector<std::vector<uint8_t>>> _pending;

    void _sendBatch(const std::string& ip, uint16_t port,
                    const std::vector<std::vector<uint8_t>>& bufs)
    {
        if (bufs.size() == 1) { _udp.send(ip, port, bufs[0]); return; }

        std::vector<uint8_t> out;
        out.push_back(F_BATCH);
        out.push_back((uint8_t)bufs.size());
        for (auto& b : bufs) {
            out.push_back((uint8_t)(b.size() >> 8));
            out.push_back((uint8_t)(b.size() & 0xFF));
            out.insert(out.end(), b.begin(), b.end());
        }
        _udp.send(ip, port, out);
    }
};
