#pragma once

#include <cstdint>
#include <cstring>
#include <chrono>
#include <functional>
#include <list>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
#include "constants.hpp"

static inline int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

class BloomFilter {
public:
    BloomFilter(int bits = BLOOM_BITS, int numHashes = BLOOM_HASHES)
        : _bits(bits), _hashes(numHashes),
          _cur(bits >> 3, 0), _old(bits >> 3, 0),
          _count(0), _lastRotate(now_ms()) {}

    void add(const std::string& key) {
        _rotate();
        for (int pos : _positions(key))
            _cur[pos >> 3] |= (1 << (pos & 7));
        _count++;
    }

    bool has(const std::string& key) const {
        auto pos = _positions(key);
        bool inCur = true;
        for (int p : pos) if (!(_cur[p >> 3] & (1 << (p & 7)))) { inCur = false; break; }
        if (inCur) return true;
        for (int p : pos) if (!(_old[p >> 3] & (1 << (p & 7)))) return false;
        return true;
    }

    bool seen(const std::string& key) {
        if (has(key)) return true;
        add(key);
        return false;
    }

private:
    int                  _bits, _hashes, _count;
    int64_t              _lastRotate;
    std::vector<uint8_t> _cur, _old;

    void _rotate() {
        if (now_ms() - _lastRotate < BLOOM_ROTATE) return;
        _old         = _cur;
        _cur.assign(_bits >> 3, 0);
        _count       = 0;
        _lastRotate  = now_ms();
    }

    std::vector<int> _positions(const std::string& key) const {
        std::vector<int> out;
        out.reserve(_hashes);
        for (int i = 0; i < _hashes; i++) {
            uint32_t h = (2166136261u + i * 16777619u);
            for (unsigned char c : key) { h ^= c; h *= 16777619u; }
            out.push_back((int)(h % (uint32_t)_bits));
        }
        return out;
    }
};

template<typename V>
class LRU {
public:
    LRU(int max, int64_t ttl = -1) : _max(max), _ttl(ttl) {}

    void add(const std::string& k, V v) {
        const int64_t t = now_ms();
        if (_ttl > 0) {
            int n = 0;
            for (auto it = _order.begin(); it != _order.end() && n < 300; ) {
                if (t - it->second.t > _ttl) {
                    _map.erase(it->first);
                    it = _order.erase(it);
                } else { ++it; ++n; }
            }
        }
        if ((int)_map.size() >= _max && !_order.empty()) {
            _map.erase(_order.front().first);
            _order.pop_front();
        }
        _order.push_back({ k, { v, t } });
        _map[k] = std::prev(_order.end());
    }

    std::optional<V> get(const std::string& k) const {
        auto it = _map.find(k);
        if (it == _map.end()) return std::nullopt;
        return it->second->second.v;
    }

    bool has(const std::string& k) const { return _map.count(k) > 0; }

    bool seen(const std::string& k) {
        if (has(k)) return true;
        add(k, V{});
        return false;
    }

    void del(const std::string& k) {
        auto it = _map.find(k);
        if (it == _map.end()) return;
        _order.erase(it->second);
        _map.erase(it);
    }

    int size() const { return (int)_map.size(); }

    // Returns all keys in insertion order (oldest first), mirroring JS store.keys()
    std::vector<std::string> keys() const {
        std::vector<std::string> out;
        out.reserve(_map.size());
        for (auto& [k, _] : _order) out.push_back(k);
        return out;
    }

private:
    struct Entry { V v; int64_t t; };
    using ListT = std::list<std::pair<std::string, Entry>>;
    int     _max;
    int64_t _ttl;
    ListT   _order;
    std::unordered_map<std::string, typename ListT::iterator> _map;
};

template<typename T>
class RingBuffer {
public:
    explicit RingBuffer(int size) : _mask(size - 1), _head(0), _tail(0) {
        if (size == 0 || (size & (size - 1)) != 0)
            throw std::invalid_argument("RingBuffer: size must be power of 2");
        _buf.resize(size);
    }

    int  length() const { return (_tail - _head) & _mask; }
    bool full()   const { return ((_tail + 1) & _mask) == (_head & _mask); }
    bool empty()  const { return _head == _tail; }

    void push(T item) {
        if (full()) _head = (_head + 1) & _mask;
        _buf[_tail] = std::move(item);
        _tail = (_tail + 1) & _mask;
    }

    std::optional<T> shift() {
        if (empty()) return std::nullopt;
        T item = std::move(_buf[_head]);
        _head = (_head + 1) & _mask;
        return item;
    }

    void clear() { _head = _tail = 0; }

private:
    std::vector<T> _buf;
    int _mask, _head, _tail;
};

class PayloadCache {
public:
    explicit PayloadCache(int size) : _mask(size - 1), _head(0) {
        _keys.resize(size);
        _vals.resize(size);
    }

    void set(const std::string& msgId, const std::vector<uint8_t>& frame) {
        const auto& old = _keys[_head];
        if (!old.empty()) _map.erase(old);
        _keys[_head] = msgId;
        _vals[_head] = frame;
        _map[msgId]  = _head;
        _head        = (_head + 1) & _mask;
    }

    std::optional<std::vector<uint8_t>> get(const std::string& msgId) const {
        auto it = _map.find(msgId);
        if (it == _map.end()) return std::nullopt;
        return _vals[it->second];
    }

    bool has(const std::string& msgId) const { return _map.count(msgId) > 0; }

private:
    int                                          _mask, _head;
    std::vector<std::string>                     _keys;
    std::vector<std::vector<uint8_t>>            _vals;
    std::unordered_map<std::string, int>         _map;
};
