#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <list>
#include <map>
#include <optional>
#include <random>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

static constexpr int DHT_K          = 20;
static constexpr int DHT_ALPHA      = 3;
static constexpr int DHT_ID_BYTES   = 20;
static constexpr int DHT_ID_BITS    = 160;
static constexpr int DHT_TIMEOUT_MS = 5000;
static constexpr int DHT_REPUBLISH  = 60 * 60 * 1000;

static constexpr uint8_t DHT_MSG_PING       = 0x01;
static constexpr uint8_t DHT_MSG_PONG       = 0x02;
static constexpr uint8_t DHT_MSG_STORE      = 0x03;
static constexpr uint8_t DHT_MSG_FIND_NODE  = 0x04;
static constexpr uint8_t DHT_MSG_FOUND_NODE = 0x05;
static constexpr uint8_t DHT_MSG_FIND_VALUE = 0x06;
static constexpr uint8_t DHT_MSG_FOUND_VAL  = 0x07;

using NodeId  = std::array<uint8_t, DHT_ID_BYTES>;
using NodeIdS = std::string;

struct DhtNode {
    NodeIdS     id;
    std::string ip;
    uint16_t    port;
    int64_t     lastSeen = 0;
};

struct DhtMsg {
    uint8_t     type = 0;
    std::string from;
    std::string rpcId;
    std::string target;
    std::string key;
    std::string value;
    std::vector<DhtNode> nodes;
};

inline NodeId hexToId(const NodeIdS& hex) {
    NodeId id{};
    for (int i = 0; i < DHT_ID_BYTES; i++)
        id[i] = (uint8_t)std::stoi(hex.substr(i * 2, 2), nullptr, 16);
    return id;
}

inline NodeIdS idToHex(const NodeId& id) {
    char buf[DHT_ID_BYTES * 2 + 1];
    for (int i = 0; i < DHT_ID_BYTES; i++) snprintf(buf + i * 2, 3, "%02x", id[i]);
    return std::string(buf, DHT_ID_BYTES * 2);
}

inline NodeId xorDistance(const NodeId& a, const NodeId& b) {
    NodeId d{};
    for (int i = 0; i < DHT_ID_BYTES; i++) d[i] = a[i] ^ b[i];
    return d;
}

inline int cmpDistance(const NodeId& d1, const NodeId& d2) {
    for (int i = 0; i < DHT_ID_BYTES; i++) {
        if (d1[i] < d2[i]) return -1;
        if (d1[i] > d2[i]) return  1;
    }
    return 0;
}

inline int bucketIndex(const NodeId& selfId, const NodeId& otherId) {
    NodeId d = xorDistance(selfId, otherId);
    for (int i = 0; i < DHT_ID_BYTES; i++) {
        if (d[i] == 0) continue;
        int bit = 7;
        uint8_t byte = d[i];
        while (byte > 1) { byte >>= 1; bit--; }
        return i * 8 + (7 - bit);
    }
    return DHT_ID_BITS - 1;
}

class KBucket {
public:
    std::vector<DhtNode> nodes;

    void add(const DhtNode& node) {
        for (auto it = nodes.begin(); it != nodes.end(); ++it) {
            if (it->id == node.id) {
                nodes.erase(it);
                DhtNode n = node;
                n.lastSeen = now_ms();
                nodes.push_back(n);
                return;
            }
        }
        if ((int)nodes.size() < DHT_K) {
            DhtNode n = node;
            n.lastSeen = now_ms();
            nodes.push_back(n);
        }
    }

    void remove(const NodeIdS& id) {
        nodes.erase(std::remove_if(nodes.begin(), nodes.end(),
            [&](const DhtNode& n){ return n.id == id; }), nodes.end());
    }

    std::vector<DhtNode> closest(const NodeId& target, int count = DHT_K) const {
        auto sorted = nodes;
        std::sort(sorted.begin(), sorted.end(), [&](const DhtNode& a, const DhtNode& b){
            return cmpDistance(
                xorDistance(hexToId(a.id), target),
                xorDistance(hexToId(b.id), target)) < 0;
        });
        if ((int)sorted.size() > count) sorted.resize(count);
        return sorted;
    }

private:
    static int64_t now_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
};

class RoutingTable {
public:
    NodeId selfId;
    std::array<KBucket, DHT_ID_BITS> buckets;

    explicit RoutingTable(const NodeId& id) : selfId(id) {}

    void add(const DhtNode& node) {
        if (node.id == idToHex(selfId)) return;
        int idx = bucketIndex(selfId, hexToId(node.id));
        buckets[idx].add(node);
    }

    void remove(const NodeIdS& id) {
        int idx = bucketIndex(selfId, hexToId(id));
        buckets[idx].remove(id);
    }

    std::vector<DhtNode> closest(const NodeId& target, int count = DHT_K) const {
        std::vector<DhtNode> all;
        for (auto& b : buckets)
            all.insert(all.end(), b.nodes.begin(), b.nodes.end());
        std::sort(all.begin(), all.end(), [&](const DhtNode& a, const DhtNode& b){
            return cmpDistance(
                xorDistance(hexToId(a.id), target),
                xorDistance(hexToId(b.id), target)) < 0;
        });
        if ((int)all.size() > count) all.resize(count);
        return all;
    }

    int size() const {
        int s = 0;
        for (auto& b : buckets) s += (int)b.nodes.size();
        return s;
    }
};

struct SimpleDHTCallbacks {
    std::function<void(const std::string& ip, uint16_t port, const std::string& json)> sendUdp;
    std::function<std::string()>                                                        randomId;
    std::function<std::string(const std::string&)>                                     sha1hex;
};

class SimpleDHT {
public:
    NodeIdS                              nodeId;
    std::unordered_map<std::string, std::string> storage;

    SimpleDHT(const SimpleDHTCallbacks& cb, const std::string& nodeIdHex = "")
        : _cb(cb)
    {
        if (nodeIdHex.empty()) {
            std::string rand = cb.randomId();
            _idBuf  = hexToId(rand);
            nodeId  = rand;
        } else {
            _idBuf  = hexToId(nodeIdHex);
            nodeId  = nodeIdHex;
        }
        _table = std::make_unique<RoutingTable>(_idBuf);
    }

    void addNode(const DhtNode& node) {
        if (node.id.empty() || !node.port) return;
        _table->add(node);
    }

    std::string put(const std::string& key, const std::string& value) {
        std::string keyHash = _cb.sha1hex(key);
        storage[keyHash]    = value;

        NodeId keyBuf = hexToId(keyHash);
        auto   closest = _table->closest(keyBuf, DHT_K);
        for (auto& n : closest) {
            DhtMsg msg;
            msg.type  = DHT_MSG_STORE;
            msg.from  = nodeId;
            msg.key   = keyHash;
            msg.value = value;
            _send(n.ip, n.port, msg);
        }
        return keyHash;
    }

    std::optional<std::string> get(const std::string& key) const {
        std::string keyHash = _cb.sha1hex(key);
        auto it = storage.find(keyHash);
        if (it == storage.end()) return std::nullopt;
        return it->second;
    }

    void onMessage(const std::string& fromIp, uint16_t fromPort, const DhtMsg& msg) {
        if (!msg.from.empty())
            _table->add({ msg.from, fromIp, fromPort });

        if (!msg.rpcId.empty()) {
            auto it = _pending.find(msg.rpcId);
            if (it != _pending.end()) {
                it->second(msg);
                _pending.erase(it);
                return;
            }
        }

        DhtMsg reply;
        reply.from  = nodeId;
        reply.rpcId = msg.rpcId;

        switch (msg.type) {
        case DHT_MSG_PING:
            reply.type = DHT_MSG_PONG;
            _send(fromIp, fromPort, reply);
            break;

        case DHT_MSG_STORE:
            if (!msg.key.empty())
                storage[msg.key] = msg.value;
            break;

        case DHT_MSG_FIND_NODE: {
            NodeId target = hexToId(msg.target);
            reply.type  = DHT_MSG_FOUND_NODE;
            reply.nodes = _table->closest(target, DHT_K);
            _send(fromIp, fromPort, reply);
            break;
        }

        case DHT_MSG_FIND_VALUE: {
            auto it = storage.find(msg.key);
            if (it != storage.end()) {
                reply.type  = DHT_MSG_FOUND_VAL;
                reply.value = it->second;
            } else {
                NodeId keyBuf = hexToId(msg.key);
                reply.type  = DHT_MSG_FOUND_NODE;
                reply.nodes = _table->closest(keyBuf, DHT_K);
            }
            _send(fromIp, fromPort, reply);
            break;
        }
        }
    }

    void republish() {
        for (auto& [keyHash, value] : storage) {
            NodeId keyBuf  = hexToId(keyHash);
            auto   closest = _table->closest(keyBuf, DHT_K);
            for (auto& n : closest) {
                DhtMsg msg;
                msg.type  = DHT_MSG_STORE;
                msg.from  = nodeId;
                msg.key   = keyHash;
                msg.value = value;
                _send(n.ip, n.port, msg);
            }
        }
    }

    std::vector<DhtNode> closestNodes(const std::string& targetHex, int count = DHT_K) const {
        return _table->closest(hexToId(targetHex), count);
    }

    int tableSize() const { return _table->size(); }

private:
    SimpleDHTCallbacks             _cb;
    NodeId                         _idBuf;
    std::unique_ptr<RoutingTable>  _table;
    std::unordered_map<std::string, std::function<void(const DhtMsg&)>> _pending;

    void _send(const std::string& ip, uint16_t port, const DhtMsg& msg) {
        _cb.sendUdp(ip, port, _encode(msg));
    }

    static std::string _encode(const DhtMsg& msg) {
        std::string s = "{";
        s += "\"type\":" + std::to_string(msg.type);
        if (!msg.from.empty())  s += ",\"from\":\"" + msg.from + "\"";
        if (!msg.rpcId.empty()) s += ",\"rpcId\":\"" + msg.rpcId + "\"";
        if (!msg.target.empty())s += ",\"target\":\"" + msg.target + "\"";
        if (!msg.key.empty())   s += ",\"key\":\"" + msg.key + "\"";
        if (!msg.value.empty()) s += ",\"value\":\"" + msg.value + "\"";
        if (!msg.nodes.empty()) {
            s += ",\"nodes\":[";
            for (size_t i = 0; i < msg.nodes.size(); i++) {
                if (i) s += ",";
                s += "{\"id\":\"" + msg.nodes[i].id + "\","
                     "\"ip\":\"" + msg.nodes[i].ip + "\","
                     "\"port\":" + std::to_string(msg.nodes[i].port) + "}";
            }
            s += "]";
        }
        s += "}";
        return s;
    }
};
