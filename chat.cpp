#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "swarm.hpp"

static std::string sha256hex(const std::string& s) {
    uint8_t h[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const uint8_t*>(s.data()), s.size(), h);
    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", h[i]);
    return std::string(hex, 64);
}

static std::string topicHex(const std::string& room) {
    return sha256hex("chat:" + room);
}

static std::string timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm* tm   = std::localtime(&t);
    char buf[12];
    snprintf(buf, sizeof(buf), "[%02d:%02d:%02d] ", tm->tm_hour, tm->tm_min, tm->tm_sec);
    return buf;
}

static std::string loadOrCreateSeed(const std::string& path = "./identity.json") {
    {
        std::ifstream f(path);
        if (f) {
            std::string content((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
            auto p = content.find("\"seed\"");
            if (p != std::string::npos) {
                p = content.find('"', p + 6);
                if (p != std::string::npos) {
                    auto e = content.find('"', p + 1);
                    if (e != std::string::npos)
                        return content.substr(p + 1, e - p - 1);
                }
            }
        }
    }
    uint8_t raw[32];
    RAND_bytes(raw, 32);
    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", raw[i]);
    std::string seedHex(hex, 64);
    std::ofstream f(path);
    if (f) f << "{\"seed\":\"" << seedHex << "\"}\n";
    return seedHex;
}

static std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if      (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else                out += c;
    }
    return out;
}

static std::vector<uint8_t> makeJoin(const std::string& nick) {
    std::string j = "{\"type\":\"JOIN\",\"nick\":\"" + jsonEscape(nick) + "\"}";
    return std::vector<uint8_t>(j.begin(), j.end());
}

static std::vector<uint8_t> makeMsg(const std::string& nick, const std::string& text,
                                    const std::string& selfId) {
    std::string j = "{\"type\":\"MSG\",\"nick\":\"" + jsonEscape(nick) +
                    "\",\"text\":\"" + jsonEscape(text) +
                    "\",\"_selfId\":\"" + selfId + "\"}";
    return std::vector<uint8_t>(j.begin(), j.end());
}

static std::vector<uint8_t> makeLeave(const std::string& nick) {
    std::string j = "{\"type\":\"LEAVE\",\"nick\":\"" + jsonEscape(nick) + "\"}";
    return std::vector<uint8_t>(j.begin(), j.end());
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <nick> [room]\n";
        return 1;
    }

    const std::string nick = argv[1];
    const std::string room = (argc >= 3) ? argv[2] : "general"; 
    const std::string seedHex = loadOrCreateSeed();
    std::vector<uint8_t> seed;
    seed.resize(seedHex.size() / 2);
    for (int i = 0; i < (int)seed.size(); i++)
        seed[i] = (uint8_t)std::stoi(seedHex.substr(i * 2, 2), nullptr, 16);

    std::cout << timestamp() << "starting... nick=" << nick << " room=" << room << "\n";
    std::cout << "Commands: /peers  /nat  /quit\n\n";

    std::unordered_map<std::string, std::string> nicks;
    std::unordered_set<std::string> handshook;
    std::mutex nickMu;

    SwarmOpts opts;
    opts.seed = seed;  
    Swarm swarm(opts);


    swarm.onConnection = [&](Peer* peer, const PeerInfo& /*info*/) {
        std::cout << timestamp() << "* peer connected: "
                  << peer->id.substr(0, 8) << "… (" << peer->remoteAddress << ")\n";
        peer->_enqueue(makeJoin(nick));
    };

    swarm.onDisconnect = [&](const std::string& id) {
        std::string who;
        {
            std::lock_guard<std::mutex> lk(nickMu);
            auto it = nicks.find(id);
            who = (it != nicks.end()) ? it->second : id.substr(0, 8) + "…";
            nicks.erase(id);
            handshook.erase(id);
        }
        std::cout << timestamp() << "* " << who << " disconnected\n";
    };

    swarm.onNat = [&swarm]() {
        std::cout << timestamp() << "* nat=" << swarm.natType
                  << "  addr=" << (swarm.publicAddress.empty() ? "LAN" : swarm.publicAddress) << "\n";
    };

    swarm.onData = [&](const std::vector<uint8_t>& data, Peer* peer) {
        std::string json(data.begin(), data.end());
        std::string type    = jsonGet(json, "type");
        std::string msgNick = jsonGet(json, "nick");

        if (type == "JOIN") {
            bool fresh        = false;
            bool needHandshake = false;
            {
                std::lock_guard<std::mutex> lk(nickMu);
                fresh = nicks.find(peer->id) == nicks.end();
                nicks[peer->id] = msgNick;
                if (handshook.find(peer->id) == handshook.end()) {
                    handshook.insert(peer->id);
                    needHandshake = true;
                }
            }
            if (fresh)
                std::cout << timestamp() << "* " << msgNick << " joined\n";
            if (needHandshake)
                peer->_enqueue(makeJoin(nick));

        } else if (type == "MSG") {
            std::string selfId = jsonGet(json, "_selfId");
            if (selfId == swarm._id) return;
            std::string text = jsonGet(json, "text");
            std::cout << timestamp() << "<" << msgNick << "> " << text << "\n";

        } else if (type == "LEAVE") {
            std::lock_guard<std::mutex> lk(nickMu);
            std::cout << timestamp() << "* " << msgNick << " left\n";
            nicks.erase(peer->id);
        }
    };

    swarm.join(topicHex(room), /*announce=*/true, /*lookup=*/true);

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;

        if (line == "/quit") {
            swarm.broadcast(makeLeave(nick));
            break;
        } else if (line == "/peers") {
            auto ps = swarm.peers();
            std::cout << timestamp() << ps.size() << " peer(s) connected\n";
            std::lock_guard<std::mutex> lk(nickMu);
            for (auto* p : ps) {
                auto it = nicks.find(p->id);
                std::string pnick = (it != nicks.end()) ? it->second : "?";
                std::cout << "  " << p->id.substr(0, 8) << "…"
                          << "  nick=" << pnick
                          << "  rtt=" << (int)p->rtt << "ms"
                          << (p->inMesh ? "  [mesh]" : "") << "\n";
            }
        } else if (line == "/nat") {
            std::cout << timestamp()
                      << "nat=" << swarm.natType
                      << "  public=" << (swarm.publicAddress.empty() ? "(discovering…)"
                                                                      : swarm.publicAddress)
                      << "\n";
        } else {
            auto msg = makeMsg(nick, line, swarm._id);
            int n = swarm.broadcast(msg);
            if (n == 0)
                std::cout << timestamp() << "(no peers yet — message not delivered)\n";
        }
    }

    swarm.destroy();
    std::cout << "Bye.\n";
    return 0;
}
