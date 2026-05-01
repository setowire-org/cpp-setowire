#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_set>

inline const std::vector<std::string> PIPING_SERVERS = {
    "ppng.io",
    "piping.nwtgck.org",
    "piping.onrender.com",
    "piping.glitch.me",
};

struct StunHost {
    std::string host;
    uint16_t    port;
};

inline const std::vector<StunHost> STUN_HOSTS = {
    { "stun.l.google.com",      19302 },
    { "stun1.l.google.com",     19302 },
    { "stun2.l.google.com",     19302 },
    { "stun.cloudflare.com",    3478  },
    { "stun.stunprotocol.org",  3478  },
    { "global.stun.twilio.com", 3478  },
    { "stun.ekiga.net",         3478  },
};

constexpr uint8_t F_RELAY_ANN = 0x20;
constexpr uint8_t F_RELAY_REQ = 0x21;
constexpr uint8_t F_RELAY_FWD = 0x22;

constexpr uint8_t  F_PEX        = 0x30;
constexpr int      PEX_MAX      = 20;
constexpr uint32_t PEX_INTERVAL = 60'000; 

inline const std::vector<std::string> HARDCODED_SEEDS = {};

inline const std::vector<std::string> HARDCODED_HTTP_BOOTSTRAP = {
    "https://bootstrap-4eft.onrender.com",
    "https://bootsrtap.firestarp.workers.dev",
};

constexpr uint32_t PEER_CACHE_EMIT_MS = 30'000;
constexpr uint32_t BOOTSTRAP_TIMEOUT  = 15'000;

inline const std::unordered_set<std::string> RELAY_NAT_OPEN = {
    "full_cone",
    "open",
};

constexpr int      RELAY_MAX    = 20;
constexpr uint32_t RELAY_ANN_MS = 30'000;
constexpr uint32_t RELAY_BAN_MS = 5 * 60'000;

constexpr int      MAX_PEERS      = 100;
constexpr int      MAX_ADDRS_PEER = 4;
constexpr uint32_t PEER_TIMEOUT   = 60'000;
constexpr uint32_t ANNOUNCE_MS    = 18'000;
constexpr uint32_t HEARTBEAT_MS   = 1'000;
constexpr int      PUNCH_TRIES    = 8;
constexpr uint32_t PUNCH_INTERVAL = 300;

constexpr int      GOSSIP_MAX = 200'000;
constexpr uint32_t GOSSIP_TTL = 30'000;

constexpr int D_DEFAULT = 6;
constexpr int D_MIN     = 4;
constexpr int D_MAX     = 16;
constexpr int D_LOW     = 4;
constexpr int D_HIGH    = 16;
constexpr int D_GOSSIP  = 6;
constexpr int IHAVE_MAX = 200;

constexpr int BATCH_MTU      = 1400;
constexpr int BATCH_INTERVAL = 2; 

constexpr int QUEUE_CTRL = 256;
constexpr int QUEUE_DATA = 2048;

constexpr int      BLOOM_BITS   = 64 * 1024 * 1024;
constexpr int      BLOOM_HASHES = 5;
constexpr uint32_t BLOOM_ROTATE = 5 * 60'000;

constexpr int      SYNC_CACHE_MAX  = 10'000;
constexpr int      SYNC_CHUNK_SIZE = 900;
constexpr uint32_t SYNC_TIMEOUT    = 30'000;
constexpr int      HAVE_BATCH      = 64;

constexpr int      MAX_PAYLOAD   = 1200;
constexpr int      FRAG_HDR      = 12;
constexpr int      FRAG_DATA_MAX = MAX_PAYLOAD - FRAG_HDR;
constexpr uint32_t FRAG_TIMEOUT  = 10'000;

constexpr int    CWND_INIT  = 16;
constexpr int    CWND_MAX   = 512;
constexpr double CWND_DECAY = 0.75;

constexpr int RATE_PER_SEC = 128;
constexpr int RATE_BURST   = 256;

constexpr double RTT_ALPHA = 0.125;
constexpr int    RTT_INIT  = 100;

constexpr uint32_t DRAIN_TIMEOUT     = 2000;
constexpr uint32_t STUN_FAST_TIMEOUT = 1500;

constexpr int TAG_LEN   = 16;
constexpr int NONCE_LEN = 12;

constexpr uint8_t F_DATA      = 0x01;
constexpr uint8_t F_PING      = 0x03;
constexpr uint8_t F_PONG      = 0x04;
constexpr uint8_t F_FRAG      = 0x0B;
constexpr uint8_t F_GOAWAY    = 0x0A;
constexpr uint8_t F_HAVE      = 0x10;
constexpr uint8_t F_WANT      = 0x11;
constexpr uint8_t F_CHUNK     = 0x12;
constexpr uint8_t F_BATCH     = 0x13;
constexpr uint8_t F_CHUNK_ACK = 0x14;

inline const std::string MCAST_ADDR = "239.0.0.1";
constexpr uint16_t       MCAST_PORT = 45678;
constexpr uint8_t        F_LAN      = 0x09;
