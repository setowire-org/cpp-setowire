# Setowire - C++

A lightweight, portable P2P networking library built on UDP. No central servers, no brokers — peers find each other and communicate directly.

Port of the JavaScript implementation. Protocol-compatible — a C++ node and a JS node can talk to each other out of the box.

---

## Why

Most P2P libraries are either too heavy or too tied to a specific runtime. This port targets native applications that need low-level control without depending on a JS runtime. Same protocol, same wire format, zero runtime overhead.

---

## How it works

Peers discover each other through multiple strategies running in parallel — whichever works first wins:

- **DHT** — decentralized peer discovery by topic
- **Piping servers** — HTTPS rendezvous for peers behind strict NATs
- **LAN multicast** — instant discovery on local networks
- **HTTP bootstrap nodes** — fallback seed servers
- **Peer cache** — remembers peers from previous sessions

Once connected, all traffic is encrypted end-to-end with X25519 + ChaCha20-Poly1305. Peers that detect they have a full-cone NAT automatically become relays for others.

---

## Dependencies

- **OpenSSL** ≥ 1.1 — X25519 key exchange, ChaCha20-Poly1305, SHA-256/SHA-1
- **libcurl** — HTTPS requests (piping servers, HTTP bootstrap)
- **pthreads** — background threads (included on Linux/macOS, use `-lpthread`)

On Windows, `ws2_32` is also required (Winsock).

---

## Building

### CMake (recommended)

```bash
cmake -B build
cmake --build build
```

The `chat` binary will be at `build/chat`.

### Manual (clang++ / g++)

```bash
clang++ -std=c++17 -O2 chat.cpp -lssl -lcrypto -lcurl -lpthread -o chat
```

### Installing dependencies

**Ubuntu / Debian**
```bash
sudo apt install libssl-dev libcurl4-openssl-dev
```

**macOS (Homebrew)**
```bash
brew install openssl curl
```

**Windows (vcpkg)**
```bash
vcpkg install openssl curl
```

---

## File structure

```
constants.hpp  — all tuneable parameters and frame type definitions
crypto.hpp     — X25519 key exchange, ChaCha20-Poly1305 encrypt/decrypt
structs.hpp    — BloomFilter, LRU, RingBuffer, PayloadCache
framing.hpp    — packet fragmentation, jitter buffer, batch UDP sender
dht_lib.hpp    — minimal DHT for decentralized topic-based discovery
peer.hpp       — per-peer state: queues, congestion control, multipath
swarm.hpp      — main class: discovery, mesh, relay, sync, gossip
index.hpp      — single include entry point
chat.cpp       — example terminal chat app
CMakeLists.txt — build file
```

Everything is header-only except `chat.cpp`. Just `#include "index.hpp"` and link the dependencies.

---

## Quick start

```cpp
#include "index.hpp"
#include <openssl/sha.h>

// Hash a topic string to 64 hex chars (32 bytes)
std::string topicHex = sha256hex("my-topic");

SwarmOpts opts;
// opts.seed = { ... };  // optional: 32-byte deterministic identity

Swarm swarm(opts);

swarm.onConnection = [](Peer* peer, const PeerInfo& info) {
    std::string hello = "hello";
    peer->_enqueue(std::vector<uint8_t>(hello.begin(), hello.end()));
};

swarm.onData = [](const std::vector<uint8_t>& data, Peer* peer) {
    std::string msg(data.begin(), data.end());
    printf("got: %s\n", msg.c_str());
};

swarm.join(topicHex, /*announce=*/true, /*lookup=*/true);

// Block / run your own event loop here
```

---

## API

### `Swarm(SwarmOpts opts = {})`

| field | default | description |
|---|---|---|
| `seed` | random | `std::vector<uint8_t>` — 32-byte deterministic identity |
| `maxPeers` | 100 | max simultaneous connections |
| `relay` | false | force relay mode regardless of NAT |
| `bootstrap` | [] | `{"host:port"}` bootstrap nodes |
| `seeds` | [] | additional hardcoded seed peers |
| `bootstrapHttp` | [] | additional HTTP bootstrap URLs |
| `pipingServers` | [] | additional piping rendezvous servers |
| `exclusivePiping` | false | use only provided piping servers, ignore defaults |
| `onSavePeers` | null | `void(const vector<PeerInfo>&)` — called to persist peer cache |
| `onLoadPeers` | null | `vector<PeerInfo>()` — called on startup to restore peer cache |

### `swarm.join(topicHex, announce, lookup)`

Start announcing and/or looking up peers on a topic. `topicHex` is a hex string (typically SHA-256 of your topic name).

### `swarm.broadcast(data)`

Send data to all connected peers with an active session. Returns number of peers reached.

### `swarm.store(key, value)`

Store a value locally and announce it to the mesh.

### `swarm.fetchAsync(key, onFound, onTimeout, timeoutMs)`

Fetch a value — calls `onFound` immediately if local, otherwise pulls from the network. Calls `onTimeout` if not resolved within `timeoutMs`.

### `swarm.destroy()`

Graceful shutdown. Notifies peers and closes all sockets.

### `swarm.peers()`

Returns `std::vector<Peer*>` of all currently connected peers.

### `swarm.meshPeers()`

Returns only peers that are part of the active gossip mesh.

### `swarm.size()`

Number of connected peers.

### Callbacks

| callback | signature | description |
|---|---|---|
| `onConnection` | `void(Peer*, const PeerInfo&)` | new peer connected |
| `onData` | `void(const vector<uint8_t>&, Peer*)` | message received |
| `onDisconnect` | `void(const string& peerId)` | peer dropped |
| `onSync` | `void(const string& key, const vector<uint8_t>& value)` | value received from network |
| `onNat` | `void()` | public address discovered |

---

## Protocol

The wire protocol is plain UDP. Each packet starts with a 1-byte frame type:

| byte | type | description |
|---|---|---|
| `0x01` | DATA | encrypted application data |
| `0x03` | PING | keepalive + RTT measurement |
| `0x04` | PONG | keepalive reply |
| `0x0A` | GOAWAY | graceful disconnect |
| `0x0B` | FRAG | fragment of a large message |
| `0x13` | BATCH | multiple frames in one datagram |
| `0x20` | RELAY_ANN | peer announcing itself as relay |
| `0x21` | RELAY_REQ | request introduction via relay |
| `0x22` | RELAY_FWD | relay forwarding an introduction |
| `0x30` | PEX | peer exchange |

Handshake is two frames: `0xA1` (hello) and `0xA2` (hello ack). Each carries the sender's ID and raw X25519 public key. After that, all data is encrypted.

---

## Porting notes (interop with JS)

The C++ port is wire-compatible with the JS version. A few things to know:

- **Peer ID** — SHA-256 of the X25519 public key, first 20 bytes as hex (40 chars). Frames use the first 8 bytes (16 hex chars).
- **Session keys** — derived with HKDF-SHA256, label `p2p-v12-session`, 68 bytes output. The peer with the lexicographically lower ID uses bytes 0–31 as send key; the other peer flips send/recv.
- **Nonce** — 12 bytes: first 4 = session ID (big-endian), next 8 = send counter (big-endian).
- **Identity persistence** — seed is stored in `./identity.json` (same file as the JS chat example, fully compatible).

---

## Chat example

```bash
./chat <nick> [room]
./chat alice myroom
```

Commands: `/peers`, `/nat`, `/quit`

Identity is saved to `./identity.json` and reused on the next run — same as the JS version.

