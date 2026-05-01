#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <vector>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "constants.hpp"

struct X25519KeyPair {
    EVP_PKEY*            privateKey;
    std::vector<uint8_t> pubRaw;
};

struct SessionKeys {
    std::vector<uint8_t> sendKey;
    std::vector<uint8_t> recvKey;
    uint32_t             sessionId;
    uint64_t             sendCtr;
};

inline std::vector<uint8_t> hkdf_sha256(
    const std::vector<uint8_t>& ikm,
    const std::vector<uint8_t>& salt,
    const std::string&          info,
    size_t                      outLen)
{
    std::vector<uint8_t> out(outLen);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), (int)salt.size());
    EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm.data(), (int)ikm.size());
    EVP_PKEY_CTX_add1_hkdf_info(ctx, (const uint8_t*)info.data(), (int)info.size());
    EVP_PKEY_derive(ctx, out.data(), &outLen);
    EVP_PKEY_CTX_free(ctx);
    return out;
}

inline X25519KeyPair generateX25519(const std::vector<uint8_t>* seed = nullptr) {
    EVP_PKEY* pkey = nullptr;

    if (seed && !seed->empty()) {
        uint8_t derived[32];
        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdCtx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(mdCtx, seed->data(), seed->size());
        unsigned int len = 32;
        EVP_DigestFinal_ex(mdCtx, derived, &len);
        EVP_MD_CTX_free(mdCtx);

        pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, derived, 32);
        if (!pkey) throw std::runtime_error("EVP_PKEY_new_raw_private_key failed");
    } else {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_keygen(ctx, &pkey);
        EVP_PKEY_CTX_free(ctx);
    }

    std::vector<uint8_t> pubRaw(32);
    size_t pubLen = 32;
    EVP_PKEY_get_raw_public_key(pkey, pubRaw.data(), &pubLen);

    return { pkey, pubRaw };
}

inline SessionKeys deriveSession(EVP_PKEY* myPriv, const std::vector<uint8_t>& theirPubRaw) {
    EVP_PKEY* theirPub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                      theirPubRaw.data(), theirPubRaw.size());
    if (!theirPub) throw std::runtime_error("EVP_PKEY_new_raw_public_key failed");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(myPriv, nullptr);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, theirPub);

    size_t sharedLen = 32;
    std::vector<uint8_t> shared(sharedLen);
    EVP_PKEY_derive(ctx, shared.data(), &sharedLen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(theirPub);

    std::vector<uint8_t> salt;
    auto derived = hkdf_sha256(shared, salt, "p2p-v12-session", 68);

    uint32_t sessionId = ((uint32_t)derived[64] << 24) |
                         ((uint32_t)derived[65] << 16) |
                         ((uint32_t)derived[66] <<  8) |
                          (uint32_t)derived[67];

    return {
        std::vector<uint8_t>(derived.begin(),      derived.begin() + 32),
        std::vector<uint8_t>(derived.begin() + 32, derived.begin() + 64),
        sessionId,
        0ULL,
    };
}

inline std::vector<uint8_t> encrypt(SessionKeys& sess, const std::vector<uint8_t>& plaintext) {
    uint8_t nonce[NONCE_LEN] = {};
    nonce[0] = (sess.sessionId >> 24) & 0xFF;
    nonce[1] = (sess.sessionId >> 16) & 0xFF;
    nonce[2] = (sess.sessionId >>  8) & 0xFF;
    nonce[3] =  sess.sessionId        & 0xFF;
    uint64_t ctr = sess.sendCtr++;
    for (int i = 0; i < 8; i++)
        nonce[4 + i] = (ctr >> (56 - 8 * i)) & 0xFF;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_LEN, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, sess.sendKey.data(), nonce);

    std::vector<uint8_t> ct(plaintext.size());
    int outLen = 0;
    EVP_EncryptUpdate(ctx, ct.data(), &outLen, plaintext.data(), (int)plaintext.size());
    int finalLen = 0;
    EVP_EncryptFinal_ex(ctx, ct.data() + outLen, &finalLen);

    uint8_t tag[TAG_LEN];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> out;
    out.insert(out.end(), nonce, nonce + NONCE_LEN);
    out.insert(out.end(), ct.begin(), ct.begin() + outLen + finalLen);
    out.insert(out.end(), tag, tag + TAG_LEN);
    return out;
}

inline std::optional<std::vector<uint8_t>> decrypt(
    const SessionKeys& sess, const std::vector<uint8_t>& buf)
{
    if ((int)buf.size() < NONCE_LEN + TAG_LEN) return std::nullopt;

    const uint8_t* nonce      = buf.data();
    const uint8_t* ciphertext = buf.data() + NONCE_LEN;
    int            ctLen      = (int)buf.size() - NONCE_LEN - TAG_LEN;
    const uint8_t* tag        = buf.data() + buf.size() - TAG_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_LEN, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, sess.recvKey.data(), nonce);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, (void*)tag);

    std::vector<uint8_t> plain(ctLen);
    int outLen = 0;
    EVP_DecryptUpdate(ctx, plain.data(), &outLen, ciphertext, ctLen);
    int finalLen = 0;
    int ok = EVP_DecryptFinal_ex(ctx, plain.data() + outLen, &finalLen);
    EVP_CIPHER_CTX_free(ctx);

    if (ok <= 0) return std::nullopt;
    plain.resize(outLen + finalLen);
    return plain;
}
