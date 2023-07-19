#include <assert.h>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>
#include <string>
#include <vector>

#include "musig_lib.h"
#include "../utils/strencodings.h"

bool extract_keys_from_keypair(
    const secp256k1_context *ctx,
    const secp256k1_keypair &keypair,
    unsigned char seckey[32], 
    secp256k1_pubkey& pubkey, 
    unsigned char compressed_pubkey[33], 
    int compressed_pubkey_size,
    std::string& error_message) {

    if (!secp256k1_keypair_sec(ctx, seckey, &keypair)) {
        error_message = "Failed to get the secret key from the key pair.";
        return false;
    }

    if (!secp256k1_keypair_pub(ctx, &pubkey, &keypair)) {
        error_message = "Failed to get the public key from the key pair.";
        return false;
    }

    // Serialize pubkey2 in a compressed form (33 bytes)
    size_t len = compressed_pubkey_size;
    int return_val = secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);
    // Should be the same size as the size of the output, because we passed a 33 byte array.
    if (len != compressed_pubkey_size) {
        error_message = "The serialized public key must be a 33-byte array.";
        return false;
    }

    return true;
}

bool secp256k1_musig_pubnonce_to_hex(
    const secp256k1_context *ctx,
    const secp256k1_musig_pubnonce pubnonce,
    std::string& result
) {
    unsigned char pubnonce_serialized[66];
    if (!secp256k1_musig_pubnonce_serialize(ctx, pubnonce_serialized, &pubnonce)) {
        return false;
    }
    
    result = key_to_string(pubnonce_serialized, sizeof(pubnonce_serialized));

    return true;

}

bool hex_to_secp256k1_musig_pubnonce(
    const secp256k1_context *ctx,
    std::string pubnonce_hex, 
    secp256k1_musig_pubnonce& pubnonce
) {
    if (pubnonce_hex.substr(0, 2) == "0x") {
        pubnonce_hex = pubnonce_hex.substr(2);
    }

    std::vector<unsigned char> pubnonce_serialized = ParseHex(pubnonce_hex);

    assert(pubnonce_serialized.size() == 66);

    return secp256k1_musig_pubnonce_parse(ctx, &pubnonce, pubnonce_serialized.data());
}

bool hex_to_secp256k1_pubkey(
    const secp256k1_context *ctx,
    std::string pubkey_hex, 
    secp256k1_xonly_pubkey& xonly_pubkey, 
    std::string& error_message) {

    if (pubkey_hex.substr(0, 2) == "0x") {
        pubkey_hex = pubkey_hex.substr(2);
    }

    std::vector<unsigned char> agg_pubkey_serialized = ParseHex(pubkey_hex);

    return secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey, agg_pubkey_serialized.data());
}

bool generate_public_nonce(
    const secp256k1_context *ctx,
    const unsigned char seckey[32], 
    const secp256k1_pubkey& pubkey,
    const unsigned char *msg32, 
    secp256k1_musig_pubnonce& pubnonce,
    secp256k1_musig_secnonce& secnonce,
    std::string& error_message
) {

    unsigned char session_id[32];

    if (RAND_bytes(session_id, sizeof(session_id)) != 1) {
        error_message = "Failed to generate a random number for the session id!";
        return false;
    }

    if (!secp256k1_musig_nonce_gen(ctx, &secnonce, &pubnonce, session_id, seckey, &pubkey, msg32, NULL, NULL)) {
        error_message = "Failed to initialize session and create the nonces!";
        return false;
    }

    return true;
}

bool create_partial_sign(
    const secp256k1_context *ctx,
    const secp256k1_keypair& keypair, 
    const unsigned char *msg32,
    secp256k1_musig_secnonce& local_secnonce,
    const secp256k1_musig_pubnonce& local_pubnonce,
    const secp256k1_musig_pubnonce& remote_pubnonce,
    const secp256k1_musig_keyagg_cache& cache,
    secp256k1_musig_session& session,
    secp256k1_musig_partial_sig& partial_sig,
    std::string& error_message
) {
    secp256k1_musig_aggnonce agg_pubnonce;

    const secp256k1_musig_pubnonce *pubnonces[2];
    pubnonces[0] = &remote_pubnonce;
    pubnonces[1] = &local_pubnonce;

    secp256k1_pubkey pubkey;
    if (!secp256k1_keypair_pub(ctx, &pubkey, &keypair)) {
        error_message = "Failed to get the public key from the key pair.";
        return false;
    }

    if (!secp256k1_musig_nonce_agg(ctx, &agg_pubnonce, pubnonces, 2)) {
        error_message = "Failed to create aggregate nonce!";
        return false;
    }

    if (!secp256k1_musig_nonce_process(ctx, &session, &agg_pubnonce, msg32, &cache, NULL)) {
        error_message = "Failed to initialize the session!";
        return false;
    }

    if (!secp256k1_musig_partial_sign(ctx, &partial_sig, &local_secnonce, &keypair, &cache, &session)) {
        error_message = "Failed to produce a partial signature!";
        return false;
    }

    if (!secp256k1_musig_partial_sig_verify(ctx, &partial_sig, &local_pubnonce, &pubkey, &cache, &session)) {
        error_message = "Failed to verify the partial signature!";
        return false;
    }

    return true;
}

bool create_partial_sign2(
    const secp256k1_keypair& keypair, 
    const unsigned char *msg32, 
    const secp256k1_musig_pubnonce& server_pubnonce,
    const secp256k1_musig_keyagg_cache& cache,
    std::string& error_message,
    int& error_code
) {

    secp256k1_musig_secnonce client_secnonce;
    secp256k1_musig_pubnonce client_pubnonce;

    secp256k1_musig_partial_sig partial_sig;

    unsigned char client_seckey[32];
    secp256k1_pubkey client_pubkey;

    unsigned char session_id[32];

    if (RAND_bytes(session_id, sizeof(session_id)) != 1) {
        error_message = "Failed to generate a random number for the session id!!";
        error_code = 500;
        return false;
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    int return_val = secp256k1_keypair_pub(ctx, &client_pubkey, &keypair);
    assert(return_val);

    return_val = secp256k1_keypair_sec(ctx, client_seckey, &keypair);
    assert(return_val);

    // Generate client public nonce

    if (!secp256k1_musig_nonce_gen(ctx, &client_secnonce, &client_pubnonce, session_id, client_seckey, &client_pubkey, msg32, NULL, NULL)) {
        std::cerr << "Failed to initialize session and create the nonces!" << std::endl;
        exit(1);
    }

    // Aggregate client and server nonce

    secp256k1_musig_aggnonce agg_pubnonce;

    const secp256k1_musig_pubnonce *pubnonces[2];
    pubnonces[0] = &server_pubnonce;
    pubnonces[1] = &client_pubnonce;

    secp256k1_musig_session session;

    if (!secp256k1_musig_nonce_agg(ctx, &agg_pubnonce, pubnonces, 2)) {
        std::cerr << "Failed to create aggregate nonce!" << std::endl;
        exit(1);
    }
    if (!secp256k1_musig_nonce_process(ctx, &session, &agg_pubnonce, msg32, &cache, NULL)) {
        std::cerr << "Failed to initialize the session!" << std::endl;
        exit(1);
    }

    if (!secp256k1_musig_partial_sign(ctx, &partial_sig, &client_secnonce, &keypair, &cache, &session)) {
        std::cerr << "Failed to produce a partial signature!" << std::endl;
        exit(1);
    }

    auto partial_sig_str = key_to_string(partial_sig.data, sizeof(partial_sig.data));

    std::cout << "partial_sig_str: " <<  partial_sig_str << std::endl;

    secp256k1_context_destroy(ctx);

    return true;
}