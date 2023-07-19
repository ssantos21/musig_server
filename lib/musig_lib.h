#pragma once

#ifndef MUSIG_LIB_H
#define MUSIG_LIB_H

#include <string>

#include "../utils/include_secp256k1_zkp_lib.h"

bool extract_keys_from_keypair(
    const secp256k1_context *ctx,
    const secp256k1_keypair &keypair,
    unsigned char seckey[32], 
    secp256k1_pubkey& pubkey, 
    unsigned char compressed_pubkey[33], 
    int compressed_pubkey_size,
    std::string& error_message
);

bool secp256k1_musig_pubnonce_to_hex(
    const secp256k1_context *ctx,
    const secp256k1_musig_pubnonce pubnonce,
    std::string& result
);

bool hex_to_secp256k1_musig_pubnonce(
    const secp256k1_context *ctx,
    std::string pubnonce_hex, 
    secp256k1_musig_pubnonce& pubnonce
);

bool hex_to_secp256k1_pubkey(
    const secp256k1_context *ctx,
    std::string pubkey_hex, 
    secp256k1_xonly_pubkey& xonly_pubkey, 
    std::string& error_message
);

bool generate_public_nonce(
    const secp256k1_context *ctx,
    const unsigned char seckey[32], 
    const secp256k1_pubkey& pubkey,
    const unsigned char *msg32, 
    secp256k1_musig_pubnonce& pubnonce,
    secp256k1_musig_secnonce& secnonce,
    std::string& error_message
);

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
);

#endif // MUSIG_LIB_H   