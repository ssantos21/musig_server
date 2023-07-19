#include <crow.h>
#include <openssl/rand.h>
#include <iostream>
#include <assert.h>
#include <iomanip>

#include "../utils/include_secp256k1_zkp_lib.h"
#include "../utils/strencodings.h"
#include "../lib/musig_lib.h"

struct AggregateKeyData {
    // std::vector<unsigned char> keypair; // size 96
    secp256k1_keypair keypair;
    secp256k1_musig_keyagg_cache cache;
    // std::vector<unsigned char> cache; // size 197

    crow::json::wvalue to_json() {

        crow::json::wvalue response;

        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

        secp256k1_pubkey server_pubkey;

        int return_val = secp256k1_keypair_pub(ctx, &server_pubkey, &keypair);
        assert(return_val);

        unsigned char compressed_pubkey1[33];
        size_t len;
        //int return_val;

        // Serialize pubkey2 in a compressed form (33 bytes)
        len = sizeof(compressed_pubkey1);
        return_val = secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey1, &len, &server_pubkey, SECP256K1_EC_COMPRESSED);
        assert(return_val);
        // Should be the same size as the size of the output, because we passed a 33 byte array.
        assert(len == sizeof(compressed_pubkey1));

        response["compressed_pubkey"] = key_to_string(compressed_pubkey1, sizeof(compressed_pubkey1));
        response["cache"] = key_to_string(cache.data, sizeof(cache.data));

        secp256k1_context_destroy(ctx);

        return response;
    }
};

int main() {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/about")
    ([]() {
        return "Simple MuSig2 server.";
    });

    std::map<std::string, AggregateKeyData> map_aggregate_key_data; 
    std::mutex mutex_map_aggregate_key_data; // protects map_aggregate_key_data

    CROW_ROUTE(app, "/key_aggregation")
    ([&map_aggregate_key_data, &mutex_map_aggregate_key_data]() {

        const std::lock_guard<std::mutex> lock(mutex_map_aggregate_key_data);
        crow::json::wvalue response;

        std::map<std::string, AggregateKeyData>::iterator it;

        for (it = map_aggregate_key_data.begin(); it != map_aggregate_key_data.end(); it++)
        {
            response[it->first] = it->second.to_json();
        }

        return response;
    });

    CROW_ROUTE(app, "/key_aggregation")
        .methods("POST"_method)([&map_aggregate_key_data, &mutex_map_aggregate_key_data](const crow::request& req) {
            auto x = crow::json::load(req.body);
            if (!x)
                return crow::response(400);

            std::string client_pubkey_str = x["pubkey"].s();

            secp256k1_pubkey client_pubkey;

            // Check if the string starts with 0x and remove it if necessary
            if (client_pubkey_str.substr(0, 2) == "0x") {
                client_pubkey_str = client_pubkey_str.substr(2);
            }

            std::vector<unsigned char> pub_key_serialized = ParseHex(client_pubkey_str);

            secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

            // Deserialize the public key
            if (!secp256k1_ec_pubkey_parse(ctx, &client_pubkey, pub_key_serialized.data(), pub_key_serialized.size())) {
                return crow::response(500, "Failed to parse public key!");
            }

            size_t n_pubkeys = 2;

            secp256k1_xonly_pubkey agg_pk;

            const secp256k1_pubkey *pubkeys_ptr[2];

            unsigned char server_seckey[32];
            secp256k1_pubkey server_pubkey;
            secp256k1_keypair server_keypair;

            unsigned char randomize[32];

            int return_val;

            size_t len;

            while (1) {
                if (RAND_bytes(server_seckey, sizeof(server_seckey)) != 1) {
                    return crow::response(500, "Failed to generate a random number for the private key!");
                }

                if (secp256k1_ec_seckey_verify(ctx, server_seckey)) {
                    break;
                }
            }

            return_val = secp256k1_keypair_create(ctx, &server_keypair, server_seckey);
            assert(return_val);

            return_val = secp256k1_keypair_pub(ctx, &server_pubkey, &server_keypair);
            assert(return_val);

            pubkeys_ptr[0] = &client_pubkey;
            pubkeys_ptr[1] = &server_pubkey;

            secp256k1_musig_keyagg_cache cache;

            /* If you just want to aggregate and not sign the cache can be NULL */
            if (!secp256k1_musig_pubkey_agg(ctx, NULL, &agg_pk, &cache, pubkeys_ptr, n_pubkeys)) {
                return crow::response(500, "Failed aggregate public keys!");
            }

            // Confirmation 
            unsigned char compressed_server_pubkey[33];

            // Serialize pubkey2 in a compressed form (33 bytes)
            len = sizeof(compressed_server_pubkey);
            return_val = secp256k1_ec_pubkey_serialize(ctx, compressed_server_pubkey, &len, &server_pubkey, SECP256K1_EC_COMPRESSED);
            assert(return_val);
            // Should be the same size as the size of the output, because we passed a 33 byte array.
            assert(len == sizeof(compressed_server_pubkey));

            auto compressed_server_pubkey_str = key_to_string(compressed_server_pubkey, sizeof(compressed_server_pubkey));

            unsigned char output_agg_pubkey[32];

            len = sizeof(output_agg_pubkey);
            return_val = secp256k1_xonly_pubkey_serialize(ctx, output_agg_pubkey, &agg_pk);
            assert(return_val);
            assert(len == sizeof(output_agg_pubkey));
            
            auto agg_pubkey_str = key_to_string(output_agg_pubkey, sizeof(output_agg_pubkey));

            auto server_seckey_str = key_to_string(server_seckey, sizeof(server_seckey));

            const std::lock_guard<std::mutex> lock(mutex_map_aggregate_key_data);

            map_aggregate_key_data[agg_pubkey_str].keypair = server_keypair;
            map_aggregate_key_data[agg_pubkey_str].cache = cache;

            secp256k1_context_destroy(ctx);

            crow::json::wvalue result({{"aggregate_pubkey", agg_pubkey_str}, {"server_pubkey", compressed_server_pubkey_str}});
            return crow::response{result};
        });

    CROW_ROUTE(app, "/public_nonce")
        .methods("POST"_method)([&map_aggregate_key_data, &mutex_map_aggregate_key_data](const crow::request& req) {

            const std::lock_guard<std::mutex> lock(mutex_map_aggregate_key_data);

            auto req_body = crow::json::load(req.body);
            if (!req_body)
                return crow::response(400);

            std::string agg_pubkey_str = req_body["agg_pubkey"].s();

            std::string message_hash = req_body["message_hash"].s();

            if (map_aggregate_key_data.find(agg_pubkey_str) == map_aggregate_key_data.end()) {
                return crow::response(404, "Aggregate Key Not Found.");
            }

            secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

            unsigned char server_seckey[32];

            int return_val = secp256k1_keypair_sec(ctx, server_seckey, &map_aggregate_key_data[agg_pubkey_str].keypair);
            assert(return_val);

            secp256k1_pubkey server_pubkey;

            return_val = secp256k1_keypair_pub(ctx, &server_pubkey, &map_aggregate_key_data[agg_pubkey_str].keypair);
            assert(return_val);
            
            if (agg_pubkey_str.substr(0, 2) == "0x") {
                agg_pubkey_str = agg_pubkey_str.substr(2);
            }

            std::vector<unsigned char> agg_pubkey_serialized = ParseHex(agg_pubkey_str);

            secp256k1_xonly_pubkey agg_pubkey;

            // Deserialize the public key
            if (!secp256k1_xonly_pubkey_parse(ctx, &agg_pubkey, agg_pubkey_serialized.data())) {
                return crow::response(500, "Failed to parse aggregate public key!");
            }

            unsigned char session_id[32];

            if (RAND_bytes(session_id, sizeof(session_id)) != 1) {
                return crow::response(500, "Failed to generate a random number for the session id!");
            }

            secp256k1_musig_pubnonce pubnonce;
            secp256k1_musig_secnonce secnonce;

            unsigned char msg[32];
            if (message_hash.size() != 64) {
                return crow::response(400, "Invalid message hash length. Must be 32 bytes!");
            }

            if (!hex_to_bytes(message_hash, msg)) {
                return crow::response(400, "Invalid message hash!");
            }

            if (!secp256k1_musig_nonce_gen(ctx, &secnonce, &pubnonce, session_id, server_seckey, &server_pubkey, msg, NULL, NULL)) {
                return crow::response(500, "Failed to initialize session and create the nonces!");
            }

            secp256k1_context_destroy(ctx);

            auto pubnonce_str = key_to_string(pubnonce.data, sizeof(pubnonce.data));

            crow::json::wvalue result({{"public_nonce", pubnonce_str}});
            return crow::response{result};
        });

    CROW_ROUTE(app, "/partial_signature")
        .methods("POST"_method)([&map_aggregate_key_data, &mutex_map_aggregate_key_data](const crow::request& req) {

            secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

            const std::lock_guard<std::mutex> lock(mutex_map_aggregate_key_data);

            auto req_body = crow::json::load(req.body);
            if (!req_body)
                return crow::response(400);

            std::string agg_pubkey_hex = req_body["agg_pubkey"].s();
            std::string message_hash = req_body["message_hash"].s();
            std::string client_pubnonce_hex = req_body["pubnonce"].s();

            if (map_aggregate_key_data.find(agg_pubkey_hex) == map_aggregate_key_data.end()) {
                return crow::response(404, "Aggregate Key Not Found.");
            }

            std::string error_message;

            unsigned char seckey[32];
            secp256k1_pubkey pubkey;
            unsigned char compressed_pubkey[33];

            bool return_val = extract_keys_from_keypair(
                ctx, map_aggregate_key_data[agg_pubkey_hex].keypair, seckey, pubkey, compressed_pubkey, sizeof(compressed_pubkey), error_message
            );

            if (!return_val) {
                return crow::response(500, error_message);
            }

            unsigned char msg[32];

            if (message_hash.size() != 64) {
                return crow::response(400, "Invalid message hash length. Must be 32 bytes!");
            }

            if (!hex_to_bytes(message_hash, msg)) {
                return crow::response(400, "Invalid message hash!");
            }

            secp256k1_musig_pubnonce server_pubnonce;
            secp256k1_musig_secnonce server_secnonce;

            return_val = generate_public_nonce(
                ctx, seckey, pubkey, msg, server_pubnonce, server_secnonce, error_message
            );

            if (!return_val) {
                return crow::response(500, error_message);
            }

            secp256k1_musig_pubnonce client_pubnonce;
            if (!hex_to_secp256k1_musig_pubnonce(ctx, client_pubnonce_hex, client_pubnonce)) {
                return crow::response(400, "Failed to parse the client's public nonce. Invalid public nonce.");
            }

            secp256k1_musig_session session;
            secp256k1_musig_partial_sig partial_sig;
            return_val = create_partial_sign(ctx,
                map_aggregate_key_data[agg_pubkey_hex].keypair, 
                msg,
                server_secnonce,
                server_pubnonce,
                client_pubnonce,
                map_aggregate_key_data[agg_pubkey_hex].cache,
                session,
                partial_sig,
                error_message
            );

            secp256k1_context_destroy(ctx);

            if (!return_val) {
                return crow::response(500, error_message);
            }

            auto partial_sig_hex = key_to_string(partial_sig.data, sizeof(partial_sig.data));

            std::string server_pubnonce_hex;

            if (!secp256k1_musig_pubnonce_to_hex(ctx, server_pubnonce, server_pubnonce_hex)) {
                return crow::response(500, "Error: Failed to serialize the server's public nonce");
            }

            crow::json::wvalue result({{"partial_sig", partial_sig_hex}, {"public_nonce", server_pubnonce_hex}});
            return crow::response{result};
        });

    app.port(18080).run();

    return 0;
}