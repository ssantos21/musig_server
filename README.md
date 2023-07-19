# Musig Server

### Dependencies used by this project

* [secp256k1-zkp](https://github.com/BlockstreamResearch/secp256k1-zkp) - A fork of libsecp256k1 with support for advanced and experimental features such as Confidential Assets and MuSig2 
* [OpenSSL](https://github.com/openssl/openssl) - TLS/SSL and crypto library 
* [CLI11](https://github.com/CLIUtils/CLI11) - CLI11 is a command line parser for C++11 and beyond that provides a rich feature set with a simple and intuitive interface. 
* [nlohmann/json](https://github.com/nlohmann/json) - JSON for Modern C++ 
* [Crow CPP](https://github.com/CrowCpp/Crow) - A Fast and Easy to use microframework for the web.
* [{fmt}](https://github.com/fmtlib/fmt) - A modern formatting library 

### Building:

* Install Crow Cpp
* Download and build secp256k1-zkp

`g++ -std=c++20  server/musig_server.cpp lib/musig_lib.cpp utils/strencodings.cpp  ../secp256k1-zkp/.libs/libsecp256k1.a -I ../secp256k1-zkp/include -lgmp  -lcrypto -o musig_server_bin`

`.\musig_server_bin`

`g++ -std=c++20 client.cpp lib/musig_lib.cpp utils/strencodings.cpp fmt/format.cc  ../secp256k1-zkp/.libs/libsecp256k1.a -I ../secp256k1-zkp/include -lgmp -lcrypto -lcpr -lcurl -o musig_client_bin`

`.\musig_client_bin execute-complete-scheme`