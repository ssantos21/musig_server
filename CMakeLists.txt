cmake_minimum_required(VERSION 3.10)

project(MuSigServer)

# Specify the required C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include directories
include_directories(../../secp256k1-zkp/include)

# Source files for musig_server_bin
set(SERVER_SOURCE_FILES
    server/musig_server.cpp
    lib/musig_lib.cpp
    utils/strencodings.cpp
)

# Executable for musig_server_bin
add_executable(musig_server_bin ${SERVER_SOURCE_FILES})

set(HOME_DIR $ENV{HOME})
set(LIBSECP256K1_A_FILE_PATH "${HOME_DIR}/Dev/secp256k1-zkp/.libs/libsecp256k1.a")

# Link against libraries for musig_server_bin
target_link_libraries(musig_server_bin
    ${LIBSECP256K1_A_FILE_PATH}
    gmp
    crypto
)

# Source files for musig_client_bin
set(CLIENT_SOURCE_FILES
    client.cpp
    lib/musig_lib.cpp
    utils/strencodings.cpp
    fmt/format.cc
)

# Executable for musig_client_bin
add_executable(musig_client_bin ${CLIENT_SOURCE_FILES})

# Link against libraries for musig_client_bin
target_link_libraries(musig_client_bin
    ${LIBSECP256K1_A_FILE_PATH}
    gmp
    crypto
    cpr
    curl
)

