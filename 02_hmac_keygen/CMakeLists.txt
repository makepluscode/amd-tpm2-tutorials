cmake_minimum_required(VERSION 3.15)
project(TpmAesKeyGen CXX)

add_executable(aes128_keygen main.cpp)

# Windows NCrypt API and BCrypt API (for HMAC)
target_link_libraries(aes128_keygen PRIVATE ncrypt.lib bcrypt.lib)
