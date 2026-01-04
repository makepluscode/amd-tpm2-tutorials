cmake_minimum_required(VERSION 3.15)
project(TpmMasterKeySealing CXX)

add_executable(master_key_sealing main.cpp)

# Windows NCrypt API and BCrypt API
target_link_libraries(master_key_sealing PRIVATE ncrypt.lib bcrypt.lib)
