cmake_minimum_required(VERSION 3.15)
project(TpmNvStorage CXX)

add_executable(tpm_nv_storage main.cpp)

# Windows TBS API for low-level TPM 2.0 commands
target_link_libraries(tpm_nv_storage PRIVATE tbs.lib bcrypt.lib)
