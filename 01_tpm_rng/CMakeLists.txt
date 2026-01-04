cmake_minimum_required(VERSION 3.15)
project(TpmRngTbs CXX)

# Windows TBS API는 별도 설치 없이 Tbs.lib만 링크하면 됩니다.
add_executable(tpm_rng main.cpp)

# Tbs.lib 링크
target_link_libraries(tpm_rng PRIVATE Tbs.lib)
