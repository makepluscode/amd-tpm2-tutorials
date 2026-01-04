# TPM 2.0 Security Demos (C++)

이 저장소는 C++과 CMake를 사용하여 TPM 2.0 보안 기능을 구현한 예제들을 포함합니다.

## 프로젝트 구조

1. **01_tpm_rng**: 하드웨어 난수 생성기(RNG) 예제.
2. **02_aes128_keygen**: TPM 기반 AES-128 키 생성 예제.

## 빌드 요구 사항

- **C++ 컴파일러**: Visual Studio 2022 이상 권장
- **CMake**: 3.15 이상
- **vcpkg**: 라이브러리 관리 도구
  - 설치 필요 패키지: `vcpkg install tpm2-tss:x64-windows`

## 빠른 시작 (CLI 빌드)

```powershell
cd 01_tpm_rng
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\vcpkg\scripts\buildsystems\vcpkg.cmake"
cmake --build build --config Release
.\build\Release\tpm_rng.exe
```
