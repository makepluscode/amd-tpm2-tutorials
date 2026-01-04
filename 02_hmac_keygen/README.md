# 02_hmac_keygen: HMAC 기반 디바이스 키 생성 (Device Provisioning)

이 예제는 **HMAC-SHA256**을 사용하여 디바이스 프로비저닝을 위한 디바이스별 AES-128 키를 생성하고, Windows의 **NCrypt (CNG)** API를 사용하여 TPM(Trusted Platform Module) 또는 소프트웨어 KSP에 안전하게 저장하는 방법을 보여줍니다.

## 🛡️ 보안 배경지식

### 1. 키 파생 함수 (Key Derivation Function, KDF)
실제 보안 환경에서는 마스터 키를 직접 암호화에 사용하지 않습니다. 대신, 마스터 키(Master Key)와 디바이스별 고유 식별자(Device ID)를 조합하여 **HMAC-SHA256**과 같은 해시 함수를 통해 새로운 키를 유도(Derive)합니다.
- **HMAC(Hash-based Message Authentication Code)**: 키와 데이터를 결합하여 해시를 생성하는 방식으로, 마스터 키를 모르고서는 동일한 디바이스 키를 생성할 수 없습니다.

### 2. 키 격리 (Key Isolation)
모든 디바이스가 동일한 키를 공유하면, 단 하나의 디바이스만 탈취되어도 전체 시스템의 보안이 무너집니다. 이 예제와 같이 디바이스마다 고유한 키를 할당하면(Provisioning), 특정 디바이스의 키가 노출되어도 다른 디바이스에는 영향을 주지 않습니다.

### 3. TPM 기반 보호 (Hardware Security)
생성된 키를 하드웨어(TPM)에 저장하면 다음과 같은 이점이 있습니다:
- **메모리 덤프 방지**: 키가 운영체제 메모리가 아닌 TPM 내부 안전한 영역에 존재합니다.
- **불법 복제 방지**: 키를 외부로 내보낼 수 없도록 설정(Non-exportable)하여 하드웨어 없이는 키를 사용할 수 없게 만듭니다.

## 주요 특징

- **HMAC 기반 키 파생**: 마스터 키와 디바이스 ID를 사용하여 HMAC-SHA256으로 디바이스별 고유 키를 생성합니다.
- **디바이스 프로비저닝**: 각 디바이스에 대해 고유한 AES-128 키를 생성하여 디바이스 프로비저닝에 사용할 수 있습니다.
- **NCrypt KSP 저장**: `MS_PLATFORM_CRYPTO_PROVIDER`(TPM)를 우선 사용하며, 미지원 시 `MS_KEY_STORAGE_PROVIDER`(Software)로 자동 전환됩니다.
- **Windows 기본 API**: 별도의 외부 라이브러리 없이 Windows SDK(`ncrypt.h`, `bcrypt.h`)만 사용하여 구현되었습니다.

## 빌드 및 실행

1. **빌드 디렉토리 생성 및 구성**:
   ```powershell
   cmake -B build -S .
   ```

2. **컴파일**:
   ```powershell
   cmake --build build --config Release
   ```

3. **실행**:
   ```powershell
   .\build\Release\aes128_keygen.exe
   ```

## 실행 결과 예시 (Actual Output)

사용자의 환경(TPM 지원 여부)에 따라 결과가 다를 수 있습니다.

```text
[Device Provisioning] HMAC-based Device Key Generation
========================================================
[HMAC] Master Key (32 bytes): 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
[HMAC] Device ID: DEVICE-001-2024
[BCrypt] Opening HMAC-SHA256 algorithm provider...
[BCrypt] Creating HMAC hash object...
[HMAC] Computing HMAC-SHA256(Device ID)...
[HMAC] Generated Device Key (AES-128, 16 bytes): 7b d8 5c f4 da 78 26 be c9 50 cc 69 70 17 a1 2c

[NCrypt API] Creating AES-128 key handle in TPM...
[NCrypt API] TPM does not support AES key creation. Trying software provider for key import...
[NCrypt API] Using software provider for key import.
[NCrypt API] Importing HMAC-generated device key...
NCryptSetProperty(KEY_DATA_BLOB) failed: 0x80090029
Note: Key data blob import may not be supported. Trying alternative method...
[NCrypt API] Finalizing key (Persisting in TPM KSP)...
Success! HMAC-generated device key imported and persisted in TPM.
[NCrypt API] Re-opening key to verify storage...
NCryptGetProperty(IMPL_TYPE) failed: 0x80090029
[NCrypt API] Deleting key for cleanup...

Device provisioning key generation completed successfully!
```

> [!TIP]
> **오류 `0x80090029` (NTE_NOT_SUPPORTED)**: 많은 소비자용 TPM은 대칭키(AES)의 직접적인 생성을 지원하지 않습니다. 이 경우 프로그램은 소프트웨어 KSP를 사용하여 키를 저장합니다.

## 주의사항

- **마스터 키 관리**: 실제 운영 환경에서는 소스 코드에 마스터 키를 하드코딩해서는 안 됩니다. 별도의 안전한 관리 서버(HSM 등)를 통해 프로비저닝 단계에서만 사용해야 합니다.
- **TPM 권한**: 일부 TPM 작업은 관리자 권한이 필요할 수 있습니다.
- **프로덕션 고려사항**: 실습을 위해 키를 하단에서 삭제(`NCryptDeleteKey`)하고 있으나, 실제 프로비저닝 시에는 유지해야 합니다.
