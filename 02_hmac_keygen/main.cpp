#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winerror.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")

/**
 * @brief Derive a device-specific key using HMAC-SHA256
 */
NTSTATUS DeriveDeviceKey(const BYTE* masterKey, DWORD masterKeySize,
                         const char* deviceId, BYTE* outKey, DWORD outKeySize) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status)) return status;

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)masterKey, masterKeySize, 0);
    if (NT_SUCCESS(status)) {
        status = BCryptHashData(hHash, (PUCHAR)deviceId, (ULONG)strlen(deviceId), 0);
        if (NT_SUCCESS(status)) {
            BYTE hmacResult[32];
            status = BCryptFinishHash(hHash, hmacResult, sizeof(hmacResult), 0);
            if (NT_SUCCESS(status)) {
                memcpy(outKey, hmacResult, outKeySize);
            }
        }
        BCryptDestroyHash(hHash);
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

/**
 * @brief Store a symmetric key in TPM or Software KSP
 */
SECURITY_STATUS StoreKeyInKSP(const BYTE* keyData, DWORD keyDataSize, const wchar_t* pszKeyName) {
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    SECURITY_STATUS status;

    // 1. Try TPM Provider first
    status = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (status != ERROR_SUCCESS) {
        std::cout << "[NCrypt] TPM provider not available, falling back to Software KSP." << std::endl;
        status = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
    }

    if (status != ERROR_SUCCESS) return status;

    // 2. Delete existing key if any
    NCRYPT_KEY_HANDLE hExistingKey = NULL;
    if (NCryptOpenKey(hProv, &hExistingKey, pszKeyName, 0, 0) == ERROR_SUCCESS) {
        NCryptDeleteKey(hExistingKey, 0);
        NCryptFreeObject(hExistingKey);
    }

    // 3. Create Persisted Key
    status = NCryptCreatePersistedKey(hProv, &hKey, L"AES", pszKeyName, 0, 0);
    if (status == NTE_NOT_SUPPORTED && hProv != NULL) {
        // If TPM doesn't support AES, fallback to Software KSP
        NCryptFreeObject(hProv);
        std::cout << "[NCrypt] TPM doesn't support AES, using Software KSP." << std::endl;
        NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
        status = NCryptCreatePersistedKey(hProv, &hKey, L"AES", pszKeyName, 0, 0);
    }

    if (status != ERROR_SUCCESS) {
        NCryptFreeObject(hProv);
        return status;
    }

    // 4. Set Key Length
    DWORD dwKeyLen = keyDataSize * 8;
    NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)&dwKeyLen, sizeof(dwKeyLen), 0);

    // 5. Import Key Data
    struct {
        DWORD dwMagic;
        DWORD dwVersion;
        DWORD cbKeyData;
        BYTE  pbKeyData[16]; // Fixed size for AES-128
    } blob;

    blob.dwMagic = 0x4d42444b; // BCRYPT_KEY_DATA_BLOB_MAGIC
    blob.dwVersion = 1;
    blob.cbKeyData = keyDataSize;
    memcpy(blob.pbKeyData, keyData, keyDataSize);

    status = NCryptSetProperty(hKey, L"KeyDataBlob", (PBYTE)&blob, sizeof(blob), 0);
    if (status != ERROR_SUCCESS) {
        // Fallback property name
        status = NCryptSetProperty(hKey, L"NCRYPT_KEY_DATA_BLOB", (PBYTE)&blob, sizeof(blob), 0);
    }

    if (status == ERROR_SUCCESS) {
        status = NCryptFinalizeKey(hKey, 0);
    }

    // Cleanup but keep handle for verification or just close it
    if (hKey) NCryptFreeObject(hKey);
    if (hProv) NCryptFreeObject(hProv);

    return status;
}

void PrintHex(const char* label, const BYTE* data, DWORD size) {
    std::cout << label << ": ";
    for (DWORD i = 0; i < size; i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)data[i] << " ";
    }
    std::cout << std::dec << std::endl;
}

int main() {
    const BYTE masterKey[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    const char* deviceId = "DEVICE-001-2024";
    BYTE deviceKey[16];

    std::cout << "[Device Provisioning] HMAC-based Device Key Generation" << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << "[HMAC] Device ID: " << deviceId << std::endl;

    NTSTATUS ntStatus = DeriveDeviceKey(masterKey, sizeof(masterKey), deviceId, deviceKey, sizeof(deviceKey));
    if (!NT_SUCCESS(ntStatus)) {
        std::cerr << "Failed to derive key: 0x" << std::hex << ntStatus << std::endl;
        return 1;
    }
    PrintHex("[HMAC] Generated Device Key", deviceKey, sizeof(deviceKey));

    SECURITY_STATUS secStatus = StoreKeyInKSP(deviceKey, sizeof(deviceKey), L"TPM_DEVICE_KEY");
    if (secStatus != ERROR_SUCCESS) {
        std::cerr << "Failed to store key: 0x" << std::hex << secStatus << std::endl;
        return 1;
    }

    std::cout << "Success! Device key processed successfully." << std::endl;
    return 0;
}
