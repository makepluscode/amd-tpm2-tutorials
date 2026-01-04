#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <bcrypt.h>
#include <iomanip>
#include <iostream>
#include <ncrypt.h>
#include <ntstatus.h>
#include <vector>
#include <winerror.h>


#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")

/**
 * @brief Helper to print hex data
 */
void PrintHex(const char *label, const BYTE *data, DWORD size) {
  std::cout << label << " (" << std::dec << size << " bytes): ";
  if (size == 0) {
    std::cout << "(empty)" << std::endl;
    return;
  }
  for (DWORD i = 0; i < size; i++) {
    std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)data[i]
              << " ";
    if (i > 32) { // Limit output for large blobs
      std::cout << "...";
      break;
    }
  }
  std::cout << std::dec << std::endl;
}

/**
 * @brief Get or Create a TPM-resident RSA Storage Key
 */
SECURITY_STATUS GetStorageKey(NCRYPT_PROV_HANDLE hProv,
                              const wchar_t *pszKeyName,
                              NCRYPT_KEY_HANDLE *phKey) {
  SECURITY_STATUS status = NCryptOpenKey(hProv, phKey, pszKeyName, 0, 0);
  if (status != ERROR_SUCCESS) {
    std::cout << "[NCrypt] Creating new RSA Storage Key..." << std::endl;
    status = NCryptCreatePersistedKey(hProv, phKey, NCRYPT_RSA_ALGORITHM,
                                      pszKeyName, 0, 0);
    if (status == ERROR_SUCCESS) {
      status = NCryptFinalizeKey(*phKey, 0);
    }
  } else {
    std::cout << "[NCrypt] Using existing RSA Storage Key." << std::endl;
  }
  return status;
}

/**
 * @brief Seal (Wrap) data using an RSA key
 */
SECURITY_STATUS SealKey(NCRYPT_KEY_HANDLE hKey, const BYTE *pbData,
                        DWORD cbData, std::vector<BYTE> &sealedBlob) {
  DWORD cbSealed = 0;
  // Query required buffer size
  SECURITY_STATUS status =
      NCryptEncrypt(hKey, (PBYTE)pbData, cbData, NULL, NULL, 0, &cbSealed,
                    NCRYPT_PAD_PKCS1_FLAG);
  if (status == ERROR_SUCCESS) {
    sealedBlob.resize(cbSealed);
    // Actual encryption
    status = NCryptEncrypt(hKey, (PBYTE)pbData, cbData, NULL, sealedBlob.data(),
                           (DWORD)sealedBlob.size(), &cbSealed,
                           NCRYPT_PAD_PKCS1_FLAG);
    if (status == ERROR_SUCCESS) {
      sealedBlob.resize(cbSealed); // Final size adjustment
    }
  }
  return status;
}

/**
 * @brief Unseal (Unwrap) data using an RSA key
 */
SECURITY_STATUS UnsealKey(NCRYPT_KEY_HANDLE hKey, const BYTE *pbSealed,
                          DWORD cbSealed, std::vector<BYTE> &unsealedData) {
  DWORD cbUnsealed = 0;
  // Query required buffer size
  SECURITY_STATUS status =
      NCryptDecrypt(hKey, (PBYTE)pbSealed, cbSealed, NULL, NULL, 0, &cbUnsealed,
                    NCRYPT_PAD_PKCS1_FLAG);
  if (status == ERROR_SUCCESS) {
    unsealedData.resize(cbUnsealed);
    // Actual decryption
    status = NCryptDecrypt(hKey, (PBYTE)pbSealed, cbSealed, NULL,
                           unsealedData.data(), (DWORD)unsealedData.size(),
                           &cbUnsealed, NCRYPT_PAD_PKCS1_FLAG);
    if (status == ERROR_SUCCESS) {
      unsealedData.resize(cbUnsealed); // Final size adjustment
    }
  }
  return status;
}

int main() {
  NCRYPT_PROV_HANDLE hProv = NULL;
  NCRYPT_KEY_HANDLE hStorageKey = NULL;
  const wchar_t *pszStorageKeyName = L"TPM_STORAGE_WRAPPER_KEY_V3";
  SECURITY_STATUS status;

  std::cout << "[Example 03] Master Key Sealing (Wrapping) with TPM"
            << std::endl;
  std::cout << "========================================================"
            << std::endl;

  // 1. Generate random Master Key
  BYTE masterKey[32] = {0};
  NTSTATUS ntStatus = BCryptGenRandom(NULL, masterKey, sizeof(masterKey),
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (ntStatus != 0) {
    std::cerr << "BCryptGenRandom failed: 0x" << std::hex << (DWORD)ntStatus
              << std::endl;
    return 1;
  }
  PrintHex("[Master Key] Original", masterKey, sizeof(masterKey));

  // 2. Open Provider
  status = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0);
  if (status != ERROR_SUCCESS) {
    std::cout << "[NCrypt] TPM not found (0x" << std::hex << status
              << "), falling back to Software KSP." << std::endl;
    status = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
  }

  if (status == ERROR_SUCCESS) {
    // 3. Get/Create Storage Key
    status = GetStorageKey(hProv, pszStorageKeyName, &hStorageKey);
    if (status == ERROR_SUCCESS) {
      // 4. Seal
      std::vector<BYTE> sealedBlob;
      status = SealKey(hStorageKey, masterKey, sizeof(masterKey), sealedBlob);
      if (status == ERROR_SUCCESS) {
        std::cout << "[NCrypt] Master Key successfully sealed." << std::endl;
        PrintHex("[Storage] Sealed Blob", sealedBlob.data(),
                 (DWORD)sealedBlob.size());

        // 5. Unseal
        std::vector<BYTE> unsealedData;
        status = UnsealKey(hStorageKey, sealedBlob.data(),
                           (DWORD)sealedBlob.size(), unsealedData);
        if (status == ERROR_SUCCESS) {
          PrintHex("[Master Key] Unsealed", unsealedData.data(),
                   (DWORD)unsealedData.size());

          // 6. Verify
          if (unsealedData.size() == sizeof(masterKey) &&
              memcmp(masterKey, unsealedData.data(), sizeof(masterKey)) == 0) {
            std::cout
                << "✓ Verification Success: Unsealed key matches original!"
                << std::endl;
          } else {
            std::cerr << "✗ Verification Failed: Key content mismatch or size "
                         "mismatch."
                      << std::endl;
            std::cerr << "Expected size: " << sizeof(masterKey)
                      << ", Actual size: " << unsealedData.size() << std::endl;
          }
        } else {
          std::cerr << "UnsealKey failed: 0x" << std::hex << status
                    << std::endl;
        }
      } else {
        std::cerr << "SealKey failed: 0x" << std::hex << status << std::endl;
      }
    } else {
      std::cerr << "GetStorageKey failed: 0x" << std::hex << status
                << std::endl;
    }
  } else {
    std::cerr << "NCryptOpenStorageProvider failed: 0x" << std::hex << status
              << std::endl;
  }

  if (hStorageKey)
    NCryptFreeObject(hStorageKey);
  if (hProv)
    NCryptFreeObject(hProv);

  return (status == ERROR_SUCCESS) ? 0 : 1;
}
