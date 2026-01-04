#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <bcrypt.h>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <ntstatus.h>
#include <tbs.h>
#include <vector>
#include <winerror.h>

#pragma comment(lib, "tbs.lib")
#pragma comment(lib, "bcrypt.lib")

/**
 * @brief Helper to print hex data
 */
void PrintHex(const char *label, const BYTE *data, DWORD size) {
  std::cout << label << " (" << std::dec << size << " bytes): ";
  for (DWORD i = 0; i < size; i++) {
    std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)data[i]
              << " ";
  }
  std::cout << std::dec << std::endl;
}

/**
 * @brief TPM 2.0 NV Index Definition structure (simplified for example)
 */
struct TPM2_NV_PUBLIC_PART {
  UINT32 nvIndex;
  UINT16 nameAlg;
  UINT32 attributes;
  UINT16 authPolicySize;
  UINT16 dataSize;
};

/**
 * @brief Send a raw TPM 2.0 command via TBS
 */
HRESULT SubmitTpmCommand(TBS_HCONTEXT hContext, const BYTE *cmd, UINT32 cmdSize,
                         BYTE *resp, UINT32 *respSize) {
  return Tbsip_Submit_Command(hContext, TBS_COMMAND_LOCALITY_ZERO,
                              TBS_COMMAND_PRIORITY_NORMAL, cmd, cmdSize, resp,
                              respSize);
}

/**
 * @brief Define an NV Index in TPM
 */
HRESULT DefineNVIndex(TBS_HCONTEXT hContext, UINT32 index, UINT16 size) {
  std::cout << "[TPM] Defining NV Index 0x" << std::hex << index
            << " (Size: " << std::dec << size << ")..." << std::endl;

  // TPM2_NV_DefineSpace Command
  // Tag(2) + Size(4) + CC(4) + AuthHandle(4) + AuthSize(2) + PublicInfoSize(2)
  // + PublicInfo + AuthValueSize(2) + AuthValue
  BYTE cmd[1024] = {
      0x80, 0x02, // Tag: TPM_ST_SESSIONS
      0x00, 0x00,
      0x00, 0x00, // Size (Placeholder)
      0x00, 0x00,
      0x01, 0x2A, // CC: TPM_CC_NV_DefineSpace
      0x40, 0x00,
      0x00, 0x01, // AuthHandle: TPM_RH_OWNER

      0x00, 0x00,
      0x00, 0x09, // Session: Handle(4) + Nonce(2) + Attr(1) + PasswordSize(2)
      0x40, 0x00,
      0x00, 0x09, // Session Handle: TPM_RS_PW
      0x00, 0x00, // Nonce
      0x00,       // Attributes
      0x00, 0x00, // Password (empty)

      0x00, 0x00 // AuthValueSize (empty)
  };

  // Public Area Construction
  BYTE publicArea[32];
  int p = 0;
  publicArea[p++] = (BYTE)(index >> 24);
  publicArea[p++] = (BYTE)(index >> 16);
  publicArea[p++] = (BYTE)(index >> 8);
  publicArea[p++] = (BYTE)(index & 0xFF); // nvIndex
  publicArea[p++] = 0x00;
  publicArea[p++] = 0x0B; // nameAlg: TPM_ALG_SHA256
  publicArea[p++] = 0x00;
  publicArea[p++] = 0x06;
  publicArea[p++] = 0x20;
  publicArea[p++] =
      0x02; // attributes: TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD |
            // TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE | TPMA_NV_NO_DA
  publicArea[p++] = 0x00;
  publicArea[p++] = 0x00; // authPolicySize
  publicArea[p++] = (BYTE)(size >> 8);
  publicArea[p++] = (BYTE)(size & 0xFF); // dataSize

  // Insert Public Info size and data
  cmd[22] = 0x00;
  cmd[23] = (BYTE)p;
  memcpy(cmd + 24, publicArea, p);

  // Auth Value Size (already set to 0x00 0x00)
  int totalSize = 24 + p + 2;
  cmd[2] = (BYTE)(totalSize >> 24);
  cmd[3] = (BYTE)(totalSize >> 16);
  cmd[4] = (BYTE)(totalSize >> 8);
  cmd[5] = (BYTE)(totalSize & 0xFF);

  BYTE resp[512];
  UINT32 respSize = sizeof(resp);
  HRESULT hr = SubmitTpmCommand(hContext, cmd, totalSize, resp, &respSize);

  if (hr == S_OK) {
    UINT32 resCode =
        (resp[6] << 24) | (resp[7] << 16) | (resp[8] << 8) | resp[9];
    if (resCode != 0) {
      if (resCode == 0x14C) { // TPM_RC_NV_DEFINED
        std::cout << "[TPM] NV Index already defined." << std::endl;
        return S_OK;
      }
      if (resCode == 0x80280400) { // TBS_E_COMMAND_BLOCKED
        std::cerr << "TPM Error: 0x" << std::hex << resCode
                  << " (Command Blocked)" << std::endl;
        std::cerr << "Tip: Windows is blocking raw TPM NV commands. See "
                     "README.md for unblocking instructions."
                  << std::endl;
      } else {
        std::cerr << "TPM Error: 0x" << std::hex << resCode << std::endl;
      }
      return E_FAIL;
    }
  }
  return hr;
}

/**
 * @brief Write data to an NV Index
 */
HRESULT WriteNVData(TBS_HCONTEXT hContext, UINT32 index, const BYTE *data,
                    UINT16 size) {
  std::cout << "[TPM] Writing data to NV Index 0x" << std::hex << index << "..."
            << std::endl;

  // TPM2_NV_Write Command
  // Tag(2) + Size(4) + CC(4) + AuthHandle(4) + NVIndex(4) + SessionInfo +
  // DataSize(2) + Data
  BYTE cmd[1024] = {
      0x80, 0x02, // Tag: TPM_ST_SESSIONS
      0x00, 0x00,
      0x00, 0x00, // Size
      0x00, 0x00,
      0x01, 0x37, // CC: TPM_CC_NV_Write
      0x40, 0x00,
      0x00, 0x01, // AuthHandle: TPM_RH_OWNER (could be index handle)
  };
  int p = 14;
  cmd[p++] = (BYTE)(index >> 24);
  cmd[p++] = (BYTE)(index >> 16);
  cmd[p++] = (BYTE)(index >> 8);
  cmd[p++] = (BYTE)(index & 0xFF); // nvIndex

  // Session: Handle(4) + Nonce(2) + Attr(1) + PasswordSize(2)
  cmd[p++] = 0x00;
  cmd[p++] = 0x00;
  cmd[p++] = 0x00;
  cmd[p++] = 0x09;
  cmd[p++] = 0x40;
  cmd[p++] = 0x00;
  cmd[p++] = 0x00;
  cmd[p++] = 0x09; // TPM_RS_PW
  cmd[p++] = 0x00;
  cmd[p++] = 0x00; // Nonce
  cmd[p++] = 0x00; // Attr
  cmd[p++] = 0x00;
  cmd[p++] = 0x00; // Password

  cmd[p++] = (BYTE)(size >> 8);
  cmd[p++] = (BYTE)(size & 0xFF); // dataSize
  memcpy(cmd + p, data, size);
  p += size;
  cmd[p++] = 0x00;
  cmd[p++] = 0x00; // offset

  cmd[2] = (BYTE)(p >> 24);
  cmd[3] = (BYTE)(p >> 16);
  cmd[4] = (BYTE)(p >> 8);
  cmd[5] = (BYTE)(p & 0xFF);

  BYTE resp[512];
  UINT32 respSize = sizeof(resp);
  HRESULT hr = SubmitTpmCommand(hContext, cmd, p, resp, &respSize);
  if (hr == S_OK) {
    UINT32 resCode =
        (resp[6] << 24) | (resp[7] << 16) | (resp[8] << 8) | resp[9];
    if (resCode != 0)
      return E_FAIL;
  }
  return hr;
}

/**
 * @brief Read data from an NV Index
 */
HRESULT ReadNVData(TBS_HCONTEXT hContext, UINT32 index, BYTE *data,
                   UINT16 size) {
  std::cout << "[TPM] Reading data from NV Index 0x" << std::hex << index
            << "..." << std::endl;

  // TPM2_NV_Read Command
  BYTE cmd[1024] = {
      0x80, 0x02, // Tag: TPM_ST_SESSIONS
      0x00, 0x00,
      0x00, 0x00, // Size
      0x00, 0x00,
      0x01, 0x4E, // CC: TPM_CC_NV_Read
      0x40, 0x00,
      0x00, 0x01, // AuthHandle: TPM_RH_OWNER (could be index handle)
  };
  int p = 14;
  cmd[p++] = (BYTE)(index >> 24);
  cmd[p++] = (BYTE)(index >> 16);
  cmd[p++] = (BYTE)(index >> 8);
  cmd[p++] = (BYTE)(index & 0xFF); // nvIndex

  // Session
  cmd[p++] = 0x00;
  cmd[p++] = 0x00;
  cmd[p++] = 0x00;
  cmd[p++] = 0x09;
  cmd[p++] = 0x40;
  cmd[p++] = 0x00;
  cmd[p++] = 0x00;
  cmd[p++] = 0x09; // TPM_RS_PW
  cmd[p++] = 0x00;
  cmd[p++] = 0x00;
  cmd[p++] = 0x00;
  cmd[p++] = 0x00;
  cmd[p++] = 0x00;

  cmd[p++] = (BYTE)(size >> 8);
  cmd[p++] = (BYTE)(size & 0xFF); // dataSize
  cmd[p++] = 0x00;
  cmd[p++] = 0x00; // offset

  cmd[2] = (BYTE)(p >> 24);
  cmd[3] = (BYTE)(p >> 16);
  cmd[4] = (BYTE)(p >> 8);
  cmd[5] = (BYTE)(p & 0xFF);

  BYTE resp[1024];
  UINT32 respSize = sizeof(resp);
  HRESULT hr = SubmitTpmCommand(hContext, cmd, p, resp, &respSize);
  if (hr == S_OK) {
    UINT32 resCode =
        (resp[6] << 24) | (resp[7] << 16) | (resp[8] << 8) | resp[9];
    if (resCode == 0) {
      UINT16 readSize = (resp[10] << 8) | resp[11];
      memcpy(data, resp + 12, readSize);
    } else {
      return E_FAIL;
    }
  }
  return hr;
}

/**
 * @brief Undefine (Delete) an NV Index
 */
HRESULT UndefineNVIndex(TBS_HCONTEXT hContext, UINT32 index) {
  std::cout << "[TPM] Undefining NV Index 0x" << std::hex << index << "..."
            << std::endl;

  // TPM2_NV_UndefineSpace Command
  BYTE cmd[1024] = {
      0x80, 0x02,             // Tag: TPM_ST_SESSIONS
      0x00, 0x00, 0x00, 0x1A, // Size (26 bytes)
      0x00, 0x00, 0x01, 0x22, // CC: TPM_CC_NV_UndefineSpace
      0x40, 0x00, 0x00, 0x01, // AuthHandle: TPM_RH_OWNER
  };
  cmd[14] = (BYTE)(index >> 24);
  cmd[15] = (BYTE)(index >> 16);
  cmd[16] = (BYTE)(index >> 8);
  cmd[17] = (BYTE)(index & 0xFF);

  // Session
  cmd[18] = 0x00;
  cmd[19] = 0x00;
  cmd[20] = 0x00;
  cmd[21] = 0x09;
  cmd[22] = 0x40;
  cmd[23] = 0x00;
  cmd[24] = 0x00;
  cmd[25] = 0x09;
  // ... Simplified, rest are 0

  BYTE resp[512];
  UINT32 respSize = sizeof(resp);
  return SubmitTpmCommand(hContext, cmd, 26, resp, &respSize);
}

int main() {
  TBS_HCONTEXT hContext = NULL;
  TBS_CONTEXT_PARAMS2 params;
  params.version = TBS_CONTEXT_VERSION_TWO;
  params.includeTpm12 = 0;
  params.includeTpm20 = 1;

  std::cout << "[Example 04] TPM NV Storage (Hardware Secure Storage)"
            << std::endl;
  std::cout << "========================================================"
            << std::endl;

  HRESULT hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &hContext);
  if (hr != S_OK) {
    std::cerr << "Failed to create TBS context: 0x" << std::hex << hr
              << std::endl;
    return 1;
  }

  const UINT32 nvIndex = 0x01500001; // User-defined NV index
  const char *secret = "TPM_SAFE_SECRET_2026";
  const UINT16 secretSize = (UINT16)strlen(secret);

  // 1. Define NV Space
  if (DefineNVIndex(hContext, nvIndex, 64) == S_OK) {
    // 2. Write Data
    if (WriteNVData(hContext, nvIndex, (const BYTE *)secret, secretSize) ==
        S_OK) {
      std::cout << "✓ Successfully wrote secret to TPM NV RAM." << std::endl;

      // 3. Read Data back
      BYTE readBuffer[64] = {0};
      if (ReadNVData(hContext, nvIndex, readBuffer, secretSize) == S_OK) {
        PrintHex("[TPM] Read Secret", readBuffer, secretSize);
        if (strncmp((char *)readBuffer, secret, secretSize) == 0) {
          std::cout
              << "✓ Verification Success: Read data matches original secret!"
              << std::endl;
        }
      }
    }
  }

  // 4. Cleanup (Optional: keep it to see persistency, or delete to leave no
  // trace)
  std::cout
      << std::endl
      << "[Cleanup] Do you want to delete the NV index? (For demo, deleting...)"
      << std::endl;
  UndefineNVIndex(hContext, nvIndex);

  Tbsip_Context_Close(hContext);
  return 0;
}
