#define WIN32_LEAN_AND_MEAN
#include <iomanip>
#include <iostream>
#include <vector>
#include <windows.h>


extern "C" {
#include <tbs.h>
}

#pragma comment(lib, "tbs.lib")

/**
 * @brief Handles TPM Base Services (TBS) Context
 */
class TbsContext {
public:
  TbsContext() : m_hContext(NULL) {}
  ~TbsContext() {
    if (m_hContext) {
      Tbsip_Context_Close(m_hContext);
    }
  }

  HRESULT Initialize() {
    TBS_CONTEXT_PARAMS2 params;
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm12 = 1;
    params.includeTpm20 = 1;

    return Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &m_hContext);
  }

  TBS_HCONTEXT Get() const { return m_hContext; }

private:
  TBS_HCONTEXT m_hContext;
};

/**
 * @brief TPM2_GetRandom command wrapper
 */
HRESULT GetRandom(TBS_HCONTEXT hContext, UINT16 bytesRequested,
                  std::vector<BYTE> &randomData) {
  // TPM2_GetRandom Command Buffer
  BYTE cmd[] = {
      0x80, 0x01,             // Tag: TPM_ST_NO_SESSIONS
      0x00, 0x00, 0x00, 0x0C, // Size: 12 bytes
      0x00, 0x00, 0x01, 0x7B, // CommandCode: TPM_CC_GetRandom
      0x00, 0x00              // BytesRequested (Placeholder)
  };
  cmd[10] = (BYTE)(bytesRequested >> 8);
  cmd[11] = (BYTE)(bytesRequested & 0xFF);

  BYTE response[512];
  UINT32 responseSize = sizeof(response);

  HRESULT hr = Tbsip_Submit_Command(
      hContext, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, cmd,
      (UINT32)sizeof(cmd), response, &responseSize);

  if (hr != S_OK)
    return hr;

  if (responseSize < 12)
    return E_FAIL;

  UINT32 resCode = (response[6] << 24) | (response[7] << 16) |
                   (response[8] << 8) | response[9];

  if (resCode != 0) {
    std::cerr << "TPM Error Code: 0x" << std::hex << resCode << std::endl;
    return E_FAIL;
  }

  UINT16 dataSize = (response[10] << 8) | response[11];
  randomData.assign(response + 12, response + 12 + dataSize);

  return S_OK;
}

void PrintHex(const std::vector<BYTE> &data) {
  for (BYTE b : data) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
  }
  std::cout << std::dec << std::endl;
}

int main() {
  TbsContext tbs;

  std::cout << "[TBS API] Connecting to TPM..." << std::endl;
  HRESULT hr = tbs.Initialize();
  if (hr != S_OK) {
    std::cerr << "Failed to initialize TBS context: 0x" << std::hex << hr
              << std::endl;
    if (hr == 0x8028400F) {
      std::cerr << "Error: TPM device not found. Check BIOS/UEFI settings and "
                   "TPM Base Services."
                << std::endl;
    }
    return 1;
  }

  const UINT16 requestSize = 32;
  std::vector<BYTE> randomData;

  std::cout << "[TBS API] Requesting " << requestSize << " random bytes..."
            << std::endl;
  hr = GetRandom(tbs.Get(), requestSize, randomData);

  if (hr == S_OK) {
    std::cout << "Success! Random Data: ";
    PrintHex(randomData);
  } else {
    std::cerr << "Failed to get random data: 0x" << std::hex << hr << std::endl;
    return 1;
  }

  return 0;
}
