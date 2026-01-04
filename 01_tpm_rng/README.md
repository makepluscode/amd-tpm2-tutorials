# 01_tpm_rng

This project demonstrates how to interact with the **TPM (Trusted Platform Module)** on Windows using the **TBS (TPM Base Services) API**. It specifically requests 32 bytes of secure random data from the TPM's hardware random number generator.

## Prerequisites

- **Windows 10/11**
- **TPM 2.0** (Check `tpm.msc` to ensure it's enabled)
- **Visual Studio 2022** with C++ Desktop Development workload
- **CMake** (v3.15+)

## Project Structure

- `main.cpp`: Main source code using TBS API.
- `CMakeLists.txt`: CMake configuration file.
- `.gitignore`: Standard exclusion rules for build artifacts.

## How to Build

1. Open a terminal (PowerShell or Command Prompt).
2. Create a build directory and configure:
   ```powershell
   cmake -B build -S .
   ```
3. Build the project:
   ```powershell
   cmake --build build --config Release
   ```

## How to Run

After building, execute the generated binary:
```powershell
.\build\Release\tpm_rng.exe
```

### Expected Output

```text
[TBS API] Connecting to TPM...
[TBS API] Requesting 32 random bytes...
Success! Random Data: df10d564d4e430d3f89f077c79c821a12c53006d9c6774e7d907b8e84eadb30ca
```

## Troubleshooting

If you see `TBS_E_NO_DEVICE` (`0x8028400f`):
1. Ensure TPM is enabled in your BIOS/UEFI settings (look for Security Device Support, PTT, or fTPM).
2. Check if the "TPM Base Services" is running in `services.msc`.
