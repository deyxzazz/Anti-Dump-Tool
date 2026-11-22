# AntiDumpTool • Unity IL2CPP Protector
<img width="993" height="691" alt="изображение" src="https://github.com/user-attachments/assets/964bc8a4-70bc-4c27-ad69-f214c7e928c4" />


A standalone PE patcher and metadata protector for **Unity IL2CPP (x64)** builds, designed to prevent static dumping (`Il2CppDumper`, `Cpp2IL`) and basic debugging without external proxy DLLs.

## Features
- **Metadata Encryption:** Strips the `0xFAB11BAF` IL2CPP header magic and encrypts `global-metadata.dat` with a rolling XOR cipher.
- **Unique 64-bit Key Per Build:** Generates a cryptographically random 8-byte key for every protected build.
- **Standalone PE Section Injection (`.guard`):** Injects a native x64 `.guard` section directly into `GameAssembly.dll`, hooking `MapViewOfFile` via IAT to decrypt metadata in memory (`PAGE_WRITECOPY`) at runtime and checking `PEB->BeingDebugged`.
- **Source Build Mode (Mode 2):** Generates a ready-to-paste C++ snippet for `MetadataLoader.cpp` for developers compiling from source.
- **PE Header Scrubbing:** Removes `Rich` signatures and `.pdb` debug paths from `GameAssembly.dll`.
- **Built-in Decryptor & Backup Restore:** Extracts the embedded key from `.guard` to decrypt `global-metadata.dat` or restores original `.bak` files in one click.

## Usage
1. Launch `AntiDumpTool.exe`.
2. Drag & drop your Unity IL2CPP build folder (containing `GameAssembly.dll`) or click **Browse...**.
3. Select **Mode 1** (Standalone PE Patcher) or **Mode 2** (Source Build) and click **PROTECT BUILD**.
