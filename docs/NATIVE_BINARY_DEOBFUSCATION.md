# Our Notes 1.0.1 arm64 binary recovery

Use `analysis/il2cpp/libil2cpp-deobfuscated.so` with the complete `analysis/il2cpp/global-metadata-decrypted-v39.dat` for Cpp2IL and Il2CppInspectorRedux. The repaired ELF is 214,602,464 bytes, SHA-256 `f99e3d1537d5515d6bdd7f47ba429484208f14c6be404d79eefd3f8963a44b55`. The original package ELF remains unchanged, SHA-256 `514a5b73d038c264b60cc91fd4a747cf178190c6b2096e6d7007c2020e2b1bca`.

## Cause of the impossible count

Cpp2IL's [binary initializer](https://github.com/SamboyCoding/Cpp2IL/blob/development/LibCpp2IL/Il2CppBinary.cs) reads `genericMethodTable` from `MetadataRegistration`, then computes the adjustor thunk pointer-array length as `Max(adjustorThunk) + 1`. The table begins at ELF file offset `0x26e2818`, contains 345,722 records of four 32-bit integers, and crosses periodically protected windows. In the original file, 69,111 `adjustorThunk` fields contain `0x67676767`. Their decoded value is `0xffffffff` (`-1`, the no-thunk sentinel), because `0x67676767 XOR 0x98989898 = 0xffffffff`. The bogus maximum therefore becomes the reported count `0x67676768`. Cpp2IL tried to read that many pointers at raw offset `0xbe9ca08` (the relocated adjustor-thunk array address), beyond the ELF's `0xcca92e0` length.

After recovery, all 345,722 generic table records have nondecreasing method-spec indices within the 424,396 registered specs. Their method and invoker indices are in range, and the maximum real adjustor index is 68,983. The pointer-array length is therefore 68,984.

## Recovery

The original is a valid ELF with usable loader code and relocation data. Its `.rodata` and generated `il2cpp` sections are selectively obfuscated. In each section, file offsets `0xc000..0xffff` of each `0x10000` block are XORed with `0x98`. The final partial block after the last full window is XORed through the section end: `.rodata` has a `0x17d4`-byte tail and `il2cpp` has a `0xa434`-byte tail.

Each section's **first** protected 16 KB window uses a different transform. A native arm64 Frida probe captured those plaintext windows from the loaded game:

| Section | File offset | Runtime snapshot | SHA-256 |
|---|---:|---|---|
| `.rodata` | `0x1ffc000` | `analysis/il2cpp/rodata_first_mask-runtime.bin` | `8cda0fc954cc1492d38c83e3f1acec7e94d262d6c2f0b0d20eadc82e92c60b7c` |
| `il2cpp` | `0x54cc000` | `analysis/il2cpp/il2cpp_first_mask-runtime.bin` | `18deac63ea28c6ea1b651176a735cfb56923395a9f0e309c3836cf739c345891` |

The snapshots reproduced byte for byte on repeat launches. The `analysis/il2cpp/native-runtime-probe.log` compares loaded memory with the original and repaired ELF at the first, middle, and last protected windows, both full trailing spans, and unchanged pages. Every sampled byte in the repaired sections matches loaded memory. No ELF relocation targets occur in the two patched sections; observed differences in `.data.rel.ro` are normal loader relocations. The initial-window algorithm itself has not been recovered statically, so the saved runtime snapshots are inputs to a reproducible offline repair.

[`deobfuscate_native_binary.py`](../tools/deobfuscate_native_binary.py) verifies the input and snapshot hashes, checks section offsets and sizes, restores 212 `.rodata` and 1,682 `il2cpp` windows plus both tails, validates the whole generic method table, and writes a separate ELF:

```powershell
python .\tools\deobfuscate_native_binary.py '.\BanG+Dream!+Our+Notes_1.0.1_APKPure\config.arm64_v8a\lib\arm64-v8a\libil2cpp.so' .\analysis\il2cpp .\analysis\il2cpp\libil2cpp-deobfuscated.so
```

The loaded process shows the restored bytes, but this probe does not identify which game component performs the transformation. The native Poco F3 still exits shortly after startup; the repaired ELF is an offline analysis artifact, not a device patch.

## Analyzer results

Cpp2IL development build 1715 completed on the repaired ELF and metadata: it initialized the binary, mapped 234,093 pointers to method definitions, and generated 201 DLLs (19,448,832 bytes total) under `analysis/il2cpp/cpp2il-deobfuscated`. Its run log (`analysis/il2cpp/cpp2il-deobfuscated.log`) ends with `Done`. The `dll_empty` format contains reconstructed managed declarations with empty method bodies; it does not reconstruct C# implementations from native code.

Il2CppInspectorRedux CLI 2026.2 completed its IL2CPP analysis and exported `analysis/il2cpp/inspector-deobfuscated/cs/il2cpp.cs` (39,868,453 bytes); see its run log (`analysis/il2cpp/inspector-deobfuscated.log`). It warns that no exact IL2CPP API match was found, so C++ project API availability would be partial. The C# type export completed.

```powershell
$binary = (Resolve-Path -LiteralPath '.\analysis\il2cpp\libil2cpp-deobfuscated.so').Path
$metadata = (Resolve-Path -LiteralPath '.\analysis\il2cpp\global-metadata-decrypted-v39.dat').Path
& .\analysis\tooling\Cpp2IL\Cpp2IL.exe --force-binary-path $binary --force-metadata-path $metadata --force-unity-version 6000.3.12f1 --output-as dll_empty --output-to .\analysis\il2cpp\cpp2il-deobfuscated
& "$env:USERPROFILE\Downloads\Il2CppInspectorRedux.CLI-win-x64\Il2CppInspector.Redux.CLI.exe" process $binary $metadata --unity-version 6000.3.12f1 -o .\analysis\il2cpp\inspector-deobfuscated -s
```

The earlier `analysis/il2cpp/dump-v39/dump.cs` came from an error-tolerant dumper run against the original obfuscated ELF and remains partial. Use the new outputs for further investigation.
