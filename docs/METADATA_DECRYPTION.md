# Complete IL2CPP metadata recovery for Our Notes 1.0.1

The parser-ready metadata is `analysis/il2cpp/global-metadata-decrypted-v39.dat` (31,547,372 bytes, SHA-256 `e51bc47a2fa62666e7c360c27f2999682e4fdd7a9a3064e9d22a50e28686d600`). For Inspector and Cpp2IL, pair it with `analysis/il2cpp/libil2cpp-deobfuscated.so`. The original package files remain unchanged.

## Recovery and provenance

The original metadata SHA-256 is `104f5b604ff64097021ab56a2dd44368bd9de09e5da4e5d8eb1950ef2a75461c`. The earlier static repair ([`decode_metadata.py`](../tools/decode_metadata.py)) recovered the header and periodic XOR windows but left `0x1000..0x5000` opaque. It also missed a trailing partial XOR window.

On the native arm64 Poco F3, [`frida_metadata_trace.py`](../tools/frida/frida_metadata_trace.py) observed the game open `global-metadata.dat`, then found its 31,547,372-byte in-memory image using 16 known bytes at file offset `0x5000`. The complete in-memory snapshot is `analysis/il2cpp/global-metadata-runtime-raw.dat`, SHA-256 `91aa665bd138276af998b9090f9395ada45ed78bbbc1e51cbb13ed2e61e9ef59`. This is game-processed metadata, captured before the game's later crash. No APK or on-device installation was patched.

Comparing the runtime image with the earlier repair found differences only at:

| File offsets | Meaning |
|---|---|
| `0x0..0x8` | Runtime header state (`00 00 00 00 18 00 00 00`); replaced with standard IL2CPP magic and candidate version 39 |
| `0x1000..0x5000` | Previously opaque 16 KB string-literal offset table, now recovered from memory |
| `0x1e15000..0x1e15fec` | Last 4,076 bytes still XORed with `0x66` in the earlier repair; decoded in memory |

[`finalize_metadata.py`](../tools/finalize_metadata.py) verifies hashes, checks every other byte against the partial repair, validates the tail XOR relation and literal offsets, and writes the parser-ready copy. The first eight output bytes are synthesized as `AF 1B B1 FA 27 00 00 00`; version 39 is inferred from the Unity 6 layout and parser behavior, not recovered from the package's custom marker. The 16 KB window's cipher and key have not been reconstructed for offline decryption; the recovered runtime bytes are saved and hash-checked so the final file is reproducible without relaunching the game.

## Validation

- All 33,055 string-literal offsets are in bounds and nondecreasing; all 33,054 literal payloads decode as UTF-8, with zero skipped or corrupt entries. The prior partial repair skipped 4,097.
- The local Unity 6 metadata parser loads version 39, 201 images, 14,891 selected game types, 95,694 selected methods, and 1,438 protobuf field numbers; it skips no selected type or method ranges.
- [`run_static_analysis.ps1`](../tools/run_static_analysis.ps1) reproduces the final hash and all downstream checks, including 55 gRPC services, 259 RPCs, 240 master-data tables, and 43,594 records.

Reproduce the final metadata from the saved snapshot:

```powershell
python .\tools\decode_metadata.py '.\BanG+Dream!+Our+Notes_1.0.1_APKPure\com.bilibili.sirius\assets\bin\Data\Managed\Metadata\global-metadata.dat' '.\analysis\il2cpp\global-metadata-repaired-v39.dat'
python .\tools\finalize_metadata.py '.\analysis\il2cpp\global-metadata-repaired-v39.dat' '.\analysis\il2cpp\global-metadata-runtime-raw.dat' '.\analysis\il2cpp\global-metadata-decrypted-v39.dat'
```

## Inspector and Cpp2IL status

The original ELF's generic method table has periodic XOR protection. It caused Cpp2IL's impossible `0x67676768` pointer count and Inspector's earlier generic failure; the original-input transcripts are `analysis/il2cpp/cpp2il-decrypted.log` and `analysis/il2cpp/inspector-decrypted.log`. The [native binary recovery](NATIVE_BINARY_DEOBFUSCATION.md) explains the masking pattern, runtime validation, and reproducible repair.

With `analysis/il2cpp/libil2cpp-deobfuscated.so`, both analyzers complete. Cpp2IL generated 201 DLLs (`analysis/il2cpp/cpp2il-deobfuscated`), and Inspector exported `analysis/il2cpp/inspector-deobfuscated/cs/il2cpp.cs`. Their final logs are `analysis/il2cpp/cpp2il-deobfuscated.log` and `analysis/il2cpp/inspector-deobfuscated.log`. The earlier `analysis/il2cpp/dump-v39/dump.cs` remains a partial result from the obfuscated input.

The direct metadata index and string literals are usable independently of the native analyzers. The seven unresolved full gRPC service-name literals remain absent after complete string-literal recovery, so they were not merely lost to the opaque index window.
