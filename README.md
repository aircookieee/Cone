# Our Notes 1.0.1 research tools

Tools and research notes for the Android arm64 IL2CPP build of **BanG Dream! Our Notes 1.0.1**. The investigation recovered parser-ready metadata, a tool-compatible native ELF, and the bundled master-data format. [RESEARCH.md](RESEARCH.md) summarizes the findings; [docs/FINDINGS.md](docs/FINDINGS.md) records the evidence and limits.

## Repository contents

- `tools/`: metadata and native repair scripts, master-data verification and extraction, metadata indexing, and Frida probes.
- `patches/`: the small local changes to a pinned [Il2CppDumper Unity 6 revision](https://github.com/Perfare/Il2CppDumper/pull/922).
- `docs/`: recovery procedures, validation, and runtime observations.

The complete decrypted metadata and repaired arm64 ELF are kept locally under `analysis/il2cpp/`, outside Git. [Download-link placeholders and SHA-256 hashes](docs/METADATA_DECRYPTION.md#artifact-downloads) are in the metadata recovery notes. The original XAPK/APK, extracted assets, other generated output, device captures, and logs remain local and ignored. Paths to `analysis/` artifacts in the research notes resolve after the corresponding analysis has been run locally. No account credentials are included.

## Reproduce locally

Place the downloaded artifacts under `analysis/il2cpp/`, or use your own copy of the 1.0.1 package for regeneration. The scripts expect its extracted files under `BanG+Dream!+Our+Notes_1.0.1_APKPure/`. Python 3, PowerShell, Git, and the .NET 8 SDK are needed for the static pipeline. The live capture scripts additionally need an arm64 Android device, ADB, and matching Frida host/server versions.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\setup_il2cppdumper.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\run_static_analysis.ps1
```

The static regeneration pipeline also requires the saved in-memory metadata snapshot at `analysis/il2cpp/global-metadata-runtime-raw.dat` and the earlier partial `analysis/il2cpp/dump-v39/dump.cs` used for signature cross-checking. Their provenance is in [docs/METADATA_DECRYPTION.md](docs/METADATA_DECRYPTION.md). A fresh runtime capture can be made with [tools/frida/frida_metadata_trace.py](tools/frida/frida_metadata_trace.py) on a compatible native device. The scripts verify known input and output hashes and fail when the expected build is absent.

The two recovered files form the tested Cpp2IL and Il2CppInspectorRedux input pair. [docs/NATIVE_BINARY_DEOBFUSCATION.md](docs/NATIVE_BINARY_DEOBFUSCATION.md) documents their recovery, analyzer commands, and observed output limits. Regenerating the ELF from the original package requires two saved 16 KB runtime spans, which remain local.

## Scope

The DLLs produced by the tested `dll_empty` Cpp2IL mode contain declarations with empty method bodies. The documented service routes are candidates from recovered names; no authenticated backend exchange was captured. The original package and device captures remain outside the Git history.
