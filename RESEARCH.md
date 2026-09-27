# BanG Dream! Our Notes 1.0.1 reverse engineering notes

This workspace contains static analysis and runtime observations for the supplied `com.bilibili.sirius` Android package. The formats, recovery steps, and code paths here are specific to Our Notes.

For the full evidence trail, see [`docs/FINDINGS.md`](docs/FINDINGS.md). The complete metadata recovery and tool compatibility checks are in [`docs/METADATA_DECRYPTION.md`](docs/METADATA_DECRYPTION.md). The recovered master-data format and dump are described in [`docs/MASTERDATA_DUMP.md`](docs/MASTERDATA_DUMP.md). The live-device signal and traffic observations are in [`docs/RUNTIME_FINDINGS.md`](docs/RUNTIME_FINDINGS.md).

## Package and evidence

- Unity `6000.3.12f1`, arm64 IL2CPP. The supplied APK requires Android API 26 or newer.
- Original `global-metadata.dat`: 31,547,372 bytes; SHA-256 `104f5b604ff64097021ab56a2dd44368bd9de09e5da4e5d8eb1950ef2a75461c`.
- `assets/Master/MasterManifest.json` version `829b4509079c7a43ca9e0df837119a84` lists 240 `.bin` files. Every file is present and matches its declared size and SHA-256; see `analysis/master_verification.json`.
- No original package files were modified.

## Metadata recovery

The metadata has a custom first eight bytes and periodic XOR protection. [`tools/decode_metadata.py`](tools/decode_metadata.py) performs the initial static repair. A native arm64 runtime capture recovered its previously opaque `0x1000..0x5000` span and revealed a missed trailing XOR span at `0x1e15000..EOF`. [`tools/finalize_metadata.py`](tools/finalize_metadata.py) verifies the runtime snapshot and produces the complete parser-ready copy.

Use `analysis/il2cpp/global-metadata-decrypted-v39.dat`, SHA-256 `e51bc47a2fa62666e7c360c27f2999682e4fdd7a9a3064e9d22a50e28686d600`, for analysis. All 33,054 string literals decode, and all 201 image definitions pass structural checks. The first eight bytes use standard magic and an inferred version 39; the saved runtime snapshot supplies every remaining byte. See the [recovery details](docs/METADATA_DECRYPTION.md).

The local `analysis/tooling/Il2CppDumper` is based on [upstream's Unity 6 PR #922](https://github.com/Perfare/Il2CppDumper/pull/922/files) (`unity6`, commit `24d8241`) with two local tolerance changes. Its earlier `analysis/il2cpp/dump-v39/dump.cs`, produced from the protected original ELF, is **partial**. The recovered `analysis/il2cpp/libil2cpp-deobfuscated.so` now works with the complete metadata in both Inspector Redux and Cpp2IL: Inspector exported `analysis/il2cpp/inspector-deobfuscated/cs/il2cpp.cs`, and Cpp2IL produced 201 DLLs (`analysis/il2cpp/cpp2il-deobfuscated`). See the [native recovery](docs/NATIVE_BINARY_DEOBFUSCATION.md) for validation and commands.

## Recovered client surface

[`tools/MetadataExplorer`](tools/MetadataExplorer/Program.cs) reads the final metadata directly. The selected 25 game assemblies contain 14,891 type names and 95,694 method names. The index is in `analysis/metadata-index`: `assemblies.tsv`, `game_types.tsv`, `game_methods.tsv`, and `protobuf_fields.tsv`.

The generated protobuf code reveals 55 gRPC service classes and 259 distinct RPCs. `analysis/grpc_signatures.tsv` pairs each RPC with its request and response class; `analysis/protobuf_field_types.tsv` lists 1,438 field numbers and managed property types. All 1,438 field numbers and all 259 method signatures were checked against independent metadata names or constants by [`tools/extract_proto_signatures.py`](tools/extract_proto_signatures.py). A readable service summary is in `analysis/grpc_catalog.md`.

For 48 services, a full `app.*.*Service` name literal occurs in the final metadata. The catalog's `/service/Rpc` paths are **candidates assembled from those literals and method names**; no live packet capture confirms them. Seven service wire names are unresolved. C# property types do not by themselves distinguish every protobuf wire encoding, oneof rule, or descriptor option, so the TSV is an inspection aid rather than a complete `.proto` schema.

Relevant metadata classes include `Fwk.Server.AuthenticatedCallInvoker`, `Fwk.Server.ServerCommunicationManager`, `Fwk.Master.MasterDataManager`, `Fwk.Crypt.CryptProviderBase`, `Fwk.UnityCipher.RijndaelEncryption`, and `App.Crypto.CryptProvider`. Literal strings include `x-sirius-cred`, `x-player-credential`, `https://api.bang-dream-on.jp`, `https://static.bang-dream-on.jp`, and `https://l14-prod-hk-all-gs-sirius.gamerfusiontech.com`. The network values identify likely capture points and configuration, not a verified active endpoint.

The bundled master data is now dumped: `analysis/masterdata-json.zip` contains 240 JSON tables and a hash/count manifest, with 43,594 total `_allData` records. The decoder derives its key, salt, and IV from repaired metadata, then applies Rijndael-256-CBC, PKCS#7 unpadding, and gzip decompression. All 240 outputs parsed and matched the source manifest. See [`docs/MASTERDATA_DUMP.md`](docs/MASTERDATA_DUMP.md).

## Reproduce the static analysis

From this directory in PowerShell, with Python and the .NET SDK available:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\setup_il2cppdumper.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\run_static_analysis.ps1
```

The script reads the extracted package and saved runtime metadata snapshot, rebuilds the final metadata and service/field catalogs, verifies the master manifest, and reproduces the master-data JSON dump and ZIP. It requires the existing partial `dump.cs` for the C# signature cross-check. It writes only derived files under `analysis/`.

## Runtime status and remaining questions

The game now runs to a Bilibili sign-in dialog on rooted BlueStacks Rvc64. Its x86_64 Frida server cannot see the translated ARM game modules. A local pre-login PCAP confirms Unity and Bilibili SDK TLS hosts and offered ALPN, but no Our Notes gRPC call or backend host. No account was signed in. On the native arm64 Poco F3, the process still exits within seconds with SIGBUS or SIGSEGV. A corrected probe found Unity's signal handler at `libunity.so + 0xa9dbd8`; it was not observed executing before two further SIGBUS exits. Details and evidence links are in the [runtime findings](docs/RUNTIME_FINDINGS.md).

1. Capture an authorized post-login session to verify backend hosts, service paths, request metadata, and response behavior. Passive TLS capture alone does not reveal encrypted gRPC messages.
2. Determine the Poco's actual termination path with validated kernel or ptrace observations. The available evidence does not prove that Tencent ACE or the Play Integrity gate causes its early death.
3. Use the recovered master-data JSON with runtime request captures to determine which data and response fields the client expects.
4. Build protocol tests from captures before implementing server behavior. A working private server cannot be inferred from method names alone.
