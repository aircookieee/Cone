# Our Notes 1.0.1: technical findings

This document records the static evidence recovered from the supplied Android package beginning 2026-09-26 and the subsequent native metadata capture. The bundled master records and complete IL2CPP metadata have been decrypted. Later BlueStacks startup traffic is documented in [`RUNTIME_FINDINGS.md`](RUNTIME_FINDINGS.md); no Our Notes gRPC request or validated server response has been captured. [`METADATA_DECRYPTION.md`](METADATA_DECRYPTION.md) details the full recovery and tool compatibility checks; [`RESEARCH.md`](../RESEARCH.md) is the short overview; [`MASTERDATA_DUMP.md`](MASTERDATA_DUMP.md) details the master-data export.

## 1. Inputs and provenance

| Item | Location | Finding |
|---|---|---|
| Distribution | `BanG+Dream!+Our+Notes_1.0.1_APKPure.xapk` | 466,465,506 bytes; supplied with the workspace |
| Base APK | `BanG+Dream!+Our+Notes_1.0.1_APKPure/com.bilibili.sirius.apk` | Package `com.bilibili.sirius`, version code 25, version name 1.0.1; SHA-256 `7fa7b2c1cb55f703cc479c3d09e3aad4e3e40cd852cc90d12c2a7845944ff6e0` |
| ABI split | `BanG+Dream!+Our+Notes_1.0.1_APKPure/config.arm64_v8a.apk` | SHA-256 `5cf430829fe15f2448dbda1c3f9281dc7b0f7bdae61a6e19e04491b7ffafefc0` |
| IL2CPP binary | `BanG+Dream!+Our+Notes_1.0.1_APKPure/config.arm64_v8a/lib/arm64-v8a/libil2cpp.so` | 214,602,464 bytes; SHA-256 `514a5b73d038c264b60cc91fd4a747cf178190c6b2096e6d7007c2020e2b1bca` |
| Metadata | `BanG+Dream!+Our+Notes_1.0.1_APKPure/com.bilibili.sirius/assets/bin/Data/Managed/Metadata/global-metadata.dat` | 31,547,372 bytes; SHA-256 `104f5b604ff64097021ab56a2dd44368bd9de09e5da4e5d8eb1950ef2a75461c` |
| Unity data | `assets/bin/Data/data.unity3d` in the extracted base APK | Unity version string `6000.3.12f1` |
| Master manifest | `assets/Master/MasterManifest.json` in the extracted base APK | Version `829b4509079c7a43ca9e0df837119a84` |

`aapt dump badging` reports minimum Android SDK 26 and target SDK 36. These identifiers are package metadata, not a statement that a particular runtime environment has been validated.

The methods and findings below apply to this specific Our Notes package build.

## 2. Metadata protection and repair

### Observations

The file begins with `94 43 72 12 18 4b 9e ec`, not IL2CPP's standard magic and version. The original bytes at file positions `0x8..0xfff` produce a coherent Unity 6 metadata header after XOR with `0x66`. Its first section tuple becomes `(offset=0x17c, size=0x2047c, count=33055)`, and `size == count * 4`, as expected for string-literal offsets. The image-definition section at header entry 20 becomes `(offset=0x1ac0e2c, size=0x1c44, count=201)`, with 201 structurally valid image records. The repaired first eight bytes are synthesized as standard IL2CPP magic `AF 1B B1 FA` and version 39 (`27 00 00 00`); version 39 is an inferred parser version, not a value recovered from the custom marker.

The XOR behavior is aligned to absolute file offsets, not metadata sections:

```text
0x000008 .. 0x000fff              XOR 0x66
0x001000 .. 0x004fff              ciphered span, recovered from native runtime
0x011000 .. 0x014fff              XOR 0x66
0x021000 .. 0x024fff              XOR 0x66
... each later 0x10000-byte window
0x1e15000 .. 0x1e15feb            trailing partial XOR 0x66 window
```

[`tools/decode_metadata.py`](../tools/decode_metadata.py) implements the initial repair on a copy. The resulting `analysis/il2cpp/global-metadata-repaired-v39.dat` has SHA-256 `6c057cfc65307445b606eecfcf9a579c2dd91696193855052aae2806dd5b74fd`. A later native arm64 runtime snapshot recovered the first ciphered span and identified the trailing XOR span. [`tools/finalize_metadata.py`](../tools/finalize_metadata.py) verifies those bytes against the snapshot and writes the complete `analysis/il2cpp/global-metadata-decrypted-v39.dat`, SHA-256 `e51bc47a2fa62666e7c360c27f2999682e4fdd7a9a3064e9d22a50e28686d600`. See [`METADATA_DECRYPTION.md`](METADATA_DECRYPTION.md) for provenance and exact checks.

[`tools/extract_literals.py`](../tools/extract_literals.py) now recovers all 33,054 readable literals into `analysis/il2cpp/string_literals.jsonl`, with zero skipped. Its “long base64 candidate” heuristic found none. Seven gRPC service names still have no matching full wire-name literal in the complete metadata.

### Parser and native dump

The stock installed `Il2CppDumper` did not handle this Unity 6 metadata layout. A local clone of [Il2CppDumper's Unity 6 PR #922](https://github.com/Perfare/Il2CppDumper/pull/922/files) is at `analysis/tooling/Il2CppDumper`, branch `unity6`, commit `24d8241`. Two local checks skip out-of-range RGCTX ranges and generic method table indices, and its config disables dummy DLL/struct generation and the keypress prompt. The clone is a nested Git repository; the parent workspace is not a Git repository.

The patched dumper reports metadata version 39 and registration locations `CodeRegistration: bdf4fa0`, `MetadataRegistration: c315bd8`. It also reports `ERROR: This file may be protected` and repeated `ERROR: Some errors in dumping`. Its `analysis/il2cpp/dump-v39/dump.cs` is about 34 MB and omits many expected classes. Treat RVAs, field offsets, and absent declarations from that **partial** run as unverified. The registration addresses were later corroborated by both analyzers on the repaired binary. See `analysis/il2cpp/dumper-run.log`. The error-tolerant run was useful for generated protobuf declarations, which were independently checked below; it is not complete native decompilation.

The original ELF's periodic XOR protection causes Cpp2IL's impossible pointer count `0x67676768`. The repaired `analysis/il2cpp/libil2cpp-deobfuscated.so`, SHA-256 `f99e3d1537d5515d6bdd7f47ba429484208f14c6be404d79eefd3f8963a44b55`, now works with the complete metadata. Cpp2IL generated 201 DLLs (`analysis/il2cpp/cpp2il-deobfuscated`); Inspector Redux exported `analysis/il2cpp/inspector-deobfuscated/cs/il2cpp.cs`. See [`NATIVE_BINARY_DEOBFUSCATION.md`](NATIVE_BINARY_DEOBFUSCATION.md) for the exact repair and limits.

## 3. Direct metadata index

[`tools/MetadataExplorer/Program.cs`](../tools/MetadataExplorer/Program.cs) loads the final decrypted file with the Unity 6 metadata parser and indexes managed definitions without depending on native method pointers. It found 201 total images. The 25 selected game assemblies (including `App.*`, `Fwk`, and named game modules) contain 14,891 type names and 95,694 method names. No selected type or method range was skipped. These are symbolic names, not method bodies or verified runtime addresses.

The output directory `analysis/metadata-index` contains:

| File | Rows | Use |
|---|---:|---|
| `assemblies.tsv` | 201 | All image names and type ranges |
| `game_types.tsv` | 14,891 | Namespace, type, type index, method count |
| `game_methods.tsv` | 95,694 | Method names and metadata indices |
| `protobuf_fields.tsv` | 1,438 | Generated `*FieldNumber` constants read from metadata default-value blobs |

Field constants use the parser's compressed signed integer format. Every exported protobuf field number was later compared to the same declaration in the partial C# dump; all 1,438 agreed. This validates those generated declarations without validating arbitrary parts of `dump.cs`.

## 4. Network and protocol surface

`App.Protobuf.dll` contains 55 generated gRPC service classes and 259 distinct server-base RPC method names. [`tools/extract_grpc_catalog.py`](../tools/extract_grpc_catalog.py) writes the overview `analysis/grpc_catalog.md` and the symbolic `analysis/grpc_routes.tsv`. Of the 55 services, 48 have a matching full `app.*.*Service` literal in the recovered string data. Seven lack that literal in the current recovery: `CarouselHelpService`, `ContentUnlockService`, `ExternalPaymentsService`, `FeatureSwitchService`, `PersonalNotificationService`, `SerialCodeService`, and `SupportsTermsService`.

[`tools/extract_proto_signatures.py`](../tools/extract_proto_signatures.py) reads generated C# declarations from the partial dump and cross-checks them against metadata. It emits:

- `analysis/grpc_signatures.tsv`: all 259 RPCs, with request class, response class, managed namespace, wire-service literal when known, and a constructed candidate path.
- `analysis/protobuf_field_types.tsv`: all 1,438 generated fields, with field number and C# property type. Repeated and map types remain written as `RepeatedField<T>` and `MapField<K,V>`.

For example, the generated declaration connects `PlayerLoginService.PlayerLogin` to `PlayerLoginRequest` and `PlayerLoginResponse`; the recovered literal is `app.playerlogin.PlayerLoginService`, so `/app.playerlogin.PlayerLoginService/PlayerLogin` is a **candidate** path. `PlayerLoginRequest` has 13 numbered properties, including `SdkUid=1`, `SdkAccessToken=2`, `Platform=3`, and `IdToken=13`. The C# property `uint Platform` does not alone prove whether the `.proto` field was `uint32` or a fixed-width or enum encoding. Message nesting, descriptor options, oneofs, and exact wire tags still require descriptors, generated serialization analysis, or a packet capture.

The direct index also identifies `Fwk.Server.AuthenticatedCallInvoker` (`AsyncUnaryCall`, `BlockingUnaryCall`, streaming call methods, player/device setters), and `Fwk.Server.ServerCommunicationManager` (`Setup`, request queue, retry, response notification, error handling). These are the most specific **candidate** observation points for runtime protocol tracing; their arguments and call graph are not yet confirmed.

Readable literals include `x-player-credential`, `x-sirius-cred`, `x-client-version`, `x-master-version`, `x-asset-version`, and `x-resource-version`, along with `https://api.bang-dream-on.jp`, `https://static.bang-dream-on.jp`, and `https://l14-prod-hk-all-gs-sirius.gamerfusiontech.com`. Their presence establishes only that the strings are in the client. Which host and headers are used for each live request remains unknown. Avoid constructing a server implementation from these names alone.

## 5. Bundled master data and recovered format

[`tools/verify_master_manifest.py`](../tools/verify_master_manifest.py) checked all 240 embedded `.bin` files against the manifest's sizes and SHA-256 hashes: 240 present, 0 mismatches, 0 extra `.bin` files, total 1,262,336 bytes. Every length is divisible by 32. The result is `analysis/master_verification.json`.

`App.Crypto.CryptProvider::.ctor` initializes three 32-byte arrays from `<PrivateImplementationDetails>` fields in the repaired metadata. The first and third arrays match the common 64-byte prefix of every file; the second decrypts the remaining bytes with Rijndael-256-CBC. Every file has valid PKCS#7 padding, a gzip payload, and JSON with an `_allData` array. [`tools/MasterDump`](../tools/MasterDump/Program.cs) recovered 240 JSON tables with 43,594 total records into `analysis/masterdata-json`, and `analysis/masterdata-json.zip` packages them. Independent output hash/count checks passed. See [`MASTERDATA_DUMP.md`](MASTERDATA_DUMP.md) for the exact field refs, command, and validation.

## 6. Verification and limitations

`powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\run_static_analysis.ps1` was run successfully with the saved runtime snapshot. It reproduced the final decrypted metadata hash, all 33,054 literals, 201 parsed images, 14,891 selected game types, 95,694 methods, 1,438 field numbers, 55 services, 259 signatures, 240/240 manifest verification, and 240 valid master-data JSON exports. The C# to metadata cross-check failed on zero records.

At the time of this static snapshot, there had been no successful runtime session. Subsequent work booted the game to the sign-in dialog on BlueStacks Rvc64, where a TLS endpoint capture succeeded. The native arm64 Poco F3 still exits within seconds. See [`RUNTIME_FINDINGS.md`](RUNTIME_FINDINGS.md) for current observations and corrected signal analysis. No account sign-in or validated backend response is in the workspace.

The remaining decisions depend on runtime evidence: actual startup hosts, TLS/grpc behavior, headers, authentication sequencing, possible application payload transforms, and the minimum set of responses needed for a working server.
