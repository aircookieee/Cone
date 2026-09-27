# Master-data dump: Our Notes 1.0.1

The 240 bundled `assets/Master/*.bin` files have been decrypted and exported as JSON in `analysis/masterdata-json`. A single archive is `analysis/masterdata-json.zip`. The archive contains the 240 tables plus `analysis/masterdata-json/_dump_manifest.json`, which lists each source hash, output hash, byte count, and record count.

## Results

| Check | Result |
|---|---:|
| Manifest-listed `.bin` files | 240 |
| Source size/SHA-256 matches | 240/240 |
| Header, decryption, padding, gzip, JSON checks | 240/240 |
| Exported JSON table files | 240 |
| Total `_allData` records | 43,594 |
| JSON bytes (excluding dump manifest) | 12,884,490 |
| Tables with zero records | 54 |
| ZIP members / ZIP size | 241 / 1,237,925 bytes |

The ZIP's SHA-256 is `e7c7fe17d125a8bd31219cb5f52bad2d9f13711b2cd05a6baf8ed8c9d749c969`. The exported table bytes are exactly the decompressed JSON bytes, without reformatting. For example, `analysis/masterdata-json/MasterAdv.json` has 946 records, while `analysis/masterdata-json/MasterSkillLevelResource.json` has 7,201. The empty tables are valid JSON with zero `_allData` records.

## How the format was identified

All 240 source files have a common 64-byte prefix and a length divisible by 32. `App.Crypto.CryptProvider::.ctor` (metadata method index 48670, native RVA `0x5D4744C`) initializes three 32-byte arrays from `<PrivateImplementationDetails>` fields. [`tools/MethodLocator`](../tools/MethodLocator/Program.cs) resolves the constructor and its referenced field handles. The field refs and default-value blobs in the repaired metadata are:

| Constructor value | Field ref | Field definition | Role established by validation |
|---|---:|---:|---|
| `get_Salt` | 58 | 45051 | Matches source bytes `0..31` |
| `get_Key` | 53 | 45046 | Decrypts the content |
| `get_IV` | 50 | 45043 | Matches source bytes `32..63` and is the CBC IV |

The remaining bytes are Rijndael with a 256-bit block and 256-bit key, in CBC mode with PKCS#7 padding. The unpadded plaintext is gzip, and the decompressed bytes are UTF-8 JSON with an `_allData` array. This was established by successful decryption, valid padding, gzip decompression, and JSON parsing across **every** manifest-listed file. The stored `get_Salt` value is verified as a fixed file header; the working decryption path uses the embedded key directly. There is no need to derive a key from that salt for this version.

[`tools/MasterDump`](../tools/MasterDump/Program.cs) reads the three arrays from the repaired metadata, so their values are not hard-coded in the decoder. It uses [Bouncy Castle's Rijndael implementation](https://github.com/bcgit/bc-csharp/blob/master/crypto/src/crypto/engines/RijndaelEngine.cs) through the [BouncyCastle.Cryptography 2.7.0 package](https://www.nuget.org/packages/bouncycastle.cryptography/). Standard AES APIs have a fixed 128-bit block and cannot directly decode this 256-bit block format.

## Reproduce

From the workspace root in PowerShell:

```powershell
dotnet run --project .\tools\MasterDump\MasterDump.csproj -- `
  '.\BanG+Dream!+Our+Notes_1.0.1_APKPure\com.bilibili.sirius\assets\Master' `
  '.\analysis\il2cpp\global-metadata-decrypted-v39.dat' `
  '.\analysis\masterdata-json'
python .\tools\package_masterdata.py .\analysis\masterdata-json .\analysis\masterdata-json.zip
```

The [full static pipeline](../tools/run_static_analysis.ps1) now performs these steps as well. The dump tool verifies each source against `MasterManifest.json`, checks the cipher header and padding, parses every JSON document, and refuses to overwrite a different existing output. The package tool checks output hashes and counts before writing the ZIP. Both read the original package files and write only derived files under `analysis/`.

This decoder is tied to the supplied version 1.0.1 package and decrypted metadata. Another version should be independently validated before reusing its field indices or output.
