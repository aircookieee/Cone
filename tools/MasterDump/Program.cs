using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using Il2CppDumper;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

if (args.Length != 3)
{
    Console.Error.WriteLine("Usage: MasterDump <assets/Master> <repaired-metadata.dat> <output-directory>");
    return 2;
}

var sourceDir = Path.GetFullPath(args[0]);
var metadataPath = Path.GetFullPath(args[1]);
var outputDir = Path.GetFullPath(args[2]);
var manifest = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(sourceDir, "MasterManifest.json")));
var version = manifest.RootElement.GetProperty("version").GetString() ?? "";

using var metadataStream = new MemoryStream(File.ReadAllBytes(metadataPath));
var metadata = new Metadata(metadataStream);
if (metadata.Version != 39 || metadata.imageDefs.Length != 201)
    throw new InvalidDataException("Expected the repaired Our Notes 1.0.1 metadata");

// These <PrivateImplementationDetails> fields are referenced, in order, by
// App.Crypto.CryptProvider::.ctor (metadata method 48670 / native RVA 0x5D4744C).
// Field refs 58, 53, and 50 resolve to definitions 45051, 45046, and 45043.
byte[] ReadStaticArray(int fieldIndex)
{
    if (!metadata.GetFieldDefaultValueFromIndex(fieldIndex, out var value) || value.dataIndex < 0)
        throw new InvalidDataException($"Missing static array field {fieldIndex}");
    metadata.Position = metadata.GetDefaultValueFromIndex(value.dataIndex);
    return metadata.Reader.ReadBytes(32);
}

var salt = ReadStaticArray(45051);
var key = ReadStaticArray(45046);
var iv = ReadStaticArray(45043);
if (salt.Length != 32 || key.Length != 32 || iv.Length != 32)
    throw new InvalidDataException("Invalid embedded cipher constants");

static byte[] Decrypt(byte[] encrypted, byte[] salt, byte[] key, byte[] iv)
{
    if (encrypted.Length < 96 || encrypted.Length % 32 != 0 ||
        !encrypted.AsSpan(0, 32).SequenceEqual(salt) ||
        !encrypted.AsSpan(32, 32).SequenceEqual(iv))
        throw new InvalidDataException("Unexpected master file header or length");

    var engine = new RijndaelEngine(256);
    engine.Init(false, new KeyParameter(key));
    var padded = new byte[encrypted.Length - 64];
    var previous = iv.ToArray();
    var block = new byte[32];
    for (var offset = 64; offset < encrypted.Length; offset += 32)
    {
        engine.ProcessBlock(encrypted, offset, block, 0);
        for (var i = 0; i < 32; i++)
            padded[offset - 64 + i] = (byte)(block[i] ^ previous[i]);
        Array.Copy(encrypted, offset, previous, 0, 32);
    }
    var padding = padded[^1];
    if (padding is <= 0 or > 32 || !padded.AsSpan(padded.Length - padding).ToArray().All(b => b == padding))
        throw new InvalidDataException("Invalid Rijndael CBC padding");
    if (padded[0] != 0x1f || padded[1] != 0x8b)
        throw new InvalidDataException("Decrypted payload is not gzip");
    using var compressed = new MemoryStream(padded, 0, padded.Length - padding);
    using var gzip = new GZipStream(compressed, CompressionMode.Decompress);
    using var clear = new MemoryStream();
    gzip.CopyTo(clear);
    return clear.ToArray();
}

var rows = new List<object>();
var outputs = new List<(string Name, byte[] Data)>();
var totalRecords = 0;
foreach (var item in manifest.RootElement.GetProperty("files").EnumerateArray())
{
    var name = item.GetProperty("name").GetString() ?? throw new InvalidDataException("Missing name");
    if (name != Path.GetFileName(name) || !name.EndsWith(".bin", StringComparison.Ordinal))
        throw new InvalidDataException($"Unexpected manifest path: {name}");
    var encrypted = File.ReadAllBytes(Path.Combine(sourceDir, name));
    var expectedSize = item.GetProperty("size").GetInt64();
    var expectedHash = item.GetProperty("hash").GetString() ?? "";
    var sourceHash = Convert.ToHexString(SHA256.HashData(encrypted)).ToLowerInvariant();
    if (encrypted.Length != expectedSize || sourceHash != expectedHash.ToLowerInvariant())
        throw new InvalidDataException($"Manifest mismatch: {name}");

    byte[] clear;
    try { clear = Decrypt(encrypted, salt, key, iv); }
    catch (Exception ex) { throw new InvalidDataException($"Failed to decrypt {name}: {ex.Message}", ex); }
    using var parsed = JsonDocument.Parse(clear);
    if (parsed.RootElement.ValueKind != JsonValueKind.Object ||
        !parsed.RootElement.TryGetProperty("_allData", out var allData) ||
        allData.ValueKind != JsonValueKind.Array)
        throw new InvalidDataException($"Unexpected JSON structure: {name}");
    var recordCount = allData.GetArrayLength();
    totalRecords += recordCount;
    var outputName = Path.ChangeExtension(name, ".json");
    outputs.Add((outputName, clear));
    rows.Add(new {
        source = name,
        source_sha256 = sourceHash,
        output = outputName,
        output_sha256 = Convert.ToHexString(SHA256.HashData(clear)).ToLowerInvariant(),
        records = recordCount,
        bytes = clear.Length,
    });
}

var extra = Directory.GetFiles(sourceDir, "*.bin").Select(Path.GetFileName)
    .Except(outputs.Select(x => Path.ChangeExtension(x.Name, ".bin")), StringComparer.Ordinal)
    .ToArray();
if (extra.Length != 0)
    throw new InvalidDataException($"Unlisted source .bin files: {string.Join(", ", extra)}");

var report = JsonSerializer.SerializeToUtf8Bytes(new {
    game_version = "1.0.1",
    master_manifest_version = version,
    cipher = "Rijndael-256-CBC / PKCS7; 32-byte salt, 32-byte IV, gzip JSON",
    files = rows,
}, new JsonSerializerOptions { WriteIndented = true });
Directory.CreateDirectory(outputDir);
foreach (var (name, data) in outputs)
{
    var destination = Path.Combine(outputDir, name);
    if (File.Exists(destination) && !File.ReadAllBytes(destination).AsSpan().SequenceEqual(data))
        throw new IOException($"Refusing to overwrite different output: {destination}");
}
var reportPath = Path.Combine(outputDir, "_dump_manifest.json");
if (File.Exists(reportPath) && !File.ReadAllBytes(reportPath).AsSpan().SequenceEqual(report))
    throw new IOException($"Refusing to overwrite different report: {reportPath}");
foreach (var (name, data) in outputs)
    File.WriteAllBytes(Path.Combine(outputDir, name), data);
File.WriteAllBytes(reportPath, report);
Console.WriteLine($"Dumped {outputs.Count} JSON master tables to {outputDir}");
Console.WriteLine($"Total records: {totalRecords}");
Console.WriteLine(reportPath);
return 0;
