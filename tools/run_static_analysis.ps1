# Reproduce the non-destructive Our Notes 1.0.1 static analysis.
# Inputs are the extracted XAPK assets, captured metadata snapshot, and partial C# dump.
# All generated files remain under analysis/.
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

$package = 'BanG+Dream!+Our+Notes_1.0.1_APKPure'
$sourceMetadata = Join-Path $package 'com.bilibili.sirius/assets/bin/Data/Managed/Metadata/global-metadata.dat'
$master = Join-Path $package 'com.bilibili.sirius/assets/Master'
$repaired = 'analysis/il2cpp/global-metadata-repaired-v39.dat'
$runtime = 'analysis/il2cpp/global-metadata-runtime-raw.dat'
$metadata = 'analysis/il2cpp/global-metadata-decrypted-v39.dat'
$index = 'analysis/metadata-index'
$dump = 'analysis/il2cpp/dump-v39/dump.cs'
$json = 'analysis/masterdata-json'
$zip = 'analysis/masterdata-json.zip'

function Assert-Hash([string]$Path, [string]$Expected) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing input or output: $Path"
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected) {
        throw "SHA-256 mismatch for $Path`: expected $Expected, got $actual"
    }
}

function Assert-Exit([string]$Step) {
    if ($LASTEXITCODE -ne 0) { throw "$Step failed with exit code $LASTEXITCODE" }
}

Assert-Hash $sourceMetadata '104f5b604ff64097021ab56a2dd44368bd9de09e5da4e5d8eb1950ef2a75461c'
if (-not (Test-Path -LiteralPath 'analysis/tooling/Il2CppDumper/Il2CppDumper/Il2CppDumper.csproj' -PathType Leaf)) {
    throw 'Missing pinned Il2CppDumper parser. Run tools/setup_il2cppdumper.ps1 first.'
}
if (-not (Test-Path -LiteralPath $dump -PathType Leaf)) { throw "Missing input: $dump" }

python .\tools\decode_metadata.py $sourceMetadata $repaired
Assert-Exit 'metadata repair'
Assert-Hash $repaired '6c057cfc65307445b606eecfcf9a579c2dd91696193855052aae2806dd5b74fd'
Assert-Hash $runtime '91aa665bd138276af998b9090f9395ada45ed78bbbc1e51cbb13ed2e61e9ef59'
python .\tools\finalize_metadata.py $repaired $runtime $metadata
Assert-Exit 'metadata finalization'
Assert-Hash $metadata 'e51bc47a2fa62666e7c360c27f2999682e4fdd7a9a3064e9d22a50e28686d600'

python .\tools\extract_literals.py $metadata analysis/il2cpp/string_literals.jsonl
Assert-Exit 'literal extraction'
$literalCount = (Get-Content -LiteralPath 'analysis/il2cpp/string_literals.jsonl' | Measure-Object -Line).Lines
if ($literalCount -ne 33054) { throw "Expected 33054 decoded string literals, got $literalCount" }
dotnet run --project .\tools\MetadataExplorer\MetadataExplorer.csproj -- $metadata $index
Assert-Exit 'metadata index'
python .\tools\extract_grpc_catalog.py $index analysis --metadata $metadata
Assert-Exit 'gRPC catalog'
python .\tools\extract_proto_signatures.py $dump $index analysis/grpc_routes.tsv analysis
Assert-Exit 'protobuf signatures'
python .\tools\verify_master_manifest.py $master --json-output analysis/master_verification.json
Assert-Exit 'master manifest verification'
dotnet run --project .\tools\MasterDump\MasterDump.csproj -- $master $metadata $json
Assert-Exit 'master-data dump'
python .\tools\package_masterdata.py $json $zip
Assert-Exit 'master-data ZIP'

$assemblies = @(Import-Csv -LiteralPath (Join-Path $index 'assemblies.tsv') -Delimiter "`t")
$types = @(Import-Csv -LiteralPath (Join-Path $index 'game_types.tsv') -Delimiter "`t")
$methods = @(Import-Csv -LiteralPath (Join-Path $index 'game_methods.tsv') -Delimiter "`t")
$fields = @(Import-Csv -LiteralPath (Join-Path $index 'protobuf_fields.tsv') -Delimiter "`t")
$routes = @(Import-Csv -LiteralPath 'analysis/grpc_routes.tsv' -Delimiter "`t")
$signatures = @(Import-Csv -LiteralPath 'analysis/grpc_signatures.tsv' -Delimiter "`t")
$masterReport = Get-Content -LiteralPath (Join-Path $json '_dump_manifest.json') -Raw | ConvertFrom-Json
$verification = Get-Content -LiteralPath 'analysis/master_verification.json' -Raw | ConvertFrom-Json
$serviceCount = @($routes.service | Sort-Object -Unique).Count
$recordCount = ($masterReport.files | Measure-Object -Property records -Sum).Sum

if ($assemblies.Count -ne 201 -or $types.Count -ne 14891 -or
    $methods.Count -ne 95694 -or $fields.Count -ne 1438 -or
    $serviceCount -ne 55 -or $routes.Count -ne 259 -or
    $signatures.Count -ne 259 -or $masterReport.files.Count -ne 240 -or
    $recordCount -ne 43594 -or $verification.issues.Count -ne 0 -or
    $verification.extra_bins.Count -ne 0) {
    throw "Unexpected analysis counts: images=$($assemblies.Count), types=$($types.Count), methods=$($methods.Count), fields=$($fields.Count), services=$serviceCount, RPCs=$($routes.Count), signatures=$($signatures.Count), master tables=$($masterReport.files.Count), records=$recordCount"
}
Assert-Hash $zip 'e7c7fe17d125a8bd31219cb5f52bad2d9f13711b2cd05a6baf8ed8c9d749c969'
Write-Host "Static analysis verified: 201 images, 14891 types, 95694 methods, 55 services, 259 RPCs, 1438 fields, 240 master tables, 43594 records."
