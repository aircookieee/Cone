# Fetch the pinned Unity 6 parser used by the local .NET tools.
# Its checkout stays under ignored analysis/tooling/; this repository stores only our patch.
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$target = Join-Path $root 'analysis/tooling/Il2CppDumper'
$patch = Join-Path $root 'patches/il2cppdumper-unity6-local.patch'
$commit = '24d8241b76ae79bbca92abc64aca00f66b3f11ce'

if (-not (Test-Path -LiteralPath $patch -PathType Leaf)) { throw "Missing patch: $patch" }
if (-not (Test-Path -LiteralPath (Join-Path $target '.git'))) {
    if (Test-Path -LiteralPath $target) { throw "Existing directory is not a Git checkout: $target" }
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    & git clone https://github.com/Perfare/Il2CppDumper.git $target
    if ($LASTEXITCODE -ne 0) { throw 'Il2CppDumper clone failed' }
    & git -C $target fetch origin refs/pull/922/head
    if ($LASTEXITCODE -ne 0) { throw 'Unity 6 PR fetch failed' }
    & git -C $target checkout --detach $commit
    if ($LASTEXITCODE -ne 0) { throw 'Pinned Unity 6 checkout failed' }
}

$actual = (& git -C $target rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actual -ne $commit) {
    throw "Il2CppDumper checkout must be at $commit; found $actual"
}

& git -C $target apply --reverse --check $patch 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host 'Pinned Il2CppDumper checkout and local patch already present.'
    exit 0
}
& git -C $target apply --check $patch
if ($LASTEXITCODE -ne 0) { throw 'Local patch does not apply cleanly; checkout was not changed' }
& git -C $target apply $patch
if ($LASTEXITCODE -ne 0) { throw 'Local patch failed' }
Write-Host 'Pinned Il2CppDumper checkout and local patch ready.'
