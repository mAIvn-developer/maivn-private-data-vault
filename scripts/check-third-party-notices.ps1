$ErrorActionPreference = 'Stop'
$vaultRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$notice = Join-Path $vaultRoot 'crates/private-data-vault-py/THIRD_PARTY_NOTICES'
function Test-RustStandardLibraryMaterials {
    $verbose = & rustc -Vv
    if ($LASTEXITCODE) { throw 'rustc -Vv failed' }
    $release = ($verbose | Where-Object { $_ -match '^release:\s*(.+)$' } | ForEach-Object { $Matches[1].Trim() } | Select-Object -First 1)
    if ($release -ne '1.97.1') { throw "Rust compiler release changed ($release); regenerate and review THIRD_PARTY_NOTICES." }
    $sysroot = (& rustc --print sysroot).Trim()
    if ($LASTEXITCODE -or -not $sysroot) { throw 'rustc --print sysroot failed' }
    $staticFiles = Join-Path $sysroot 'share/doc/rust/html/static.files'
    $apache = @(Get-ChildItem -LiteralPath $staticFiles -Filter 'LICENSE-APACHE-*.txt' -File)
    $mit = @(Get-ChildItem -LiteralPath $staticFiles -Filter 'LICENSE-MIT-*.txt' -File)
    $copyright = Join-Path $sysroot 'share/doc/rust/COPYRIGHT-library.html'
    if ($apache.Count -ne 1 -or $mit.Count -ne 1 -or -not (Test-Path -LiteralPath $copyright)) { throw 'Rust 1.97.1 standard-library license materials are unavailable from the installed toolchain.' }
    $expected = @{ $apache[0].FullName = 'a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2'; $mit[0].FullName = '23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3'; $copyright = '0a65bb747c49c7bb816cbc7188319bd6e4e8d08091c1190b8a3c0971c47968ed' }
    foreach ($path in $expected.Keys) { if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected[$path]) { throw "Rust standard-library material changed: $path" } }
}
$expectedLock = 'b30ee70f528dd35ebf5d70ceb89d8441bec1e6d86a4a64d294eba9705ccab550'
$expectedClosure = 'e722dc370264309d8b220880da9fad4b5896aad5ed58a7b07fe1a72bfc39b983'
if ((Get-FileHash (Join-Path $vaultRoot 'Cargo.lock') -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedLock) { throw 'Cargo.lock changed; regenerate and review THIRD_PARTY_NOTICES.' }
Push-Location $vaultRoot
try {
    Test-RustStandardLibraryMaterials
    $ids = foreach ($target in 'x86_64-unknown-linux-gnu', 'x86_64-pc-windows-msvc') {
        $tree = cargo tree --locked --target $target -e normal -p private-data-vault-py
        if ($LASTEXITCODE) { throw "cargo tree failed for $target" }
        $tree | ForEach-Object { if ($_ -match '(?:├──|└──|│   )\s*([A-Za-z0-9_-]+) v([0-9][^ ]*)') { "$($Matches[1])@$($Matches[2])" } }
    }
} finally { Pop-Location }
$ids = $ids | Sort-Object -Unique
$actualClosure = [System.BitConverter]::ToString(([System.Security.Cryptography.SHA256]::Create()).ComputeHash([System.Text.UTF8Encoding]::new($false).GetBytes((($ids -join "`n") + "`n")))).Replace('-', '').ToLowerInvariant()
if ($actualClosure -ne $expectedClosure) { throw 'Cargo normal dependency closure changed; regenerate and review THIRD_PARTY_NOTICES.' }
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('maivn-vault-notices-' + [guid]::NewGuid() + '.txt')
try {
    & (Join-Path $PSScriptRoot 'generate-third-party-notices.ps1') -OutputPath $temporary
    if ($LASTEXITCODE) { throw 'third-party notice generator failed' }
    if ((Get-FileHash $notice -Algorithm SHA256).Hash -ne (Get-FileHash $temporary -Algorithm SHA256).Hash) { throw 'THIRD_PARTY_NOTICES is stale; regenerate it.' }
} finally { if (Test-Path $temporary) { Remove-Item -LiteralPath $temporary -Force } }
$packageNotice = Join-Path $vaultRoot 'crates/private-data-vault-py/python/private_data_vault/THIRD_PARTY_NOTICES'
if ((Get-FileHash $notice -Algorithm SHA256).Hash -ne (Get-FileHash $packageNotice -Algorithm SHA256).Hash) { throw 'Installed-package THIRD_PARTY_NOTICES differs from the source-distribution copy.' }
$source = Join-Path $vaultRoot 'crates/private-data-vault-py/python/private_data_vault/_third_party/option_ext_0_2_0'
$expected = @{ 'Cargo.toml'='ecd67cb17a0586f1406b7d494ef93191ed8ebf149db46667a7778052d94e1e6c'; 'Cargo.toml.orig'='202b034590ddf9857aaa639982f7fa8d0b2d36abc4e8223b0211bcd104e34180'; 'LICENSE.txt'='66a3107d5ad6a058aab753eaac2047ccb2ed0e39465dd0fe5844da3e300d5172'; 'README.md'='4778f769203e879f816c7b8538f427dd542755fe2efde9ee2193815b199c8648'; 'src/lib.rs'='5a0a1fb2ca896a06bcbc32024c8fe64be682170585be6313ba3ff2a87672d1fc'; 'src/impl.rs'='2f0b6f0421c4d37b1a8f0412cf71e9720cb8c5ddcec61ac802474e40ab8a3f9b' }
foreach ($relative in $expected.Keys) { $path = Join-Path $source $relative; if (-not (Test-Path $path) -or (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected[$relative]) { throw "option-ext source mismatch: $relative" } }
Write-Output 'private-data-vault third-party notices and MPL source payload are current.'
