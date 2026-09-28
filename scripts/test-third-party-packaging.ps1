$ErrorActionPreference = 'Stop'
$vaultRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$systemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$stagingName = 'maivn-vault-packaging-' + [guid]::NewGuid()
$staging = Join-Path $systemTemp $stagingName
$fixture = Join-Path $staging 'vault'
$output = Join-Path $staging 'dist'
robocopy $vaultRoot $fixture /E /XD .git target .venv .uv-cache .pytest_cache .ruff_cache /XF private_data_vault.pyd .git .env .env.* /NFL /NDL /NJH /NJS /NC /NS
if ($LASTEXITCODE -gt 7) { throw 'Could not prepare clean vault packaging fixture.' }
try {
    Push-Location $fixture
    try {
        maturin build --locked --manifest-path crates/private-data-vault-py/Cargo.toml --out $output --interpreter python
        if ($LASTEXITCODE) { throw 'maturin wheel build failed' }
        maturin sdist --manifest-path crates/private-data-vault-py/Cargo.toml --out $output
        if ($LASTEXITCODE) { throw 'maturin sdist build failed' }
    } finally { Pop-Location }
    $wheel = Get-ChildItem $output -Filter '*.whl' | Select-Object -First 1
    $sdist = Get-ChildItem $output -Filter '*.tar.gz' | Select-Object -First 1
    if (-not $wheel -or -not $sdist) { throw 'Expected wheel and sdist were not produced.' }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($wheel.FullName)
    try {
        $requiredWheel = @('private_data_vault/THIRD_PARTY_NOTICES','private_data_vault/_third_party/option_ext_0_2_0/LICENSE.txt','private_data_vault/_third_party/option_ext_0_2_0/src/lib.rs','private_data_vault/_third_party/option_ext_0_2_0/src/impl.rs')
        foreach ($name in $requiredWheel) { if (-not ($zip.Entries.FullName -contains $name)) { throw "Wheel missing $name" } }
        $expected = @{ 'private_data_vault/THIRD_PARTY_NOTICES'='470946e6be358a7a25acf813b985d342558dff680b9c984d7a10aae969949c31'; 'private_data_vault/_third_party/option_ext_0_2_0/Cargo.toml'='ecd67cb17a0586f1406b7d494ef93191ed8ebf149db46667a7778052d94e1e6c'; 'private_data_vault/_third_party/option_ext_0_2_0/Cargo.toml.orig'='202b034590ddf9857aaa639982f7fa8d0b2d36abc4e8223b0211bcd104e34180'; 'private_data_vault/_third_party/option_ext_0_2_0/LICENSE.txt'='66a3107d5ad6a058aab753eaac2047ccb2ed0e39465dd0fe5844da3e300d5172'; 'private_data_vault/_third_party/option_ext_0_2_0/README.md'='4778f769203e879f816c7b8538f427dd542755fe2efde9ee2193815b199c8648'; 'private_data_vault/_third_party/option_ext_0_2_0/src/lib.rs'='5a0a1fb2ca896a06bcbc32024c8fe64be682170585be6313ba3ff2a87672d1fc'; 'private_data_vault/_third_party/option_ext_0_2_0/src/impl.rs'='2f0b6f0421c4d37b1a8f0412cf71e9720cb8c5ddcec61ac802474e40ab8a3f9b' }
        foreach ($name in $expected.Keys) { $stream = ($zip.Entries | Where-Object FullName -eq $name).Open(); try { $hash = [System.BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($stream)).Replace('-', '').ToLowerInvariant() } finally { $stream.Dispose() }; if ($hash -ne $expected[$name]) { throw "Wheel source hash mismatch: $name" } }
    } finally { $zip.Dispose() }
    $names = @(tar -tf $sdist.FullName)
    foreach ($suffix in 'crates/private-data-vault-py/THIRD_PARTY_NOTICES','python/private_data_vault/THIRD_PARTY_NOTICES','python/private_data_vault/_third_party/option_ext_0_2_0/src/lib.rs','python/private_data_vault/_third_party/option_ext_0_2_0/src/impl.rs') { if (-not ($names | Where-Object { $_ -like "*/$suffix" })) { throw "sdist missing $suffix" } }
    $extracted = Join-Path $staging 'sdist'
    New-Item -ItemType Directory -Path $extracted | Out-Null
    tar -xf $sdist.FullName -C $extracted
    if ($LASTEXITCODE) { throw 'Could not extract the sdist for hash verification.' }
    $sdistRoot = Get-ChildItem -LiteralPath $extracted -Directory | Select-Object -First 1
    if (-not $sdistRoot) { throw 'sdist extraction did not produce a package root.' }
    $sdistExpected = @{
        'crates/private-data-vault-py/THIRD_PARTY_NOTICES' = '470946e6be358a7a25acf813b985d342558dff680b9c984d7a10aae969949c31'
        'python/private_data_vault/THIRD_PARTY_NOTICES' = '470946e6be358a7a25acf813b985d342558dff680b9c984d7a10aae969949c31'
        'python/private_data_vault/_third_party/option_ext_0_2_0/Cargo.toml' = 'ecd67cb17a0586f1406b7d494ef93191ed8ebf149db46667a7778052d94e1e6c'
        'python/private_data_vault/_third_party/option_ext_0_2_0/Cargo.toml.orig' = '202b034590ddf9857aaa639982f7fa8d0b2d36abc4e8223b0211bcd104e34180'
        'python/private_data_vault/_third_party/option_ext_0_2_0/LICENSE.txt' = '66a3107d5ad6a058aab753eaac2047ccb2ed0e39465dd0fe5844da3e300d5172'
        'python/private_data_vault/_third_party/option_ext_0_2_0/README.md' = '4778f769203e879f816c7b8538f427dd542755fe2efde9ee2193815b199c8648'
        'python/private_data_vault/_third_party/option_ext_0_2_0/src/lib.rs' = '5a0a1fb2ca896a06bcbc32024c8fe64be682170585be6313ba3ff2a87672d1fc'
        'python/private_data_vault/_third_party/option_ext_0_2_0/src/impl.rs' = '2f0b6f0421c4d37b1a8f0412cf71e9720cb8c5ddcec61ac802474e40ab8a3f9b'
    }
    foreach ($relative in $sdistExpected.Keys) { $path = Join-Path $sdistRoot.FullName $relative; if (-not (Test-Path $path) -or (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $sdistExpected[$relative]) { throw "sdist hash mismatch: $relative" } }
    if (-not ((Get-Content (Join-Path $fixture 'crates/private-data-vault-py/NOTICE') -Raw) -match 'licensing revision: 1\.1')) { throw 'NOTICE revision 1.1 is missing.' }
    Write-Output 'wheel and sdist include third-party notices and exact option-ext MPL source.'
} finally {
    if (Test-Path $staging) {
        $resolvedStaging = (Resolve-Path -LiteralPath $staging).Path
        $tempPrefix = $systemTemp.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedStaging.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolvedStaging -Leaf) -ne $stagingName) { throw 'Refusing to remove a temporary packaging path outside its validated system-temp child.' }
        Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
    }
}
