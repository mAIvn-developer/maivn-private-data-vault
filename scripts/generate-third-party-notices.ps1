param([string] $OutputPath = '')

$ErrorActionPreference = 'Stop'
$vaultRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $OutputPath) { $OutputPath = Join-Path $vaultRoot 'crates/private-data-vault-py/THIRD_PARTY_NOTICES' }
function Get-RustStandardLibraryMaterials {
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
    [pscustomobject]@{ Release = $release; Apache = $apache[0].FullName; Mit = $mit[0].FullName; Copyright = $copyright }
}
Push-Location $vaultRoot
try {
    $metadataJson = cargo metadata --format-version 1 --locked
    if ($LASTEXITCODE) { throw 'cargo metadata failed' }
    $metadata = $metadataJson | ConvertFrom-Json
    $ids = foreach ($target in 'x86_64-unknown-linux-gnu', 'x86_64-pc-windows-msvc') {
        $tree = cargo tree --locked --target $target -e normal -p private-data-vault-py
        if ($LASTEXITCODE) { throw "cargo tree failed for $target" }
        $tree | ForEach-Object {
            if ($_ -match '(?:├──|└──|│   )\s*([A-Za-z0-9_-]+) v([0-9][^ ]*)') { "$($Matches[1])@$($Matches[2])" }
        }
    }
    $ids = $ids | Sort-Object -Unique
    $lockHash = (Get-FileHash Cargo.lock -Algorithm SHA256).Hash.ToLowerInvariant()
    $textHash = [System.BitConverter]::ToString(([System.Security.Cryptography.SHA256]::Create()).ComputeHash([System.Text.UTF8Encoding]::new($false).GetBytes((($ids -join "`n") + "`n")))).Replace('-', '').ToLowerInvariant()
    $out = [System.Text.StringBuilder]::new()
    [void]$out.AppendLine('THIRD-PARTY NOTICES FOR PRIVATE-DATA-VAULT')
    [void]$out.AppendLine('')
    [void]$out.AppendLine('Applies to the private-data-vault Python wheel and source distribution.')
    [void]$out.AppendLine("Cargo.lock SHA-256: $lockHash")
    [void]$out.AppendLine("Normal dependency closure SHA-256: $textHash ($($ids.Count) crates; Linux + Windows union)")
    [void]$out.AppendLine('Build-only dependencies are excluded. License and notice files are copied verbatim from the resolved crates.io cache.')
    [void]$out.AppendLine('')
    foreach ($id in $ids) {
        $name, $version = $id.Split('@', 2)
        $package = $metadata.packages | Where-Object { $_.name -eq $name -and $_.version -eq $version } | Select-Object -First 1
        if (-not $package) { throw "Cargo metadata missing $id" }
        $files = Get-ChildItem -LiteralPath (Split-Path -Parent $package.manifest_path) -Force -File | Where-Object { $_.Name -match '^(LICENSE|COPYING|NOTICE|COPYRIGHT)([._-]|$)' } | Sort-Object Name
        if (-not $files) { throw "No license material found for $id" }
        [void]$out.AppendLine('================================================================')
        [void]$out.AppendLine("Package: $id")
        [void]$out.AppendLine("SPDX expression: $($package.license)")
        [void]$out.AppendLine("Upstream: $($package.repository)")
        foreach ($file in $files) {
            $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            [void]$out.AppendLine("`n--- $($file.Name) (SHA-256: $hash) ---")
            [void]$out.AppendLine((Get-Content -LiteralPath $file.FullName -Raw).TrimEnd())
        }
        [void]$out.AppendLine('')
    }
    $rust = Get-RustStandardLibraryMaterials
    [void]$out.AppendLine('================================================================')
    [void]$out.AppendLine('Component: Rust standard library and runtime')
    [void]$out.AppendLine("Rust release: $($rust.Release)")
    [void]$out.AppendLine('SPDX expression: MIT OR Apache-2.0')
    [void]$out.AppendLine('Scope: statically linked Rust standard-library/runtime material in the private-data-vault native extension.')
    [void]$out.AppendLine('The release-specific COPYRIGHT-library.html is distributed by the Rust toolchain and describes the standard-library source and its dependencies.')
    foreach ($file in @($rust.Apache, $rust.Mit, $rust.Copyright)) {
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        [void]$out.AppendLine("`n--- $(Split-Path -Leaf $file) (SHA-256: $hash) ---")
        [void]$out.AppendLine((Get-Content -LiteralPath $file -Raw).TrimEnd())
    }
    [void]$out.AppendLine('')
    [IO.File]::WriteAllText($OutputPath, $out.ToString().Replace("`r`n", "`n"), [Text.UTF8Encoding]::new($false))
} finally { Pop-Location }
