[CmdletBinding()]
param([switch]$Live)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path $PSScriptRoot -Parent
$installerPath = Join-Path $repoRoot 'skills/mehscan-security/scripts/install-mehscan.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($installerPath, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Installer syntax errors' }
# Load selected production functions without executing the installer's entry point.
foreach ($name in @('Normalize-VersionTag', 'Invoke-GitHubCli', 'Resolve-InstalledMehscan')) {
    $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    Invoke-Expression $definition.Extent.Text
}
. (Join-Path $repoRoot 'skills/mehscan-security/scripts/public-download.ps1')
$transport = ${function:Invoke-PublicRequest}
$passed = 0
function Assert-Rejected {
    param([string]$Name, [scriptblock]$Action)
    $rejected = $false
    # Expected native failures must not become the exit status of the CI step.
    $previousExitCode = Get-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
    $previousExitValue = if ($null -ne $previousExitCode) { $previousExitCode.Value } else { $null }
    try { & $Action | Out-Null } catch { $rejected = $true } finally {
        if ($null -ne $previousExitCode) {
            $global:LASTEXITCODE = $previousExitValue
        } else {
            Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
        }
    }
    if (-not $rejected) { throw "FAIL: $Name was accepted" }
    $script:passed++
    Write-Output "PASS: $Name rejected"
}
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $temporaryBase "mehscan-installer-tests-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $script:existingPath = Join-Path $testRoot 'mehscan.exe'
    $script:existingVersion = '0.2.0'
    function Get-Command { [pscustomobject]@{ Source = $script:existingPath } }
    function Read-MehscanVersion { $script:existingVersion }
    try {
        foreach ($tag in @('', 'v0.2.0')) {
            if ((Resolve-InstalledMehscan -RequestedTag $tag) -cne $existingPath) { throw 'PATH reuse failed' }
            $passed++
        }
        Assert-Rejected 'PATH version mismatch without installation' { Resolve-InstalledMehscan -RequestedTag 'v9.9.9' }
        Assert-Rejected 'PATH source constraint without installation' { Resolve-InstalledMehscan -RequestedTag 'v0.2.0' -SourceDigest ('a' * 40) }
        $script:existingVersion = $null
        Assert-Rejected 'broken PATH version without installation' { Resolve-InstalledMehscan }
        if ($null -ne (Resolve-InstalledMehscan -ForceDownload)) { throw 'Explicit force did not bypass PATH' }
        $passed++
    } finally {
        Remove-Item Function:Get-Command
        Remove-Item Function:Read-MehscanVersion
    }
    Assert-Rejected 'invalid version argument' { & $installerPath -Version '../../main' }
    Assert-Rejected 'source pin without version' { & $installerPath -SourceDigest ('a' * 40) }
    Assert-Rejected 'invalid source commit argument' { & $installerPath -Version 0.2.0 -SourceDigest 'not-a-commit' }
    Assert-Rejected 'HTTP download' { Invoke-PublicRequest -Uri http://github.com/a -MaximumBytes 10 }
    Assert-Rejected 'unrelated download host' { Invoke-PublicRequest -Uri https://example.com/a -MaximumBytes 10 }
    Assert-Rejected 'URL credentials' { Invoke-PublicRequest -Uri https://user@github.com/a -MaximumBytes 10 }
    Assert-Rejected 'nonstandard port' { Invoke-PublicRequest -Uri https://github.com:444/a -MaximumBytes 10 }
    $assetName = 'mehscan-v0.2.0-windows-x86_64.zip'
    $script:release = @{
        tag_name = 'v0.2.0'; draft = $false; prerelease = $false
        assets = @(
            @{ name = $assetName; size = 100; browser_download_url = "https://github.com/meh-security/mehscan/releases/download/v0.2.0/$assetName" },
            @{ name = "$assetName.sha256"; size = 101; browser_download_url = "https://github.com/meh-security/mehscan/releases/download/v0.2.0/$assetName.sha256" }
        )
    }
    function Invoke-PublicRequest { $script:release | ConvertTo-Json -Depth 10 }
    $parameters = @{ Repository = 'meh-security/mehscan'; RequestedTag = 'v0.2.0'; Platform = 'windows'; Architecture = 'x86_64' }
    $selected = Get-PublicRelease @parameters
    if ($selected.tagName -cne 'v0.2.0') { throw 'Exact release selection failed' }
    $passed++
    $release.draft = $true
    Assert-Rejected 'draft release' { Get-PublicRelease @parameters }
    $release.draft = $false
    $release.prerelease = $true
    Assert-Rejected 'prerelease' { Get-PublicRelease @parameters }
    $release.prerelease = $false
    $release.tag_name = 'v0.1.0'
    Assert-Rejected 'wrong release tag' { Get-PublicRelease @parameters }
    $release.tag_name = 'v0.2.0'
    Assert-Rejected 'missing exact architecture' { Get-PublicRelease -Repository meh-security/mehscan -RequestedTag v0.2.0 -Platform windows -Architecture aarch64 }
    $release.assets += $release.assets[0]
    Assert-Rejected 'duplicate asset' { Get-PublicRelease @parameters }
    $release.assets = @($release.assets[0], $release.assets[1])
    $release.assets[0].browser_download_url = 'https://example.com/payload.zip'
    Assert-Rejected 'unexpected release URL' { Get-PublicRelease @parameters }
    $release.assets[0].browser_download_url = "https://github.com/meh-security/mehscan/releases/download/v0.2.0/$assetName"
    $release.assets[0].size = 262144001
    Assert-Rejected 'oversized release asset' { Get-PublicRelease @parameters }
    function Invoke-PublicRequest { '{"attestations":[]}' }
    Assert-Rejected 'missing attestations' { Get-PublicAttestationBundles -Repository meh-security/mehscan -Digest ('a' * 64) }
    function Invoke-PublicRequest { '{"attestations":[{"bundle":null}]}' }
    Assert-Rejected 'missing bundle' { Get-PublicAttestationBundles -Repository meh-security/mehscan -Digest ('a' * 64) }
    function Invoke-PublicRequest { throw 'HTTP 403 API rate limit' }
    Assert-Rejected 'API failure' { Get-PublicRelease @parameters }
    function Invoke-PublicRequest { 'invalid-json' }
    Assert-Rejected 'malformed API response' { Get-PublicRelease @parameters }
    $archivePath = Join-Path $testRoot $assetName
    $checksumPath = "$archivePath.sha256"
    [IO.File]::WriteAllText($archivePath, 'test artifact')
    $hash = (Get-FileHash $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $assetName" | Set-Content $checksumPath
    if ((Assert-ArchiveChecksum $archivePath $checksumPath $assetName) -cne $hash) { throw 'Valid checksum rejected' }
    $passed++
    "$hash  other.zip" | Set-Content $checksumPath
    Assert-Rejected 'checksum filename mismatch' { Assert-ArchiveChecksum $archivePath $checksumPath $assetName }
    "$('0' * 64)  $assetName" | Set-Content $checksumPath
    Assert-Rejected 'checksum digest mismatch' { Assert-ArchiveChecksum $archivePath $checksumPath $assetName }
    'malformed checksum' | Set-Content $checksumPath
    Assert-Rejected 'malformed checksum' { Assert-ArchiveChecksum $archivePath $checksumPath $assetName }
    function gh { $global:LASTEXITCODE = 1; 'verification rejected' }
    $global:LASTEXITCODE = 0
    Assert-Rejected 'verifier failure' { Invoke-GitHubCli @('attestation', 'verify') }
    if ($LASTEXITCODE -ne 0) { throw 'Expected verifier failure leaked its exit status' }
    $passed++
    Remove-Item Function:gh
    $policy = @(Get-VerificationArguments a.zip b.jsonl v0.2.0 ('a' * 40))
    foreach ($required in @('--bundle', '--repo', 'meh-security/mehscan', '--signer-workflow', 'meh-security/mehscan/.github/workflows/release.yml', '--source-ref', 'refs/tags/v0.2.0', '--deny-self-hosted-runners', '--source-digest', ('a' * 40))) {
        if ($policy -cnotcontains $required) { throw "Missing verification constraint: $required" }
    }
    $passed++
    Set-Item Function:Invoke-PublicRequest $transport
    if ($Live) {
        Assert-Rejected 'download byte limit' { Invoke-PublicRequest -Uri https://api.github.com/repos/meh-security/mehscan/releases/tags/v0.2.0 -MaximumBytes 1 }
        Assert-Rejected 'download deadline' { Invoke-PublicRequest -Uri https://api.github.com/repos/meh-security/mehscan/releases/tags/v0.2.0 -MaximumBytes 2097152 -TimeoutSeconds 0 }
        $binary = & $installerPath -Version 0.2.0 -InstallDirectory (Join-Path $testRoot 'installed') -ForceDownload
        if (-not $binary -or -not (Test-Path -LiteralPath $binary)) { throw 'Live installer failed' }
        & $binary --version
        if ($LASTEXITCODE -ne 0) { throw 'Live version test failed' }
        $passed++
        $rejectedInstall = Join-Path $testRoot 'wrong-source'
        Assert-Rejected 'wrong source commit' { & $installerPath -Version 0.2.0 -SourceDigest ('0' * 40) -InstallDirectory $rejectedInstall -ForceDownload }
        if (Test-Path -LiteralPath $rejectedInstall) { throw 'Rejected provenance created an installation' }
    }
    Write-Output "PASS: $passed installer checks"
} finally {
    $resolvedRoot = [IO.Path]::GetFullPath($testRoot)
    $prefix = $temporaryBase.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolvedRoot.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe test cleanup path' }
    Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
}
