[CmdletBinding()]
param(
    [string]$Version,
    [string]$OutputDirectory,
    [switch]$SkipBuild,
    [switch]$SkipSmoke
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$targetRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot 'target'))
$cliManifest = Join-Path $repositoryRoot 'crates/cli/Cargo.toml'

if ([string]::IsNullOrWhiteSpace($Version)) {
    $versionMatch = Select-String -LiteralPath $cliManifest -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($null -eq $versionMatch) {
        throw "Could not read the CLI version from $cliManifest"
    }
    $Version = $versionMatch.Matches[0].Groups[1].Value
}
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$') {
    throw "Invalid release version: $Version"
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $targetRoot 'release-artifacts'
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $targetRoot -Force | Out-Null

$platform = if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) {
    'windows'
} elseif ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Linux)) {
    'linux'
} elseif ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::OSX)) {
    'macos'
} else {
    throw 'Unsupported operating system'
}
$architecture = switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
    'X64' { 'x86_64' }
    'Arm64' { 'aarch64' }
    'X86' { 'i686' }
    default { throw "Unsupported architecture: $_" }
}
$binaryName = if ($platform -eq 'windows') { 'mehscan.exe' } else { 'mehscan' }
$releaseName = "mehscan-v$Version-$platform-$architecture"
$archivePath = Join-Path $OutputDirectory "$releaseName.zip"
$checksumPath = "$archivePath.sha256"
$stageRoot = Join-Path $targetRoot ("release-stage-" + [guid]::NewGuid().ToString('N'))
$smokeRoot = Join-Path $targetRoot ("release-smoke-" + [guid]::NewGuid().ToString('N'))

function Assert-SafeTemporaryPath([string]$Path) {
    $resolved = [IO.Path]::GetFullPath($Path)
    $prefix = $targetRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean a path outside the repository target directory: $resolved"
    }
}

try {
    if (-not $SkipBuild) {
        & cargo build --manifest-path (Join-Path $repositoryRoot 'Cargo.toml') -p mehscan-cli --release --locked
        if ($LASTEXITCODE -ne 0) {
            throw "Release build failed with exit code $LASTEXITCODE"
        }
    }

    $binaryPath = Join-Path $targetRoot "release/$binaryName"
    $requiredSources = @(
        $binaryPath,
        (Join-Path $repositoryRoot 'README.md'),
        (Join-Path $repositoryRoot 'LICENSE'),
        (Join-Path $repositoryRoot 'THIRD_PARTY_NOTICES.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/SKILL.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/agents/openai.yaml'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/native-c-cpp.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/release-pins.json'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/scripts/install-mehscan.ps1'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/scripts/public-download.ps1'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/scripts/new-review-response-schema.ps1'),
        (Join-Path $repositoryRoot 'skills/mehscan-report-quality/SKILL.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-report-quality/agents/openai.yaml')
    )
    foreach ($source in $requiredSources) {
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Required release input is missing: $source"
        }
    }
    $builtVersion = (& $binaryPath --version) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $builtVersion.Trim() -cne "mehscan $Version") {
        throw "Release version mismatch: requested $Version but executable reported '$($builtVersion.Trim())'"
    }

    New-Item -ItemType Directory -Path (Join-Path $stageRoot 'skills/mehscan-security/agents') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stageRoot 'skills/mehscan-security/references') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stageRoot 'skills/mehscan-security/scripts') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stageRoot 'skills/mehscan-report-quality/agents') -Force | Out-Null
    Copy-Item -LiteralPath $binaryPath -Destination (Join-Path $stageRoot $binaryName)
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'README.md') -Destination $stageRoot
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'LICENSE') -Destination $stageRoot
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'THIRD_PARTY_NOTICES.md') -Destination $stageRoot
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/SKILL.md') -Destination (Join-Path $stageRoot 'skills/mehscan-security')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/agents/openai.yaml') -Destination (Join-Path $stageRoot 'skills/mehscan-security/agents')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/references/native-c-cpp.md') -Destination (Join-Path $stageRoot 'skills/mehscan-security/references')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/references/release-pins.json') -Destination (Join-Path $stageRoot 'skills/mehscan-security/references')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/scripts/install-mehscan.ps1') -Destination (Join-Path $stageRoot 'skills/mehscan-security/scripts')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/scripts/public-download.ps1') -Destination (Join-Path $stageRoot 'skills/mehscan-security/scripts')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/scripts/new-review-response-schema.ps1') -Destination (Join-Path $stageRoot 'skills/mehscan-security/scripts')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-report-quality/SKILL.md') -Destination (Join-Path $stageRoot 'skills/mehscan-report-quality')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-report-quality/agents/openai.yaml') -Destination (Join-Path $stageRoot 'skills/mehscan-report-quality/agents')

    $expectedFiles = @(
        'LICENSE',
        $binaryName,
        'README.md',
        'release-manifest.json',
        'skills/mehscan-report-quality/agents/openai.yaml',
        'skills/mehscan-report-quality/SKILL.md',
        'skills/mehscan-security/agents/openai.yaml',
        'skills/mehscan-security/references/native-c-cpp.md',
        'skills/mehscan-security/references/release-pins.json',
        'skills/mehscan-security/scripts/install-mehscan.ps1',
        'skills/mehscan-security/scripts/new-review-response-schema.ps1',
        'skills/mehscan-security/scripts/public-download.ps1',
        'skills/mehscan-security/SKILL.md',
        'THIRD_PARTY_NOTICES.md'
    ) | Sort-Object
    $releaseManifest = [ordered]@{
        schema_version = '1.0'
        product = 'mehscan'
        version = $Version
        platform = $platform
        architecture = $architecture
        files = $expectedFiles
    }
    $releaseManifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $stageRoot 'release-manifest.json') -Encoding UTF8

    Compress-Archive -Path (Join-Path $stageRoot '*') -DestinationPath $archivePath -CompressionLevel Optimal -Force
    $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$archiveHash  $([IO.Path]::GetFileName($archivePath))" | Set-Content -LiteralPath $checksumPath -Encoding ASCII
    $recordedHash = ((Get-Content -LiteralPath $checksumPath -Raw).Trim() -split '\s+')[0]
    if ($recordedHash -cne $archiveHash) {
        throw 'Generated checksum does not match the release archive'
    }

    $smokeSummary = $null
    if (-not $SkipSmoke) {
        New-Item -ItemType Directory -Path $smokeRoot -Force | Out-Null
        Expand-Archive -LiteralPath $archivePath -DestinationPath $smokeRoot
        $actualFiles = @(Get-ChildItem -LiteralPath $smokeRoot -File -Recurse | ForEach-Object {
            $_.FullName.Substring($smokeRoot.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar).Replace('\', '/')
        } | Sort-Object)
        if (($actualFiles -join "`n") -cne ($expectedFiles -join "`n")) {
            throw "Archive membership differs from the release manifest.`nExpected: $($expectedFiles -join ', ')`nActual: $($actualFiles -join ', ')"
        }

        $extractedBinary = Join-Path $smokeRoot $binaryName
        if ($platform -ne 'windows') {
            & chmod 755 $extractedBinary
            if ($LASTEXITCODE -ne 0) {
                throw 'Could not make the extracted executable runnable'
            }
        }
        $helpOutput = & $extractedBinary --help
        if ($LASTEXITCODE -ne 0 -or ($helpOutput -join "`n") -notmatch 'deterministic security evidence scanner') {
            throw 'Extracted executable help smoke failed'
        }
        $extractedVersion = ((& $extractedBinary --version) -join "`n").Trim()
        if ($LASTEXITCODE -ne 0 -or $extractedVersion -cne "mehscan $Version") {
            throw "Extracted executable version mismatch: $extractedVersion"
        }

        $fixtureSource = Join-Path $repositoryRoot 'tests/fixtures/v2-sql-flow'
        $fixtureTarget = Join-Path $smokeRoot '_smoke-fixture'
        Copy-Item -LiteralPath $fixtureSource -Destination $fixtureTarget -Recurse
        $candidateText = & $extractedBinary scan $fixtureTarget --format candidates
        if ($LASTEXITCODE -ne 0) {
            throw 'Extracted executable candidate scan failed'
        }
        $candidateReport = ($candidateText -join "`n") | ConvertFrom-Json
        if ($candidateReport.candidates.Count -lt 1) {
            throw 'Extracted executable candidate scan returned no candidates'
        }
        $sarifText = & $extractedBinary scan $fixtureTarget --format sarif-candidates
        if ($LASTEXITCODE -ne 0) {
            throw 'Extracted executable SARIF scan failed'
        }
        $sarif = ($sarifText -join "`n") | ConvertFrom-Json
        if ($sarif.version -ne '2.1.0' -or $sarif.runs.Count -ne 1 -or $sarif.runs[0].results.Count -lt 1) {
            throw 'Extracted executable SARIF output failed validation'
        }
        $smokeSummary = [ordered]@{
            help = 'passed'
            version = $extractedVersion
            candidates = $candidateReport.candidates.Count
            sarif_results = $sarif.runs[0].results.Count
            exact_archive_membership = 'passed'
        }
    }

    [ordered]@{
        archive = $archivePath
        checksum_file = $checksumPath
        sha256 = $archiveHash
        version = $Version
        platform = "$platform-$architecture"
        files = $expectedFiles
        smoke = $smokeSummary
    } | ConvertTo-Json -Depth 5
}
finally {
    foreach ($temporaryPath in @($stageRoot, $smokeRoot)) {
        Assert-SafeTemporaryPath $temporaryPath
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Recurse -Force
        }
    }
}
