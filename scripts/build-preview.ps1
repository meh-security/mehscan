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
        (Join-Path $repositoryRoot 'docs/installation.md'),
        (Join-Path $repositoryRoot 'LICENSE'),
        (Join-Path $repositoryRoot 'THIRD_PARTY_NOTICES.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/SKILL.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/agents/openai.yaml'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/commands.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/review-planning.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/pattern-sweep.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/review-workflow.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/evidence-packaging.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/html-output-review.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/finish-review.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/triage-buckets.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/buckets/authorization.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/buckets/credential-state.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/buckets/crypto-configuration.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/buckets/interpreted-input.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/buckets/native-memory.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/buckets/operation-policy.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/buckets/resource-boundary.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/references/buckets/state-integrity.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/scripts/release-pins.json'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/scripts/install-mehscan.sh'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/scripts/install-mehscan.py'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/scripts/install-mehscan.ps1'),
        (Join-Path $repositoryRoot 'skills/mehscan-security/scripts/public-download.ps1'),
        (Join-Path $repositoryRoot 'skills/mehscan-report-quality/SKILL.md'),
        (Join-Path $repositoryRoot 'skills/mehscan-report-quality/agents/openai.yaml'),
        (Join-Path $repositoryRoot 'skills/mehscan-revalidation/SKILL.md')
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
    New-Item -ItemType Directory -Path (Join-Path $stageRoot 'skills/mehscan-revalidation') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stageRoot 'docs') -Force | Out-Null
    Copy-Item -LiteralPath $binaryPath -Destination (Join-Path $stageRoot $binaryName)
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'README.md') -Destination $stageRoot
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'docs/installation.md') -Destination (Join-Path $stageRoot 'docs')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'LICENSE') -Destination $stageRoot
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'THIRD_PARTY_NOTICES.md') -Destination $stageRoot
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/SKILL.md') -Destination (Join-Path $stageRoot 'skills/mehscan-security')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/agents/openai.yaml') -Destination (Join-Path $stageRoot 'skills/mehscan-security/agents')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/references/commands.md') -Destination (Join-Path $stageRoot 'skills/mehscan-security/references')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/references/review-planning.md') -Destination (Join-Path $stageRoot 'skills/mehscan-security/references')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/references/pattern-sweep.md') -Destination (Join-Path $stageRoot 'skills/mehscan-security/references')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/references/review-workflow.md') -Destination (Join-Path $stageRoot 'skills/mehscan-security/references')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/references/evidence-packaging.md') -Destination (Join-Path $stageRoot 'skills/mehscan-security/references')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/references/html-output-review.md') -Destination (Join-Path $stageRoot 'skills/mehscan-security/references')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/references/finish-review.md') -Destination (Join-Path $stageRoot 'skills/mehscan-security/references')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/references/triage-buckets.md') -Destination (Join-Path $stageRoot 'skills/mehscan-security/references')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/references/buckets') -Destination (Join-Path $stageRoot 'skills/mehscan-security/references') -Recurse
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/scripts/release-pins.json') -Destination (Join-Path $stageRoot 'skills/mehscan-security/scripts')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/scripts/install-mehscan.sh') -Destination (Join-Path $stageRoot 'skills/mehscan-security/scripts')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/scripts/install-mehscan.py') -Destination (Join-Path $stageRoot 'skills/mehscan-security/scripts')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/scripts/install-mehscan.ps1') -Destination (Join-Path $stageRoot 'skills/mehscan-security/scripts')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-security/scripts/public-download.ps1') -Destination (Join-Path $stageRoot 'skills/mehscan-security/scripts')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-report-quality/SKILL.md') -Destination (Join-Path $stageRoot 'skills/mehscan-report-quality')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-report-quality/agents/openai.yaml') -Destination (Join-Path $stageRoot 'skills/mehscan-report-quality/agents')
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'skills/mehscan-revalidation/SKILL.md') -Destination (Join-Path $stageRoot 'skills/mehscan-revalidation')

    $expectedFiles = @(
        'LICENSE',
        $binaryName,
        'README.md',
        'docs/installation.md',
        'release-manifest.json',
        'skills/mehscan-report-quality/agents/openai.yaml',
        'skills/mehscan-report-quality/SKILL.md',
        'skills/mehscan-revalidation/SKILL.md',
        'skills/mehscan-security/agents/openai.yaml',
        'skills/mehscan-security/references/commands.md',
        'skills/mehscan-security/references/review-planning.md',
        'skills/mehscan-security/references/pattern-sweep.md',
        'skills/mehscan-security/references/review-workflow.md',
        'skills/mehscan-security/references/evidence-packaging.md',
        'skills/mehscan-security/references/html-output-review.md',
        'skills/mehscan-security/references/finish-review.md',
        'skills/mehscan-security/references/triage-buckets.md',
        'skills/mehscan-security/references/buckets/authorization.md',
        'skills/mehscan-security/references/buckets/credential-state.md',
        'skills/mehscan-security/references/buckets/crypto-configuration.md',
        'skills/mehscan-security/references/buckets/interpreted-input.md',
        'skills/mehscan-security/references/buckets/native-memory.md',
        'skills/mehscan-security/references/buckets/operation-policy.md',
        'skills/mehscan-security/references/buckets/resource-boundary.md',
        'skills/mehscan-security/references/buckets/state-integrity.md',
        'skills/mehscan-security/scripts/release-pins.json',
        'skills/mehscan-security/scripts/install-mehscan.sh',
        'skills/mehscan-security/scripts/install-mehscan.py',
        'skills/mehscan-security/scripts/install-mehscan.ps1',
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

        $reviewRun = Join-Path $smokeRoot '_review-run'
        & $extractedBinary investigate review-bundles $fixtureTarget --output $reviewRun --max-total-reviews 1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Extracted executable review bundle generation failed' }
        $reviewManifest = Get-Content -LiteralPath (Join-Path $reviewRun 'manifest.json') -Raw | ConvertFrom-Json
        $reviewFile = $reviewManifest.bundles[0].filename
        $requestFile = Join-Path (Join-Path $reviewRun 'requests') $reviewFile
        $request = Get-Content -LiteralPath $requestFile -Raw | ConvertFrom-Json
        $review = $request.reviews[0]
        $anchor = if ($null -ne $review.candidate) { $review.candidate.sink.id } else { $review.anchor_evidence_ids[0] }
        $anchorLocation = if ($null -ne $review.candidate) { $review.candidate.sink.location } else { @($review.evidence | Where-Object { $_.id -eq $anchor })[0].location }
        $journalDir = Join-Path $reviewRun 'journals'
        New-Item -ItemType Directory -Path $journalDir -Force | Out-Null
        $journalFile = Join-Path $journalDir "$($review.id).jsonl"
        & $extractedBinary investigate source $fixtureTarget --path $anchorLocation.path --start-line $anchorLocation.start.line --end-line $anchorLocation.end.line --journal $journalFile | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Extracted executable journaled source query failed' }
        $draft = @{
            schema_version = '1.3'
            bundle_fingerprint = $request.bundle_fingerprint
            results = @(@{
                review_id = $review.id
                selected_anchor_id = $anchor
                decision = 'needs_review'
                confidence = 'low'
                summary = 'The selected operation needs a runtime check before this smoke review can decide it.'
                checks = @('Confirm the decision-changing runtime behavior for this selected operation.')
                investigation = @{ decisive_artifacts = @(); journal_summary = $null; citations = @(); reviewer_inferences = @(); reviewer_origin_leads = @(); blockers = @() }
            })
        }
        $draftFile = Join-Path $reviewRun 'smoke-draft.json'
        $draft | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $draftFile -Encoding UTF8
        $responseDir = Join-Path $reviewRun 'responses'
        $responseFile = Join-Path $responseDir $reviewFile
        & $extractedBinary investigate review-bundle-finalize --bundle $requestFile --draft $draftFile --journal-dir $journalDir --output $responseFile --source-root $fixtureTarget | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Extracted executable review finalization failed' }
        $reviewReportText = & $extractedBinary report --run $reviewRun --responses $responseDir --source-root $fixtureTarget --format json
        if ($LASTEXITCODE -ne 0) { throw 'Extracted executable review report failed' }
        $reviewReport = ($reviewReportText -join "`n") | ConvertFrom-Json
        if ($reviewReport.summary.reviewed -ne 1) { throw 'Extracted executable review report has incorrect coverage' }
        $smokeSummary = [ordered]@{
            help = 'passed'
            version = $extractedVersion
            candidates = $candidateReport.candidates.Count
            sarif_results = $sarif.runs[0].results.Count
            review_flow = 'passed'
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
