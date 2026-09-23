[CmdletBinding()]
param(
    [string]$Fixture = "tests/fixtures/v2-process-flow",
    [string]$OutputDirectory,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$fixturePath = (Resolve-Path (Join-Path $repoRoot $Fixture)).Path

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repoRoot ("target/e2e-" + [Guid]::NewGuid().ToString("N"))
} elseif (-not [IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path $repoRoot $OutputDirectory
}

if (Test-Path -LiteralPath $OutputDirectory) {
    throw "E2E output directory already exists: $OutputDirectory"
}

if (-not $SkipBuild) {
    & cargo build --quiet --package mehscan-cli
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
}

$binaryName = if ($IsWindows -or $env:OS -eq "Windows_NT") { "mehscan.exe" } else { "mehscan" }
$binary = Join-Path $repoRoot ("target/debug/" + $binaryName)
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw "Mehscan binary was not found: $binary"
}

New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$scanPath = Join-Path $OutputDirectory "scan-candidates.json"
$runPath = Join-Path $OutputDirectory "review"

$scanJson = & $binary scan $fixturePath --format candidates
if ($LASTEXITCODE -ne 0) { throw "candidate scan failed with exit code $LASTEXITCODE" }
[IO.File]::WriteAllText(
    $scanPath,
    [string]::Join([Environment]::NewLine, @($scanJson)),
    [Text.UTF8Encoding]::new($false)
)
$scan = Get-Content -Raw -LiteralPath $scanPath | ConvertFrom-Json
if ($scan.root -ne ".") { throw "candidate scan exposed a non-portable root: $($scan.root)" }

$null = & $binary investigate review-bundles $fixturePath --output $runPath --max-reviews 20 --max-bytes 524288
if ($LASTEXITCODE -ne 0) { throw "review bundle generation failed with exit code $LASTEXITCODE" }
$manifest = Get-Content -Raw -LiteralPath (Join-Path $runPath "manifest.json") | ConvertFrom-Json
if ($manifest.root -ne ".") { throw "bundle manifest exposed a non-portable root: $($manifest.root)" }

foreach ($entry in $manifest.bundles) {
    $requestPath = Join-Path (Join-Path $runPath "requests") $entry.filename
    $responsePath = Join-Path (Join-Path $runPath "responses") $entry.filename
    $request = Get-Content -Raw -LiteralPath $requestPath | ConvertFrom-Json
    $results = foreach ($review in $request.reviews) {
        $unresolved = @($review.decision_facts.unresolved | Where-Object { $_ })
        $trace = [ordered]@{
            lookup_attempts = @()
            citations = @()
            reviewer_inferences = @()
            reviewer_origin_leads = @()
            blockers = @()
        }
        if ($unresolved.Count -gt 0) {
            $lookups = @($review.investigation.lookup_requests | Where-Object { $_ })
            for ($index = 0; $index -lt $lookups.Count; $index++) {
                if (@($lookups[$index].questions) -contains $unresolved[0]) {
                    $trace.lookup_attempts = @([ordered]@{
                        request_index = $index
                        escalation = $null
                        outcome = "unavailable"
                        detail = "The synthetic end-to-end test did not execute this supplied lookup."
                        artifacts = @()
                    })
                    break
                }
            }
            if ($trace.lookup_attempts.Count -eq 0) {
                $trace.blockers = @($review.investigation.blockers | Where-Object { $_ })
            }
            [ordered]@{
                review_id = $review.id
                decision = "needs_review"
                confidence = $review.confidence_policy.needs_review
                summary = "The supplied evidence leaves one decisive runtime fact unresolved."
                checks = @($unresolved[0])
                investigation = $trace
            }
        } else {
            [ordered]@{
                review_id = $review.id
                decision = "issue"
                confidence = $review.confidence_policy.issue
                summary = "The supplied evidence establishes the reviewed weakness without an unresolved fact."
                checks = @()
                investigation = $trace
            }
        }
    }
    $response = [ordered]@{
        schema_version = "1.1"
        bundle_fingerprint = $request.bundle_fingerprint
        results = @($results)
    }
    [IO.File]::WriteAllText(
        $responsePath,
        ($response | ConvertTo-Json -Depth 100),
        [Text.UTF8Encoding]::new($false)
    )

    $validated = & $binary investigate review-bundle-triage --bundle $requestPath --responses $responsePath
    if ($LASTEXITCODE -ne 0) { throw "response validation failed for $($entry.filename)" }
    $triage = $validated | ConvertFrom-Json
    if (-not $triage.complete) { throw "response was incomplete for $($entry.filename)" }
}

$summaryJson = & $binary investigate review-bundle-summary --run $runPath
if ($LASTEXITCODE -ne 0) { throw "review bundle summary failed with exit code $LASTEXITCODE" }
$summary = $summaryJson | ConvertFrom-Json
if ($summary.review_count -ne $manifest.review_count) {
    throw "summary reviewed $($summary.review_count) items; manifest declares $($manifest.review_count)"
}

$findingPath = Join-Path $OutputDirectory "mehscan-findings.json"
$sarifPath = Join-Path $OutputDirectory "mehscan-results.sarif"
& $binary report --run $runPath --format json --output $findingPath --reviewer synthetic-e2e
if ($LASTEXITCODE -ne 0) { throw "JSON report failed with exit code $LASTEXITCODE" }
& $binary report --run $runPath --format sarif --output $sarifPath --reviewer synthetic-e2e
if ($LASTEXITCODE -ne 0) { throw "SARIF report failed with exit code $LASTEXITCODE" }

$report = Get-Content -Raw -LiteralPath $findingPath | ConvertFrom-Json
$sarif = Get-Content -Raw -LiteralPath $sarifPath | ConvertFrom-Json
if ($report.scan.root -ne "." -or $sarif.runs[0].properties.scanRoot -ne ".") {
    throw "final report roots must be portable"
}
$reported = @($report.findings) + @($report.review_required)
foreach ($finding in $reported) {
    if ($finding.severity.level -eq "unknown") { throw "final report contains unknown severity" }
    if ($finding.severity.level -eq "medium" -and $finding.severity.source -ne "fallback_default") {
        throw "fallback medium severity is missing its source marker"
    }
    if ([IO.Path]::IsPathRooted([string]$finding.primary_location.path)) {
        throw "final report contains an absolute location: $($finding.primary_location.path)"
    }
}
if (@($sarif.runs[0].results).Count -ne @($report.findings).Count) {
    throw "SARIF confirmed-result count does not match canonical JSON"
}

[ordered]@{
    status = "passed"
    fixture = $Fixture.Replace("\", "/")
    output = $OutputDirectory
    candidates = @($scan.candidates).Count
    reviews = $summary.review_count
    findings = $report.summary.findings
    review_required = $report.summary.review_required
    dismissed = $report.summary.dismissed
    note = "Synthetic verdicts validate transport and reporting contracts, not model quality."
} | ConvertTo-Json
