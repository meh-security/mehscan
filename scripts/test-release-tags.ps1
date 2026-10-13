$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$lines = @(Get-Content -LiteralPath (Join-Path $repositoryRoot '.github/workflows/release.yml'))
$start = [Array]::IndexOf($lines, '      - name: Create the GitHub release')
if ($start -lt 0) { throw 'Missing release publication step' }
while ($start -lt $lines.Count -and $lines[$start] -cne '        run: |') { $start++ }
if ($start -eq $lines.Count) { throw 'Missing structured publication script' }
$body = @()
for ($index = $start + 1; $index -lt $lines.Count; $index++) {
    if (-not $lines[$index].StartsWith('          ')) { break }
    $body += $lines[$index].Substring(10)
}
$publish = [scriptblock]::Create($body -join "`n")
function gh { $global:mehscanReleaseTestArguments = @($args); $global:LASTEXITCODE = 0 }
if ((Get-Command gh).CommandType -ne 'Function') { throw 'Release test must use the mock publisher' }
$testRoot = Join-Path $repositoryRoot ('target/release-tag-test-' + [guid]::NewGuid().ToString('N'))
$oldRef, $oldRepository, $oldLocation = $env:GITHUB_REF_NAME, $env:GITHUB_REPOSITORY, (Get-Location)
try {
    New-Item -ItemType Directory -Path (Join-Path $testRoot 'dist') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $testRoot 'dist/synthetic.zip') -Value fixture
    Set-Location $testRoot
    $env:GITHUB_REPOSITORY = 'example/synthetic'
    foreach ($tag in @('v1.2.3', 'v1.2.3-rc.1', 'v1.2.3-beta.2+test', 'v1.2.3+build')) {
        $env:GITHUB_REF_NAME = $tag
        & $publish
        $expectedPrerelease = $tag -match '^v[0-9]+\.[0-9]+\.[0-9]+-'
        if (($global:mehscanReleaseTestArguments -contains '--prerelease') -ne $expectedPrerelease) { throw 'Incorrect prerelease decision' }
        if (($global:mehscanReleaseTestArguments -contains '--latest=false') -ne $expectedPrerelease) { throw 'Incorrect latest decision' }
    }
    $global:mehscanReleaseTestArguments = @()
    $env:GITHUB_REF_NAME = '--unsafe'
    $rejected = $false
    try { & $publish } catch { $rejected = $true }
    if (-not $rejected -or $global:mehscanReleaseTestArguments.Count) { throw 'Invalid tag reached publisher' }
    Write-Output 'PASS: five release tag cases; publisher mocked, no GitHub writes'
} finally {
    Set-Location $oldLocation
    $env:GITHUB_REF_NAME, $env:GITHUB_REPOSITORY = $oldRef, $oldRepository
    $targetPrefix = [IO.Path]::GetFullPath((Join-Path $repositoryRoot 'target')) + [IO.Path]::DirectorySeparatorChar
    $resolved = [IO.Path]::GetFullPath($testRoot)
    if (-not $resolved.StartsWith($targetPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe release test cleanup path' }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    Remove-Variable -Scope Global -Name mehscanReleaseTestArguments -ErrorAction SilentlyContinue
}
