[CmdletBinding()]
param(
    [string]$Version,
    [string]$InstallDirectory,
    [switch]$ForceDownload,
    [string]$SourceDigest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'public-download.ps1')

$repository = 'meh-security/mehscan'
$maximumExpandedBytes = 1073741824
$maximumArchiveFiles = 100

function Invoke-GitHubCli {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $output = & gh @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "GitHub CLI failed with exit code ${LASTEXITCODE}: gh $($Arguments -join ' ')"
    }
    return ($output -join "`n")
}

function Read-MehscanVersion {
    param([Parameter(Mandatory)][string]$Executable)

    $output = & $Executable --version
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    $value = ($output -join "`n").Trim()
    if ($value -notmatch '^mehscan ([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)$') {
        return $null
    }
    return $Matches[1]
}

function Normalize-VersionTag {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }
    $tag = if ($Value.StartsWith('v', [StringComparison]::Ordinal)) { $Value } else { "v$Value" }
    if ($tag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$') {
        throw "Invalid Mehscan release version: $Value"
    }
    return $tag
}

function Get-Target {
    if (-not $IsWindows) { throw 'The PowerShell installer is Windows-only. On Linux/macOS use bash scripts/install-mehscan.sh.' }

    $architecture = switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
        'X64' { 'x86_64' }
        'Arm64' { 'aarch64' }
        'X86' { 'i686' }
        default { throw "Unsupported architecture: $_" }
    }

    return [pscustomobject]@{
        Platform = 'windows'
        Architecture = $architecture
        BinaryName = 'mehscan.exe'
    }
}

function Get-DefaultInstallRoot {
    $userProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    if ([string]::IsNullOrWhiteSpace($userProfile)) {
        throw 'Could not resolve the current user profile directory'
    }
    return [IO.Path]::Combine($userProfile, '.mehscan', 'cli')
}

function Resolve-InstalledMehscan {
    param([string]$RequestedTag, [string]$SourceDigest, [switch]$ForceDownload)
    if ($ForceDownload) { return $null }
    $pathCommand = Get-Command 'mehscan' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $pathCommand) {
        $pathVersion = Read-MehscanVersion $pathCommand.Source
        if ($null -eq $pathVersion) { throw 'Mehscan is on PATH but its version check failed. No installation attempted.' }
        if ($RequestedTag -and "v$pathVersion" -cne $RequestedTag) { throw "Mehscan $pathVersion is on PATH but $RequestedTag was requested. No installation attempted." }
        if ($SourceDigest) { throw 'Mehscan is on PATH; a version check cannot establish source provenance. No installation attempted. Explicit verified reinstallation requires -ForceDownload.' }
        Write-Output ([IO.Path]::GetFullPath($pathCommand.Source))
        return
    }
}

$requestedTag = Normalize-VersionTag $Version
if ($SourceDigest -and ($SourceDigest -cnotmatch '^[0-9a-f]{40}$' -or -not $requestedTag)) {
    throw 'SourceDigest requires an exact version and a lowercase 40-character Git commit'
}
if (-not $IsWindows) { throw 'The PowerShell installer is Windows-only. On Linux/macOS use bash scripts/install-mehscan.sh.' }
$installedPath = Resolve-InstalledMehscan -RequestedTag $requestedTag -SourceDigest $SourceDigest -ForceDownload:$ForceDownload
if ($installedPath) { Write-Output $installedPath; exit 0 }

$ghCommand = Get-Command 'gh' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $ghCommand) {
    throw 'GitHub CLI (gh) with attestation verification is required; login is not needed. No unverified installation fallback is available.'
}
Invoke-GitHubCli @('attestation', 'verify', '--help') | Out-Null

$target = Get-Target
$release = Get-PublicRelease -Repository $repository -RequestedTag $requestedTag -Platform $target.Platform -Architecture $target.Architecture
$tag = Normalize-VersionTag $release.tagName
if ($null -ne $requestedTag -and $tag -cne $requestedTag) {
    throw "GitHub returned release $tag when $requestedTag was requested"
}
# Immutable pins distributed with the trusted skill protect known releases against tag movement.
$releasePins = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../references/release-pins.json') -Raw | ConvertFrom-Json -AsHashtable
if (-not $SourceDigest -and $releasePins.ContainsKey($tag)) { $SourceDigest = $releasePins[$tag] }
if ($releasePins.ContainsKey($tag) -and $releasePins[$tag] -cnotmatch '^[0-9a-f]{40}$') {
    throw "Malformed source commit pin for $tag"
}

$assetName = "mehscan-$tag-$($target.Platform)-$($target.Architecture).zip"
$checksumName = "$assetName.sha256"
$usingDefaultInstallDirectory = [string]::IsNullOrWhiteSpace($InstallDirectory)
$managedInstallRoot = $null
if ($usingDefaultInstallDirectory) {
    $managedInstallRoot = Get-DefaultInstallRoot
    $InstallDirectory = [IO.Path]::Combine($managedInstallRoot, $tag, "$($target.Platform)-$($target.Architecture)")
}
$InstallDirectory = [IO.Path]::GetFullPath($InstallDirectory)
$destination = [IO.Path]::Combine($InstallDirectory, $target.BinaryName)

$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporaryRoot = [IO.Path]::Combine($temporaryBase, "mehscan-install-$([guid]::NewGuid().ToString('N'))")
$temporaryPrefix = $temporaryBase.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$stagedDestination = $null

try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    foreach ($downloadName in @($assetName, $checksumName)) {
        $downloadAsset = @($release.assets | Where-Object { $_.name -ceq $downloadName })[0]
        Invoke-PublicRequest -Uri $downloadAsset.browser_download_url -MaximumBytes $downloadAsset.size -OutputPath ([IO.Path]::Combine($temporaryRoot, $downloadName))
        if ((Get-Item -LiteralPath ([IO.Path]::Combine($temporaryRoot, $downloadName))).Length -ne $downloadAsset.size) {
            throw "Downloaded asset size differs from release metadata: $downloadName"
        }
    }

    $archivePath = [IO.Path]::Combine($temporaryRoot, $assetName)
    $checksumPath = [IO.Path]::Combine($temporaryRoot, $checksumName)
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        throw 'GitHub CLI did not download both required release files'
    }

    $actualHash = Assert-ArchiveChecksum -ArchivePath $archivePath -ChecksumPath $checksumPath -AssetName $assetName
    $bundles = @(Get-PublicAttestationBundles -Repository $repository -Digest $actualHash)
    $bundlePath = [IO.Path]::Combine($temporaryRoot, 'attestations.jsonl')
    [IO.File]::WriteAllText($bundlePath, ($bundles -join "`n"), [Text.UTF8Encoding]::new($false))
    $verificationArguments = Get-VerificationArguments -ArchivePath $archivePath -BundlePath $bundlePath -Tag $tag -SourceDigest $SourceDigest
    Invoke-GitHubCli $verificationArguments | Out-Null

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        $fileEntries = @($archive.Entries | Where-Object { -not [string]::IsNullOrEmpty($_.Name) })
        if ($fileEntries.Count -gt $maximumArchiveFiles -or
            ($fileEntries | Measure-Object -Property Length -Sum).Sum -gt $maximumExpandedBytes) {
            throw 'Release archive exceeds the extraction safety limits'
        }
        $files = @($fileEntries | ForEach-Object {
            $name = $_.FullName.Replace('\', '/')
            if ($name.StartsWith('/', [StringComparison]::Ordinal) -or
                $name -match '(^|/)\.\.(/|$)' -or
                $name.Contains(':')) {
                throw "Unsafe archive member: $name"
            }
            $unixFileType = (($_.ExternalAttributes -shr 16) -band 0xF000)
            if ($unixFileType -eq 0xA000) {
                throw "Release archive contains a symbolic link: $name"
            }
            $name
        })
        if (@($files | Select-Object -Unique).Count -ne $files.Count) {
            throw 'Release archive contains duplicate file paths'
        }
        foreach ($requiredFile in @($target.BinaryName, 'release-manifest.json')) {
            if ($files -cnotcontains $requiredFile) {
                throw "Release archive is missing $requiredFile"
            }
        }
    } finally {
        $archive.Dispose()
    }

    $extractionRoot = [IO.Path]::Combine($temporaryRoot, 'extracted')
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractionRoot
    $manifest = Get-Content -LiteralPath ([IO.Path]::Combine($extractionRoot, 'release-manifest.json')) -Raw | ConvertFrom-Json
    $manifestFiles = @($manifest.files | Sort-Object)
    $archiveFiles = @($files | Sort-Object)
    if ($manifest.schema_version -cne '1.0' -or
        $manifest.product -cne 'mehscan' -or
        $manifest.version -cne $tag.Substring(1) -or
        $manifest.platform -cne $target.Platform -or
        $manifest.architecture -cne $target.Architecture -or
        ($manifestFiles -join "`n") -cne ($archiveFiles -join "`n")) {
        throw 'Release manifest does not match the requested target and archive contents'
    }

    $extractedBinary = [IO.Path]::Combine($extractionRoot, $target.BinaryName)
    New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
    $stagedName = ".mehscan.$([guid]::NewGuid().ToString('N')).exe"
    $stagedDestination = [IO.Path]::Combine($InstallDirectory, $stagedName)
    Copy-Item -LiteralPath $extractedBinary -Destination $stagedDestination
    $stagedVersion = Read-MehscanVersion $stagedDestination
    if ($null -eq $stagedVersion -or "v$stagedVersion" -cne $tag) {
        throw "Installed executable does not report version $($tag.Substring(1))"
    }
    Move-Item -LiteralPath $stagedDestination -Destination $destination -Force
    $stagedDestination = $null
    $installedVersion = Read-MehscanVersion $destination
    if ($null -eq $installedVersion -or "v$installedVersion" -cne $tag) {
        throw "Final installed executable does not report version $($tag.Substring(1))"
    }
    Write-Output $destination
}
finally {
    if ($null -ne $stagedDestination -and (Test-Path -LiteralPath $stagedDestination -PathType Leaf)) {
        Remove-Item -LiteralPath $stagedDestination -Force
    }
    $resolvedTemporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
    if (-not $resolvedTemporaryRoot.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean unsafe temporary path: $resolvedTemporaryRoot"
    }
    if (Test-Path -LiteralPath $resolvedTemporaryRoot) {
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}
