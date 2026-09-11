[CmdletBinding()]
param(
    [string]$Version,
    [string]$InstallDirectory,
    [switch]$ForceDownload
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repository = 'meh-security/mehscan'
$signerWorkflow = 'meh-security/mehscan/.github/workflows/release.yml'
$maximumArchiveBytes = 262144000
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

    return [pscustomobject]@{
        Platform = $platform
        Architecture = $architecture
        BinaryName = if ($platform -eq 'windows') { 'mehscan.exe' } else { 'mehscan' }
    }
}

function Get-DefaultInstallRoot {
    if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) {
        $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
        if (-not [string]::IsNullOrWhiteSpace($localAppData)) {
            return [IO.Path]::Combine($localAppData, 'mehscan')
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($env:XDG_CACHE_HOME) -and [IO.Path]::IsPathRooted($env:XDG_CACHE_HOME)) {
        return [IO.Path]::Combine($env:XDG_CACHE_HOME, 'mehscan')
    }
    return [IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile), '.cache', 'mehscan')
}

$requestedTag = Normalize-VersionTag $Version
if (-not $ForceDownload) {
    $pathCommand = Get-Command 'mehscan' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $pathCommand) {
        $pathVersion = Read-MehscanVersion $pathCommand.Source
        if ($null -ne $pathVersion -and ($null -eq $requestedTag -or "v$pathVersion" -ceq $requestedTag)) {
            Write-Output ([IO.Path]::GetFullPath($pathCommand.Source))
            exit 0
        }
    }
}

$ghCommand = Get-Command 'gh' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $ghCommand) {
    throw 'GitHub CLI (gh) is required to securely download and verify a Mehscan release'
}
Invoke-GitHubCli @('attestation', 'verify', '--help') | Out-Null

$target = Get-Target
$releaseArguments = @('release', 'view')
if ($null -ne $requestedTag) {
    $releaseArguments += $requestedTag
}
$releaseArguments += @('--repo', $repository, '--json', 'tagName,isDraft,isPrerelease,assets')
$release = Invoke-GitHubCli $releaseArguments | ConvertFrom-Json
$tag = Normalize-VersionTag $release.tagName
if ($release.isDraft -or $release.isPrerelease) {
    throw "Refusing non-final release: $tag"
}
if ($null -ne $requestedTag -and $tag -cne $requestedTag) {
    throw "GitHub returned release $tag when $requestedTag was requested"
}

$assetName = "mehscan-$tag-$($target.Platform)-$($target.Architecture).zip"
$checksumName = "$assetName.sha256"
$assetNames = @($release.assets | ForEach-Object { $_.name })
foreach ($requiredName in @($assetName, $checksumName)) {
    if (@($assetNames | Where-Object { $_ -ceq $requiredName }).Count -ne 1) {
        throw "Release $tag has no unique asset named $requiredName"
    }
}
$archiveAsset = @($release.assets | Where-Object { $_.name -ceq $assetName })[0]
if ($archiveAsset.size -le 0 -or $archiveAsset.size -gt $maximumArchiveBytes) {
    throw "Release asset size is outside the allowed range: $($archiveAsset.size) bytes"
}

if ([string]::IsNullOrWhiteSpace($InstallDirectory)) {
    $InstallDirectory = [IO.Path]::Combine((Get-DefaultInstallRoot), $tag, "$($target.Platform)-$($target.Architecture)")
}
$InstallDirectory = [IO.Path]::GetFullPath($InstallDirectory)
$destination = [IO.Path]::Combine($InstallDirectory, $target.BinaryName)

$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporaryRoot = [IO.Path]::Combine($temporaryBase, "mehscan-install-$([guid]::NewGuid().ToString('N'))")
$temporaryPrefix = $temporaryBase.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$stagedDestination = $null

try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    Invoke-GitHubCli @(
        'release', 'download', $tag,
        '--repo', $repository,
        '--dir', $temporaryRoot,
        '--pattern', $assetName,
        '--pattern', $checksumName
    ) | Out-Null

    $archivePath = [IO.Path]::Combine($temporaryRoot, $assetName)
    $checksumPath = [IO.Path]::Combine($temporaryRoot, $checksumName)
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        throw 'GitHub CLI did not download both required release files'
    }

    $checksumText = (Get-Content -LiteralPath $checksumPath -Raw).Trim()
    if ($checksumText -notmatch '^([0-9a-fA-F]{64})  ([^/\\\r\n]+)$' -or $Matches[2] -cne $assetName) {
        throw "Malformed checksum file: $checksumName"
    }
    $expectedHash = $Matches[1].ToLowerInvariant()
    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne $expectedHash) {
        throw "SHA-256 mismatch for $assetName"
    }

    Invoke-GitHubCli @(
        'attestation', 'verify', $archivePath,
        '--repo', $repository,
        '--signer-workflow', $signerWorkflow,
        '--source-ref', "refs/tags/$tag",
        '--deny-self-hosted-runners'
    ) | Out-Null

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
    if ($target.Platform -ne 'windows') {
        & chmod 700 $extractedBinary
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not make the Mehscan executable runnable'
        }
    }
    $binaryVersion = Read-MehscanVersion $extractedBinary
    if ($null -eq $binaryVersion -or "v$binaryVersion" -cne $tag) {
        throw "Downloaded executable does not report version $($tag.Substring(1))"
    }

    New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
    $stagedDestination = [IO.Path]::Combine($InstallDirectory, ".$($target.BinaryName).$([guid]::NewGuid().ToString('N')).tmp")
    Copy-Item -LiteralPath $extractedBinary -Destination $stagedDestination
    Move-Item -LiteralPath $stagedDestination -Destination $destination -Force
    $stagedDestination = $null
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
