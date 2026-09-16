# Bounded public HTTPS transport. Authentication and custom trust roots are never supplied.
function Invoke-PublicRequest {
    param(
        [Parameter(Mandatory)][uri]$Uri,
        [Parameter(Mandatory)][long]$MaximumBytes,
        [string]$OutputPath,
        [int]$TimeoutSeconds = 60
    )
    $allowedHosts = @('api.github.com', 'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com')
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('mehscan-installer')
    $client.DefaultRequestHeaders.Accept.ParseAdd('application/vnd.github+json')
    $client.DefaultRequestHeaders.Add('X-GitHub-Api-Version', '2022-11-28')
    $deadline = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSeconds))
    $response = $null
    $inputStream = $null
    $outputStream = $null
    $completed = $false
    try {
        for ($redirects = 0; ; $redirects++) {
            if ($Uri.Scheme -cne 'https' -or $Uri.Port -ne 443 -or $Uri.UserInfo -or $allowedHosts -cnotcontains $Uri.Host) {
                throw 'Refusing an unexpected download origin'
            }
            $response = $client.GetAsync($Uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $deadline.Token).GetAwaiter().GetResult()
            if ([int]$response.StatusCode -in @(301, 302, 303, 307, 308)) {
                if ($redirects -ge 5 -or $null -eq $response.Headers.Location) { throw 'Invalid or excessive download redirects' }
                $Uri = [uri]::new($Uri, $response.Headers.Location)
                $response.Dispose()
                $response = $null
                continue
            }
            $response.EnsureSuccessStatusCode() | Out-Null
            break
        }
        if ($response.Content.Headers.ContentLength -gt $MaximumBytes) { throw 'Download exceeds its byte limit' }
        $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $outputStream = if ($OutputPath) { [IO.File]::Create($OutputPath) } else { [IO.MemoryStream]::new() }
        $buffer = [byte[]]::new(65536)
        $total = 0L
        while (($count = $inputStream.ReadAsync($buffer, 0, $buffer.Length, $deadline.Token).GetAwaiter().GetResult()) -gt 0) {
            $total += $count
            if ($total -gt $MaximumBytes) { throw 'Download exceeds its byte limit' }
            $outputStream.Write($buffer, 0, $count)
        }
        if ($null -ne $response.Content.Headers.ContentLength -and $total -ne $response.Content.Headers.ContentLength) {
            throw 'Download length differs from Content-Length'
        }
        if (-not $OutputPath) { [Text.Encoding]::UTF8.GetString($outputStream.ToArray()) }
        $completed = $true
    } finally {
        if ($null -ne $outputStream) { $outputStream.Dispose() }
        if ($null -ne $inputStream) { $inputStream.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
        $deadline.Dispose()
        $client.Dispose()
        if (-not $completed -and $OutputPath -and [IO.File]::Exists($OutputPath)) { [IO.File]::Delete($OutputPath) }
    }
}

function Get-PublicRelease {
    param([string]$Repository, [string]$RequestedTag, [string]$Platform, [string]$Architecture)
    $endpoint = if ($RequestedTag) { "tags/$RequestedTag" } else { 'latest' }
    $release = Invoke-PublicRequest -Uri "https://api.github.com/repos/$Repository/releases/$endpoint" -MaximumBytes 2097152 | ConvertFrom-Json
    $tag = Normalize-VersionTag $release.tag_name
    if (-not $tag -or $release.draft -or $release.prerelease) { throw 'Refusing a missing or non-final release' }
    if ($RequestedTag -and $tag -cne $RequestedTag) { throw 'Release tag differs from requested version' }
    $assetName = "mehscan-$tag-$Platform-$Architecture.zip"
    foreach ($name in @($assetName, "$assetName.sha256")) {
        $assets = @($release.assets | Where-Object { $_.name -ceq $name })
        if ($assets.Count -ne 1) { throw "Release $tag has no unique asset named $name" }
        if ($assets[0].browser_download_url -cne "https://github.com/$Repository/releases/download/$tag/$name") {
            throw "Unexpected release URL for $name"
        }
        $limit = if ($name -ceq $assetName) { 262144000 } else { 1024 }
        if ($assets[0].size -le 0 -or $assets[0].size -gt $limit) { throw "Release asset size is outside the allowed range: $name" }
    }
    [pscustomobject]@{ tagName = $tag; assets = $release.assets }
}

function Get-VerificationArguments {
    param([string]$ArchivePath, [string]$BundlePath, [string]$Tag, [string]$SourceDigest)
    $arguments = @('attestation', 'verify', $ArchivePath, '--bundle', $BundlePath,
        '--repo', 'meh-security/mehscan', '--signer-workflow', 'meh-security/mehscan/.github/workflows/release.yml',
        '--source-ref', "refs/tags/$Tag", '--deny-self-hosted-runners')
    if ($SourceDigest) { $arguments += @('--source-digest', $SourceDigest) }
    $arguments
}

function Get-PublicAttestationBundles {
    param([string]$Repository, [string]$Digest)
    $attestations = Invoke-PublicRequest -Uri "https://api.github.com/repos/$Repository/attestations/sha256:$Digest" -MaximumBytes 4194304 | ConvertFrom-Json
    $bundles = @($attestations.attestations | ForEach-Object {
        if ($null -eq $_.bundle) { throw 'Attestation bundle is missing' }
        $_.bundle | ConvertTo-Json -Depth 100 -Compress
    })
    if ($bundles.Count -eq 0) { throw 'No public artifact attestations returned; refusing installation' }
    $bundles
}

function Assert-ArchiveChecksum {
    param([string]$ArchivePath, [string]$ChecksumPath, [string]$AssetName)
    $text = (Get-Content -LiteralPath $ChecksumPath -Raw).Trim()
    if ($text -notmatch '^([0-9a-fA-F]{64})  ([^/\\\r\n]+)$' -or $Matches[2] -cne $AssetName) {
        throw "Malformed checksum file: $AssetName.sha256"
    }
    $expected = $Matches[1].ToLowerInvariant()
    $actual = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $expected) { throw "SHA-256 mismatch for $AssetName" }
    $actual
}
