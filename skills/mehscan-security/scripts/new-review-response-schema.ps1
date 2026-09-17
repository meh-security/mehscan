#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Bundle,
    [Parameter(Mandatory)][string]$Output
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$request = Get-Content -LiteralPath $Bundle -Raw | ConvertFrom-Json
$ids = @($request.review_ids)
if ($ids.Count -eq 0 -or [string]::IsNullOrWhiteSpace($request.bundle_fingerprint)) {
    throw 'The request must supply a fingerprint and at least one review ID.'
}
$seenIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($id in $ids) {
    if ($id -isnot [string] -or [string]::IsNullOrWhiteSpace($id) -or -not $seenIds.Add($id)) {
        throw 'Review IDs must be distinct nonempty strings.'
    }
}
$reviewIds = @($request.reviews | ForEach-Object { $_.id })
if ($reviewIds.Count -ne $ids.Count -or -not $seenIds.SetEquals([string[]]$reviewIds)) {
    throw 'The request review IDs must match its review objects exactly.'
}
$schema = [ordered]@{
    type = 'object'; additionalProperties = $false
    required = @('schema_version', 'bundle_fingerprint', 'results')
    properties = [ordered]@{
        schema_version = @{ type = 'string'; const = '1.0' }
        bundle_fingerprint = @{ type = 'string'; const = $request.bundle_fingerprint }
        results = @{
            type = 'array'; minItems = $ids.Count; maxItems = $ids.Count
            items = @{
                type = 'object'; additionalProperties = $false
                required = @('review_id', 'decision', 'confidence', 'summary', 'checks')
                properties = [ordered]@{
                    review_id = @{ type = 'string'; enum = $ids }
                    decision = @{ type = 'string'; enum = @('issue', 'not_issue', 'needs_review') }
                    confidence = @{ type = 'string'; enum = @('high', 'medium', 'low') }
                    summary = @{ type = 'string'; maxLength = 450 }
                    checks = @{ type = 'array'; items = @{ type = 'string' } }
                }
            }
        }
    }
}
$schema | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $Output -Encoding utf8NoBOM
