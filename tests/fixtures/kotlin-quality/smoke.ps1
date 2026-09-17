param([string]$Java = 'java')

$ErrorActionPreference = 'Stop'
$jar = Join-Path $PSScriptRoot 'build/libs/mehscan-kotlin-quality-app.jar'
if (!(Test-Path -LiteralPath $jar)) { throw 'Build the fixture with gradle bootJar first.' }
$javaPath = (Get-Command $Java -ErrorAction Stop).Source
$socket = [System.Net.Sockets.TcpClient]::new()
try {
    $connection = $socket.ConnectAsync('127.0.0.1', 8099)
    try { $connected = $connection.Wait(200) -and $socket.Connected } catch { $connected = $false }
    if ($connected) { throw 'Port 8099 is already occupied; stop that server before this check.' }
} finally { $socket.Dispose() }
$stdout = Join-Path $PSScriptRoot 'build/smoke.stdout.log'
$stderr = Join-Path $PSScriptRoot 'build/smoke.stderr.log'
$process = Start-Process -FilePath $javaPath -ArgumentList @('-jar', ('"' + $jar + '"')) -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        if ($process.HasExited) { throw "Fixture exited before readiness; inspect $stdout and $stderr" }
        try {
            $response = Invoke-WebRequest 'http://127.0.0.1:8099/query/bound?name=probe' -SkipHttpErrorCheck
            if ($response.StatusCode -eq 200) { $ready = $true; break }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    if (!$ready) { throw 'Fixture did not become ready within 30 seconds.' }
    $cases = @(
        @{ name='jdbc-raw-normal'; path='/jdbc/raw?name=Alice'; status=200; count=1 },
        @{ name='jdbc-raw-injection'; path='/jdbc/raw?name=%27%20OR%20%271%27%3D%271'; status=200; count=2 },
        @{ name='jdbc-bound-injection'; path='/jdbc/bound?name=%27%20OR%20%271%27%3D%271'; status=200; count=0 },
        @{ name='jdbc-bound-quote'; path='/jdbc/bound?name=O%27Reilly'; status=200; count=0 },
        @{ name='raw-normal'; path='/query/raw?name=Alice'; status=200; count=1 },
        @{ name='raw-injection'; path='/query/raw?name=%27%20OR%20%271%27%3D%271'; status=200; count=2 },
        @{ name='bound-injection'; path='/query/bound?name=%27%20OR%20%271%27%3D%271'; status=200; count=0 },
        @{ name='bound-missing'; path='/query/bound?name=missing'; status=200; count=0 },
        @{ name='raw-quote'; path='/query/raw?name=O%27Reilly'; status=500 },
        @{ name='bound-normal'; path='/query/bound?name=Alice'; status=200; count=1 },
        @{ name='bound-quote'; path='/query/bound?name=O%27Reilly'; status=200; count=0 },
        @{ name='numeric-valid'; path='/query/numeric?id=1'; status=200; count=1 },
        @{ name='numeric-text'; path='/query/numeric?id=not-a-number'; status=400 },
        @{ name='raw-command-benign'; path='/command/raw?command=whoami'; status=200 },
        @{ name='fixed-command'; path='/command/fixed'; status=200 }
    )
    $results = foreach ($case in $cases) {
        $response = Invoke-WebRequest ('http://127.0.0.1:8099' + $case.path) -SkipHttpErrorCheck
        $count = if ($case.ContainsKey('count')) { @($response.Content | ConvertFrom-Json).Count } else { $null }
        [pscustomobject]@{ name=$case.name; expected=$case.status; actual=[int]$response.StatusCode; expected_count=$case['count']; actual_count=$count; passed=($response.StatusCode -eq $case.status -and (!$case.ContainsKey('count') -or $count -eq $case['count'])) }
    }
    $results | ConvertTo-Json | Set-Content (Join-Path $PSScriptRoot 'build/runtime-smoke.json')
    $results | Format-Table
    if ($results.passed -contains $false) { throw 'One or more fixture checks failed.' }
} finally {
    if (!$process.HasExited) { Stop-Process -Id $process.Id -Force }
}
