# Test script for exercising SignalTrap TCP listeners
# Usage: .\test_traps.ps1 -Host 137.66.56.91
param(
    [string]$Host = '137.66.56.91',
    [int[]]$Ports = @(2222,2121,2323,3306,5432,6379,27017,3389),
    [int]$TimeoutMs = 5000
)

function Send-TCP {
    param($host, $port, $payload)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($host, $port, $null, $null)
        $success = $iar.AsyncWaitHandle.WaitOne($TimeoutMs)
        if (-not $success) { Write-Host "[TIMEOUT] $host:$port"; return }
        $client.EndConnect($iar)
        $stream = $client.GetStream()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
        $stream.Write($bytes, 0, $bytes.Length)
        Start-Sleep -Milliseconds 200
        if ($stream.DataAvailable) {
            $reader = New-Object System.IO.StreamReader($stream)
            $response = $reader.ReadToEnd()
            Write-Host "[RESPONSE] $host:$port -> $([regex]::Escape($response.Substring(0,[math]::Min(200,$response.Length))))"
        } else {
            Write-Host "[SENT] $host:$port -> $payload"
        }
        $stream.Close()
        $client.Close()
    } catch {
        Write-Host "[ERROR] $host:$port -> $_"
    }
}

# Per-port payloads to elicit common responses
$payloads = @{
    2222 = "SSH-2.0-OpenSSH_7.6p1\r\n";
    2121 = "USER test\r\nPASS test\r\n";
    2323 = "test\r\n";
    3306 = "\n"; # MySQL will likely close but connection attempt counts
    5432 = "\n"; # PostgreSQL
    6379 = "PING\r\n"; # Redis
    27017 = "\x00\x00\x00\x00\x00\x00\x00\x00"; # Mongo handshake (not strict)
    3389 = "\n"; # RDP attempt
}

Write-Host "Starting test against $Host ports: $($Ports -join ', ')"
foreach ($p in $Ports) {
    $payload = $payloads[$p]
    if (-not $payload) { $payload = "\n" }
    Send-TCP -host $Host -port $p -payload $payload
    Start-Sleep -Milliseconds 250
}

Write-Host "Done. Now check logs and /data/tcp_events.json on the Fly app."