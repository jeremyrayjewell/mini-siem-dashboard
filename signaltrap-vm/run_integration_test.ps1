# Integration test runner for SignalTrap
# Runs local test_traps.ps1 to exercise TCP listeners, then fetches recent Fly logs and /data/tcp_events.json
param(
    [string]$Host = '137.66.56.91',
    [string]$App = 'signaltrap'
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Running trap tests against $Host"
& "$scriptDir\test_traps.ps1" -Host $Host

Write-Host "\nWaiting 3s for events to be written..."
Start-Sleep -Seconds 3

Write-Host "\nFetching recent logs from Fly (last 5m)"
& flyctl logs --app $App --since 5m | Select-String -Pattern 'Logging event|LISTENERS|Saved|Started .* listener|ERROR|Exception' -SimpleMatch | Out-Host

Write-Host "\nChecking /data on instance"
& flyctl ssh console -a $App -C "ls -lh /data || true"

Write-Host "\nTail tcp_events.json (if present)"
& flyctl ssh console -a $App -C "if [ -f /data/tcp_events.json ]; then tail -n 200 /data/tcp_events.json; else echo '/data/tcp_events.json not found'; fi"

Write-Host "\nDone. If TCP events are missing, check logs for errors and ensure the listeners process is running."