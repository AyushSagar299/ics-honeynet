# stop_demo.ps1 - stop the ICS honeynet demo on Windows.
$pidFile = Join-Path $env:TEMP "honeynet_pids.txt"
if (Test-Path $pidFile) {
    Get-Content $pidFile | ForEach-Object {
        if ($_ -match '^\d+$') { taskkill /F /T /PID $_ 2>$null | Out-Null }
    }
    Remove-Item $pidFile -ErrorAction SilentlyContinue
}
Write-Host "demo stopped."
