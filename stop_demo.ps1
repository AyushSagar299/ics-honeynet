# stop_demo.ps1 - stop the ICS honeynet demo on Windows.
$pidFile = Join-Path $env:TEMP "honeynet_pids.txt"
if (Test-Path $pidFile) {
    Get-Content $pidFile | ForEach-Object {
        if ($_ -match '^\d+$') { taskkill /F /T /PID $_ 2>$null | Out-Null }
    }
    Remove-Item $pidFile -ErrorAction SilentlyContinue
}

# an OPC UA decoy started by hand (or left over from a crashed run) is not in the
# pid file, and it would keep sitting on port 4840 so the next demo.bat cannot bind
# it. same idea as the lsof bit in stop_demo.sh: ask who owns the port, and only
# kill it if the command line really is our decoy.
$holders = Get-NetTCPConnection -LocalPort 4840 -State Listen -ErrorAction SilentlyContinue |
           Select-Object -ExpandProperty OwningProcess -Unique
foreach ($holder in $holders) {
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $holder" -ErrorAction SilentlyContinue
    if ($proc -and $proc.CommandLine -like "*decoy_opcua.py*") {
        taskkill /F /T /PID $holder 2>$null | Out-Null
        Write-Host "stopped leftover opcua decoy $holder"
    }
}

Write-Host "demo stopped."
