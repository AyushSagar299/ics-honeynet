# demo.ps1 - start the ICS honeynet demo on Windows.
# Run it with:  .\demo.bat   (or right-click demo.bat -> open)
# Stop it with: .\stop_demo.bat
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$vpy = Join-Path $root ".venv\Scripts\python.exe"
$fleetDir = Join-Path $root "honeynet\fleet"
$pidFile = Join-Path $env:TEMP "honeynet_pids.txt"

if (-not (Test-Path $vpy)) { Write-Host "ERROR: virtual environment not found. Run the setup first."; exit 1 }

# a laptop demo stays on this machine. on a real isolated deployment set
# $env:FLEET_BIND = "0.0.0.0" first, so the decoys can be reached from the decoy network.
if (-not $env:FLEET_BIND) { $env:FLEET_BIND = "127.0.0.1" }

# start each run with clean logs
Remove-Item (Join-Path $fleetDir "connections.log") -ErrorAction SilentlyContinue
Remove-Item (Join-Path $fleetDir "actions.log") -ErrorAction SilentlyContinue

Write-Host "starting the honeypot fleet (8 fake devices) ..."
$fleet = Start-Process -FilePath $vpy -ArgumentList "run_fleet.py" -WorkingDirectory $fleetDir -PassThru -WindowStyle Hidden

Write-Host "starting the OPC UA decoy on port 4840 (the second protocol) ..."
# the windows are hidden, so keep the decoy's output in a file like demo.sh does,
# otherwise there is nothing to look at when it refuses to start
$opcuaLog = Join-Path $env:TEMP "honeynet_opcua.log"
$opcuaErr = Join-Path $env:TEMP "honeynet_opcua_err.log"
$opcua = Start-Process -FilePath $vpy -ArgumentList (Join-Path $root "honeynet\opcua-decoy\decoy_opcua.py") -PassThru -WindowStyle Hidden -RedirectStandardOutput $opcuaLog -RedirectStandardError $opcuaErr

Write-Host "starting the static honeypot on port 5022 (for the comparison) ..."
$static = Start-Process -FilePath $vpy -ArgumentList (Join-Path $root "honeynet\modbus-decoy\static_decoy.py") -PassThru -WindowStyle Hidden

Write-Host "starting the decoy HMI with the honeytoken files on port 8090 ..."
$hmi = Start-Process -FilePath $vpy -ArgumentList (Join-Path $root "honeynet\hmi\decoy_hmi.py") -PassThru -WindowStyle Hidden

Write-Host "starting the threat dashboard ..."
$dash = Start-Process -FilePath $vpy -ArgumentList "dashboard.py" -WorkingDirectory $fleetDir -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 6
Write-Host "adding example worldwide attacker IPs to the map ..."
Start-Process -FilePath $vpy -ArgumentList "demo_attackers.py","12" -WorkingDirectory $fleetDir -Wait -WindowStyle Hidden

@("$($fleet.Id)", "$($opcua.Id)", "$($static.Id)", "$($hmi.Id)", "$($dash.Id)") | Set-Content -Path $pidFile -Encoding utf8

Write-Host ""
# windows has no lsof, Get-NetTCPConnection is the same idea. I check the port and
# not just the log line, so an old decoy still holding 4840 does not look like a
# good start. I do not connect to it, because connecting would log a fake probe.
$opcuaSaidUp = Select-String -Path $opcuaLog -Pattern "decoy up" -Quiet -ErrorAction SilentlyContinue
$opcuaPort = Get-NetTCPConnection -LocalPort 4840 -State Listen -ErrorAction SilentlyContinue
if ($opcuaSaidUp -and $opcuaPort) {
    Write-Host "  [ok] OPC UA decoy up on port 4840"
} else {
    Write-Host "  [!!] OPC UA decoy did not start -- see $opcuaLog"
}

Write-Host ""
Write-Host "READY.  Dashboard: http://localhost:8100   Decoy HMI: http://localhost:8090"
Write-Host "Listening on $($env:FLEET_BIND) (set FLEET_BIND=0.0.0.0 to expose the decoys on an isolated network)"
Write-Host "Stop everything with:  .\stop_demo.bat"
Start-Process "http://localhost:8100"
