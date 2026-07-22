# demo.ps1 - start the ICS honeynet demo on Windows.
# Run it with:  .\demo.bat   (or right-click demo.bat -> open)
# Stop it with: .\stop_demo.bat
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$vpy = Join-Path $root ".venv\Scripts\python.exe"
$fleetDir = Join-Path $root "honeynet\fleet"
$pidFile = Join-Path $env:TEMP "honeynet_pids.txt"

if (-not (Test-Path $vpy)) { Write-Host "ERROR: virtual environment not found. Run the setup first."; exit 1 }

# start each run with clean logs
Remove-Item (Join-Path $fleetDir "connections.log") -ErrorAction SilentlyContinue
Remove-Item (Join-Path $fleetDir "actions.log") -ErrorAction SilentlyContinue

Write-Host "starting the honeypot fleet (8 fake devices) ..."
$fleet = Start-Process -FilePath $vpy -ArgumentList "run_fleet.py" -WorkingDirectory $fleetDir -PassThru -WindowStyle Hidden

Write-Host "starting the static honeypot on port 5022 (for the comparison) ..."
$static = Start-Process -FilePath $vpy -ArgumentList (Join-Path $root "honeynet\modbus-decoy\static_decoy.py") -PassThru -WindowStyle Hidden

Write-Host "starting the threat dashboard ..."
$dash = Start-Process -FilePath $vpy -ArgumentList "dashboard.py" -WorkingDirectory $fleetDir -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 6
Write-Host "adding example worldwide attacker IPs to the map ..."
Start-Process -FilePath $vpy -ArgumentList "demo_attackers.py","12" -WorkingDirectory $fleetDir -Wait -WindowStyle Hidden

@("$($fleet.Id)", "$($static.Id)", "$($dash.Id)") | Set-Content -Path $pidFile -Encoding utf8

Write-Host ""
Write-Host "READY.  Dashboard: http://localhost:8100"
Write-Host "Stop everything with:  .\stop_demo.bat"
Start-Process "http://localhost:8100"
