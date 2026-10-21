@echo off
setlocal
cd /d "%~dp0"

set "PYTHON_EXE=%~dp0backend\.venv\Scripts\python.exe"

call :check_health
if not errorlevel 1 (
    echo EAGLE-JARVIS backend is already healthy on 127.0.0.1:8011. Reusing it.
    exit /b 0
)

set "LISTENER_PID="
for /f "tokens=5" %%P in ('netstat -ano -p tcp ^| findstr /R /C:":8011 .*LISTENING"') do if not defined LISTENER_PID set "LISTENER_PID=%%P"
if defined LISTENER_PID goto :port_busy

if not exist "%PYTHON_EXE%" (
    echo ERROR: The project Python environment was not found:
    echo   "%PYTHON_EXE%"
    echo Set up the backend environment, then run this file again.
    exit /b 1
)

echo Backend is not responding and port 8011 is free. Starting EAGLE-JARVIS...
start "EAGLE-JARVIS Backend" "%PYTHON_EXE%" -m uvicorn backend.main:app --host 127.0.0.1 --port 8011

for /l %%I in (1,1,20) do (
    call :check_health
    if not errorlevel 1 goto :started
    powershell.exe -NoLogo -NoProfile -NonInteractive -Command "Start-Sleep -Milliseconds 500"
)

echo ERROR: EAGLE-JARVIS did not become healthy after 20 checks.
echo Check the backend window for startup errors. No process was terminated.
exit /b 1

:port_busy
echo ERROR: Port 8011 is occupied, but EAGLE-JARVIS did not report a healthy status.
echo Listener PID: %LISTENER_PID%
echo The process was not terminated. Identify it before taking action:
tasklist /FI "PID eq %LISTENER_PID%"
exit /b 1

:started
echo EAGLE-JARVIS backend is healthy on 127.0.0.1:8011.
exit /b 0

:check_health
powershell.exe -NoLogo -NoProfile -NonInteractive -Command "try { $h=Invoke-RestMethod -Uri 'http://127.0.0.1:8011/api/health' -TimeoutSec 2; if ($h.status -eq 'healthy' -and $h.backend -eq 'connected' -and $null -ne $h.PSObject.Properties['gemini_configured']) { exit 0 } } catch {}; exit 1" >nul 2>&1
exit /b %errorlevel%
