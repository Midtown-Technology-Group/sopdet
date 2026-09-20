@echo off
setlocal
cd /d "%~dp0"
echo Sopdet read-only device inventory
echo ---------------------------------
echo Collecting (no administrator rights required)...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-SopdetInventory.ps1" -OutputPath "%~dp0last-run.json" 1> "%~dp0last-run.log" 2>&1
if errorlevel 1 (
  echo.
  echo Finished WITH ERRORS. See last-run.log for details.
) else (
  echo.
  echo Done.
  echo   Payload : last-run.json
  echo   Log     : last-run.log
)
echo.
pause
