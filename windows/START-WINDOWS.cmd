@echo off
setlocal
chcp 65001 >nul

set "XHTTP_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "XHTTP_LAUNCHER=%~dp0_internal\xhttp-setup.ps1"
if not exist "%XHTTP_LAUNCHER%" goto :incomplete
if not exist "%XHTTP_POWERSHELL%" (
    echo ERROR: Windows PowerShell was not found.
    set "XHTTP_EXIT_CODE=1"
    goto :finished
)

"%XHTTP_POWERSHELL%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%XHTTP_LAUNCHER%"
set "XHTTP_EXIT_CODE=%ERRORLEVEL%"
goto :finished

:incomplete
echo ERROR: Release bundle is incomplete. In File Explorer select "Extract All" on the ZIP, then run START-WINDOWS.cmd from the extracted folder.
set "XHTTP_EXIT_CODE=1"

:finished
echo.
if not "%XHTTP_EXIT_CODE%"=="0" echo Setup stopped with exit code %XHTTP_EXIT_CODE%.
pause
exit /b %XHTTP_EXIT_CODE%
