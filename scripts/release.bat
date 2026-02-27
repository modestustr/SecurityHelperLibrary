@echo off
setlocal

set SCRIPT_DIR=%~dp0
powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%Prepare-Release.ps1" %*
set EXITCODE=%ERRORLEVEL%

endlocal & exit /b %EXITCODE%
