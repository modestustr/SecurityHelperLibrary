@echo off
SETLOCAL

:: --- Settings ---
SET PROJECT_DIR=%~dp0
SET CONFIGURATION=Release
SET OUTPUT_DIR=%PROJECT_DIR%bin\%CONFIGURATION%
SET LOCAL_NUGET_DIR=%PROJECT_DIR%..\nuget-packages

:: --- Read package version from csproj ---
echo Reading package version from project file...
set VERSION=unknown
for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "(Select-Xml -Path '%PROJECT_DIR%SecurityHelperLibrary.csproj' -XPath '//Version').Node.InnerText"`) do set VERSION=%%v
echo Project version: %VERSION%

:: --- Clean and build project ---
echo Cleaning project...
dotnet clean "%PROJECT_DIR%SecurityHelperLibrary.csproj"

echo Building project...
dotnet build "%PROJECT_DIR%SecurityHelperLibrary.csproj" --configuration %CONFIGURATION%

:: --- Create NuGet package ---
echo Packing NuGet package (version %VERSION%)...
dotnet pack "%PROJECT_DIR%SecurityHelperLibrary.csproj" --configuration %CONFIGURATION% --output "%LOCAL_NUGET_DIR%"

:: --- Show package path ---
echo.
echo NuGet package created in: %LOCAL_NUGET_DIR%
echo.

:: --- Package info ---
dir "%LOCAL_NUGET_DIR%\SecurityHelperLibrary*.nupkg"

pause
ENDLOCAL
