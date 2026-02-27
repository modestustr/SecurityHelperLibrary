@echo off
SETLOCAL

:: --- Settings ---
SET PROJECT_DIR=%~dp0
SET CONFIGURATION=Release
SET OUTPUT_DIR=%PROJECT_DIR%bin\%CONFIGURATION%
SET LOCAL_NUGET_DIR=%PROJECT_DIR%..\nuget-packages
SET SOLUTION_FILE=%PROJECT_DIR%..\SecurityHelperLibrary.sln
SET PROJECT_FILE=%PROJECT_DIR%SecurityHelperLibrary.csproj

if not exist "%PROJECT_FILE%" (
	echo ERROR: Project file not found: %PROJECT_FILE%
	exit /b 1
)

:: --- Read package version from csproj ---
echo Reading package version from project file...
set VERSION=unknown
for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "(Select-Xml -Path '%PROJECT_FILE%' -XPath '//Version').Node.InnerText"`) do set VERSION=%%v
echo Project version: %VERSION%

if "%VERSION%"=="unknown" (
	echo ERROR: Version could not be read from csproj.
	exit /b 1
)

echo Restoring solution...
dotnet restore "%SOLUTION_FILE%"
if errorlevel 1 exit /b 1

:: --- Clean and build project ---
echo Cleaning project...
dotnet clean "%PROJECT_FILE%" --configuration %CONFIGURATION%
if errorlevel 1 exit /b 1

echo Building project...
dotnet build "%PROJECT_FILE%" --configuration %CONFIGURATION% --no-restore
if errorlevel 1 exit /b 1

echo Running tests...
dotnet test "%SOLUTION_FILE%" --configuration %CONFIGURATION% --no-build
if errorlevel 1 exit /b 1

:: --- Create NuGet package ---
echo Packing NuGet package (version %VERSION%)...
dotnet pack "%PROJECT_FILE%" --configuration %CONFIGURATION% --no-build --output "%LOCAL_NUGET_DIR%"
if errorlevel 1 exit /b 1

:: --- Show package path ---
echo.
echo NuGet package created in: %LOCAL_NUGET_DIR%
echo.

:: --- Package info ---
dir "%LOCAL_NUGET_DIR%\SecurityHelperLibrary.%VERSION%.nupkg"

pause
ENDLOCAL
