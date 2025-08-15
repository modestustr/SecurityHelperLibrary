@echo off
SETLOCAL

:: --- Ayarlar ---
SET PROJECT_DIR=%~dp0
SET CONFIGURATION=Release
SET OUTPUT_DIR=%PROJECT_DIR%bin\%CONFIGURATION%
SET LOCAL_NUGET_DIR=%PROJECT_DIR%..\nuget-packages

:: --- Projeyi temizle ve derle ---
echo Cleaning project...
dotnet clean "%PROJECT_DIR%SecurityHelperLibrary.csproj"

echo Building project...
dotnet build "%PROJECT_DIR%SecurityHelperLibrary.csproj" --configuration %CONFIGURATION%

:: --- NuGet paketini oluştur ---
echo Packing NuGet package...
dotnet pack "%PROJECT_DIR%SecurityHelperLibrary.csproj" --configuration %CONFIGURATION% --output "%LOCAL_NUGET_DIR%"

:: --- Paket yolunu göster ---
echo.
echo NuGet package created in: %LOCAL_NUGET_DIR%
echo.

:: --- Paket info ---
dir "%LOCAL_NUGET_DIR%\SecurityHelperLibrary*.nupkg"

pause
ENDLOCAL
