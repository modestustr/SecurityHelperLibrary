<#
.SYNOPSIS  Starts the sample API and runs a quick smoke test against the auth endpoints.
.DESCRIPTION
This helper runs `dotnet run` over SecurityHelperLibrary.Sample, waits for the server to bind,
and executes registration, login, and availability checks against the same machine-local URLs.
The sample process is stopped automatically once the script finishes or fails.
.PARAMETER HttpPort
The HTTP port for the sample (default: 5000).
.PARAMETER HttpsPort
The HTTPS port for the sample (default: 5001).
.PARAMETER StartupTimeoutSeconds
How many seconds to wait for the sample to start listening before giving up (default: 60).
.PARAMETER PreferHttps
If set, the smoke test targets the HTTPS URL instead of HTTP when issuing requests. The server still starts with both protocols.
.EXAMPLE
  .\scripts\run-sample-tests.ps1
  # Starts the project on http://localhost:5000 and verifies /register, /login, /check-username, /check-email.
#>

[CmdletBinding()]
param(
    [int]
    $HttpPort = 5000,

    [int]
    $HttpsPort = 5001,

    [int]
    $StartupTimeoutSeconds = 60,

    [switch]
    $PreferHttps
)

Set-StrictMode -Version Latest
Write-Host "Preparing to smoke test SecurityHelperLibrary.Sample..."

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path "$scriptRoot/.."
$sampleProject = Resolve-Path "$repoRoot/SecurityHelperLibrary.Sample/SecurityHelperLibrary.Sample.csproj"

$scheme = if ($PreferHttps) { 'https' } else { 'http' }
$targetPort = if ($PreferHttps) { $HttpsPort } else { $HttpPort }
$baseUrl = "$scheme://localhost:$($targetPort)"
$urlsArg = "http://localhost:$HttpPort;https://localhost:$HttpsPort"

function Wait-ForPort {
    param(
        [int]
        $Port,

        [int]
        $TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            if (Test-NetConnection -ComputerName 'localhost' -Port $Port -InformationLevel Quiet) {
                return
            }
        }
        catch {
            # Ignore transient lookup failures
        }

        Start-Sleep -Seconds 1
    }

    throw "Timed out waiting for localhost:$Port after $TimeoutSeconds seconds."
}

function Invoke-SampleEndpoint {
    param(
        [ValidateSet('GET', 'POST')]
        [string]
        $Method,

        [Parameter(Mandatory = $true)]
        [string]
        $Uri,

        [Parameter()]
        $Body,

        [Parameter()]
        [string]
        $Description
    )

    try {
        if ($Body -ne $null) {
            $jsonBody = $Body | ConvertTo-Json -Depth 6
            return Invoke-RestMethod -Method $Method -Uri $Uri -ContentType 'application/json' -Body $jsonBody -ErrorAction Stop
        }

        return Invoke-RestMethod -Method $Method -Uri $Uri -ErrorAction Stop
    }
    catch {
        $message = $_.Exception.Message
        throw "$Description failed: $message"
    }
}

Write-Host "Resolving project dependencies..."
dotnet restore --project $sampleProject | Out-Null

$processArgs = @('run', '--project', $sampleProject, '--urls', $urlsArg)
Write-Host "Starting sample on $urlsArg (HTTP+$HttpPort, HTTPS+$HttpsPort)..."
$serverProcess = Start-Process dotnet -ArgumentList $processArgs -WorkingDirectory $repoRoot -NoNewWindow -PassThru

try {
    Write-Host "Waiting for $baseUrl to become available..."
    Wait-ForPort -Port $targetPort -TimeoutSeconds $StartupTimeoutSeconds
    Write-Host "Server listening on $baseUrl"

    $timestamp = (Get-Date).ToString('yyyyMMddHHmmss')
    $testUsername = "sampleuser$timestamp"
    $testEmail = "sampleuser+$timestamp@example.com"
    $testPassword = 'SampleP@ss123!'

    $registerPayload = @{
        username = $testUsername
        email = $testEmail
        password = $testPassword
        fullName = "Sample Tester $timestamp"
    }

    $registerResponse = Invoke-SampleEndpoint -Method 'POST' -Uri "$baseUrl/api/auth/register" -Body $registerPayload -Description 'Register request'
    Write-Host "Register succeeded? $($registerResponse.success) - message: $($registerResponse.message)"
    Write-Host "Created user id: $($registerResponse.user.id)"

    $usernameCheck = Invoke-SampleEndpoint -Method 'GET' -Uri "$baseUrl/api/auth/check-username?username=$testUsername" -Description 'Username availability check'
    Write-Host "Username available after register: $($usernameCheck.available) ($($usernameCheck.message))"

    $emailCheck = Invoke-SampleEndpoint -Method 'GET' -Uri "$baseUrl/api/auth/check-email?email=$testEmail" -Description 'Email availability check'
    Write-Host "Email available after register: $($emailCheck.available) ($($emailCheck.message))"

    $loginPayload = @{ usernameOrEmail = $testEmail; password = $testPassword }
    $loginResponse = Invoke-SampleEndpoint -Method 'POST' -Uri "$baseUrl/api/auth/login" -Body $loginPayload -Description 'Login request'
    Write-Host "Login success? $($loginResponse.success) - derived keys: $($loginResponse.derivedKeys.Count)"

    $invalidPayload = @{ usernameOrEmail = $testEmail; password = 'WrongPass123!' }
    try {
        Invoke-SampleEndpoint -Method 'POST' -Uri "$baseUrl/api/auth/login" -Body $invalidPayload -Description 'Invalid-credential login'
        Write-Warning "Unexpected success for invalid credentials request."
    }
    catch {
        Write-Host "Invalid credentials test correctly failed: $($_.Exception.Message)"
    }
}
finally {
    if ($serverProcess -and -not $serverProcess.HasExited) {
        Write-Host "Stopping sample process..."
        Stop-Process -Id $serverProcess.Id -ErrorAction SilentlyContinue
    }
}
Write-Host "Sample smoke test completed."
