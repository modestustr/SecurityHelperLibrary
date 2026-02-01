#!/usr/bin/env pwsh
# Test script for SecurityHelperLibrary.Sample API

Write-Host "=== SecurityHelperLibrary Sample API Test ===" -ForegroundColor Green
Write-Host ""

# Give app time to start
Write-Host "Waiting for app to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

$baseUrl = "http://localhost:5000/api/auth"

# Test 1: Register User
Write-Host ""
Write-Host "1️⃣  TEST: Register User" -ForegroundColor Cyan
$registerBody = @{
    username = "john_doe"
    email = "john@example.com"
    password = "SecurePass123!"
    fullName = "John Doe"
} | ConvertTo-Json

Write-Host "Request Body:" -ForegroundColor Gray
Write-Host $registerBody

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/register" -Method Post `
        -Headers @{"Content-Type"="application/json"} `
        -Body $registerBody -ErrorAction Stop
    
    Write-Host "✅ Response:" -ForegroundColor Green
    $response | ConvertTo-Json -Depth 10 | Write-Host
} catch {
    Write-Host "❌ Error: $_" -ForegroundColor Red
}

# Test 2: Check Username Availability
Write-Host ""
Write-Host "2️⃣  TEST: Check Username Availability" -ForegroundColor Cyan

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/check-username?username=john_doe" `
        -Method Get -ErrorAction Stop
    
    Write-Host "✅ Response:" -ForegroundColor Green
    $response | ConvertTo-Json -Depth 10 | Write-Host
} catch {
    Write-Host "❌ Error: $_" -ForegroundColor Red
}

# Test 3: Login with Correct Password
Write-Host ""
Write-Host "3️⃣  TEST: Login with Correct Password" -ForegroundColor Cyan
$loginBody = @{
    usernameOrEmail = "john@example.com"
    password = "SecurePass123!"
} | ConvertTo-Json

Write-Host "Request Body:" -ForegroundColor Gray
Write-Host $loginBody

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/login" -Method Post `
        -Headers @{"Content-Type"="application/json"} `
        -Body $loginBody -ErrorAction Stop
    
    Write-Host "✅ Response:" -ForegroundColor Green
    $response | ConvertTo-Json -Depth 10 | Write-Host
} catch {
    Write-Host "❌ Error: $_" -ForegroundColor Red
}

# Test 4: Login with Wrong Password
Write-Host ""
Write-Host "4️⃣  TEST: Login with Wrong Password" -ForegroundColor Cyan
$loginBodyWrong = @{
    usernameOrEmail = "john@example.com"
    password = "WrongPassword123!"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/login" -Method Post `
        -Headers @{"Content-Type"="application/json"} `
        -Body $loginBodyWrong -ErrorAction Stop
    
    Write-Host "✅ Response:" -ForegroundColor Green
    $response | ConvertTo-Json -Depth 10 | Write-Host
} catch {
    Write-Host "❌ Error (Expected): $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Tests Complete ===" -ForegroundColor Green
