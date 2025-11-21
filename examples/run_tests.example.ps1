# PowerShell script to run tests
# Copy this file to run_tests.ps1 and update with your values

# Activate virtual environment if it exists
if (Test-Path ".venv\Scripts\Activate.ps1") {
    Write-Host "Activating virtual environment..." -ForegroundColor Green
    . .venv\Scripts\Activate.ps1
}

# YOUR instance details - UPDATE THESE VALUES
$INSTANCE_ID = "i-YOUR-INSTANCE-ID-HERE"
$APP_PATH = "/home/ubuntu/your-app-name"
$HEALTH_PORT = 8000

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Testing Server Monitoring Features" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Instance ID: $INSTANCE_ID"
Write-Host "App Path: $APP_PATH"
Write-Host ""

# Test 1: Process Monitoring
Write-Host "----------------------------------------" -ForegroundColor Yellow
Write-Host "TEST 1: Process Monitoring" -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Yellow
python server_monitor.py --instance-id $INSTANCE_ID --check-processes --app-path $APP_PATH

Write-Host ""
Write-Host "Press Enter to continue to next test..."
Read-Host

# Test 2: Health Endpoint
Write-Host "----------------------------------------" -ForegroundColor Yellow
Write-Host "TEST 2: Health Endpoint Check" -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Yellow
python server_monitor.py --instance-id $INSTANCE_ID --check-health --health-port $HEALTH_PORT --health-path "/health"

Write-Host ""
Write-Host "Press Enter to continue to next test..."
Read-Host

# Test 3: Log Analysis
Write-Host "----------------------------------------" -ForegroundColor Yellow
Write-Host "TEST 3: Log Analysis" -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Yellow
python server_monitor.py --instance-id $INSTANCE_ID --check-logs --app-path $APP_PATH

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "All tests complete!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan

