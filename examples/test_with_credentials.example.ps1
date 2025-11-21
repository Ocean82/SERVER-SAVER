# Test script with AWS credentials
# Copy this file and update with your instance details

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Setting up AWS Credentials and Testing" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# AWS credentials should be set via environment variables or AWS config
# DO NOT hardcode credentials in this file!
# Set them before running:
#   $env:AWS_ACCESS_KEY_ID = "your_key"
#   $env:AWS_SECRET_ACCESS_KEY = "your_secret"
#   $env:AWS_DEFAULT_REGION = "us-east-1"

if (-not $env:AWS_ACCESS_KEY_ID -or -not $env:AWS_SECRET_ACCESS_KEY) {
    Write-Host "❌ ERROR: AWS credentials not set!" -ForegroundColor Red
    Write-Host "   Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables" -ForegroundColor Yellow
    exit 1
}

if (-not $env:AWS_DEFAULT_REGION) {
    $env:AWS_DEFAULT_REGION = "us-east-1"
}

Write-Host "✅ AWS credentials set" -ForegroundColor Green
Write-Host ""

# YOUR instance details - UPDATE THESE VALUES
$INSTANCE_ID = "i-YOUR-INSTANCE-ID-HERE"
$APP_PATH = "/home/ubuntu/your-app-name"
$HEALTH_PORT = 8000

Write-Host "Instance ID: $INSTANCE_ID" -ForegroundColor Cyan
Write-Host "App Path: $APP_PATH" -ForegroundColor Cyan
Write-Host "Health Port: $HEALTH_PORT" -ForegroundColor Cyan
Write-Host ""

# Test 1: Process Monitoring
Write-Host "----------------------------------------" -ForegroundColor Yellow
Write-Host "TEST 1: Process Monitoring (PM2/Node)" -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Yellow
python server_monitor.py --instance-id $INSTANCE_ID --check-processes --app-path $APP_PATH --output "test_processes_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

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

