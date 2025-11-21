# Install git hooks (PowerShell)

Write-Host "Installing git hooks..." -ForegroundColor Cyan

# Copy pre-commit hook
if (Test-Path "hooks\pre-commit") {
    Copy-Item hooks\pre-commit .git\hooks\pre-commit -Force
    Write-Host "✅ Pre-commit hook installed" -ForegroundColor Green
} else {
    Write-Host "❌ hooks\pre-commit not found" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "✅ Git hooks installed successfully!" -ForegroundColor Green
Write-Host "The pre-commit hook will now scan for secrets on every commit." -ForegroundColor Yellow

