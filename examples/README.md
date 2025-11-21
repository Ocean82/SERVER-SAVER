# Examples Directory

This directory contains example configuration files and scripts that you can use as templates.

## 🚀 Quick Start

1. **Copy the example files** you need to the root directory
2. **Remove `.example` from the filename** (if applicable)
3. **Update the placeholder values** with your actual configuration
4. **Never commit your actual config files** - they're in `.gitignore`

## 📋 Available Examples

### Configuration Files

- `config.example.json` - Main configuration file template
  - Copy to `config.json` (already in .gitignore)
  - Update with your AWS instance ID, app path, etc.

### Scripts

- `run_tests.example.ps1` - PowerShell test script
  - Copy to `run_tests.ps1` (already in .gitignore)
  - Update with your instance ID and app path

- `test_with_credentials.example.ps1` - Test script with credential setup
  - Copy to `test_with_credentials.ps1` (already in .gitignore)
  - Update with your instance details

- `check_server_status.example.py` - Python script to check server status
  - Copy to `check_server_status.py` (already in .gitignore)
  - Update with your instance ID and app path

- `check_ssh_access_logs.example.py` - SSH log analysis script
  - Copy to `check_ssh_access_logs.py` (already in .gitignore)
  - Update with your instance ID and server IP

## 🔒 Security Notes

- **Never commit files with your actual credentials or instance IDs**
- All example files use placeholder values like:
  - `i-YOUR-INSTANCE-ID-HERE`
  - `/home/ubuntu/your-app-name`
  - `YOUR_SERVER_IP_HERE`
- Your actual config files are protected by `.gitignore`
- The pre-commit hook will also prevent committing secrets

## 📝 Usage

### Example: Setting up config.json

```bash
# Copy the example
cp examples/config.example.json config.json

# Edit with your values
# Use your favorite editor to update:
# - instance_id
# - app_path
# - region
# etc.
```

### Example: Setting up test script

```powershell
# Copy the example
Copy-Item examples\run_tests.example.ps1 run_tests.ps1

# Edit with your values
# Update $INSTANCE_ID and $APP_PATH
```

## ✅ What's Safe to Commit

- ✅ `examples/` directory (all example files)
- ✅ `server_monitor.py` (main script - no hardcoded values)
- ✅ Documentation files (`.md` files)
- ✅ `.gitignore` file
- ✅ `requirements.txt`
- ✅ Pre-commit hooks

## ❌ What's NOT Safe to Commit

- ❌ `config.json` (your actual config)
- ❌ `run_tests.ps1` (if copied from example)
- ❌ Any file with your instance ID, IP addresses, or paths
- ❌ SSH keys or credentials
- ❌ `.env` files

## 🎯 Best Practice

1. **Always use example files** as templates
2. **Copy to root directory** and rename (remove `.example`)
3. **Update with your values**
4. **Verify files are in `.gitignore`** before committing
5. **Test your setup** before sharing

---

**Remember:** The example files are safe to commit. Your actual config files (copied from examples) are protected by `.gitignore` and won't be committed.

