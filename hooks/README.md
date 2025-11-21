# Git Hooks

This directory contains git hooks that you can install to help protect your repository.

## Pre-commit Hook

The `pre-commit` hook automatically scans your commits for secrets and sensitive data before they're committed.

### Installation

**Option 1: Copy manually**
```bash
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

**Option 2: Use the install script**
```bash
# On Linux/Mac
chmod +x install-hooks.sh
./install-hooks.sh

# On Windows (PowerShell)
.\install-hooks.ps1
```

### What It Checks

- ✅ AWS Access Keys (AKIA...)
- ✅ AWS Secret Keys (40+ char strings)
- ✅ SSH/RSA Private Keys
- ✅ Hardcoded passwords
- ✅ API keys
- ✅ Key files (.pem, .key, etc.)
- ✅ .env files

### Features

- **Excludes `examples/` directory** - Template files won't trigger false warnings
- **Ignores placeholder text** - Patterns like `YOUR-INSTANCE-ID-HERE` are safe
- **Protects your code** - Still catches real secrets in actual code files

### Usage

The hook runs automatically on every `git commit`. If secrets are detected, the commit will be blocked.

To bypass (not recommended):
```bash
git commit --no-verify -m "message"
```

---

**Note:** Git hooks are local to your repository. Each developer needs to install them separately.

