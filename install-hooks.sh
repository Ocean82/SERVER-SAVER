#!/bin/bash
# Install git hooks

echo "Installing git hooks..."

# Copy pre-commit hook
if [ -f "hooks/pre-commit" ]; then
    cp hooks/pre-commit .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
    echo "✅ Pre-commit hook installed"
else
    echo "❌ hooks/pre-commit not found"
    exit 1
fi

echo ""
echo "✅ Git hooks installed successfully!"
echo "The pre-commit hook will now scan for secrets on every commit."

