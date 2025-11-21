# Contributing to SERVER-SAVER

Thank you for your interest in contributing! This guide will help you get started.

## 🚀 Getting Started

1. **Clone the repository**

   ```bash
   git clone https://github.com/Ocean82/SERVER-SAVER.git
   cd SERVER-SAVER
   ```

2. **Set up your environment**

   ```bash
   # Install dependencies
   pip install -r requirements.txt

   # Set up AWS credentials (see AWS_CREDENTIALS_SETUP.md)
   aws configure
   ```

3. **Copy example files**

   ```bash
   # Copy example config
   cp examples/config.example.json config.json

   # Edit config.json with your values
   # (config.json is in .gitignore - safe!)
   ```

## 📝 Making Changes

### Before You Start

- Check existing issues and pull requests
- Create an issue to discuss major changes
- Keep changes focused and well-documented

### Code Style

- Follow Python PEP 8 style guide
- Use meaningful variable names
- Add comments for complex logic
- Include docstrings for functions/classes

### Testing

- Test your changes with your own AWS instances
- Use example files from `examples/` directory
- Verify no secrets are hardcoded

## 🔒 Security Guidelines

### ✅ DO:

- Use environment variables for credentials
- Use example files as templates
- Test with placeholder values
- Review `.gitignore` before committing

### ❌ DON'T:

- Commit actual credentials or keys
- Hardcode instance IDs or IPs
- Commit personal configuration files
- Skip the pre-commit hook checks

## 📋 Pull Request Process

1. **Create a branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**

   - Follow code style guidelines
   - Add tests if applicable
   - Update documentation

3. **Test your changes**

   - Run the pre-commit hook: `git commit` (will run automatically)
   - Test with example configurations
   - Verify no secrets are included

4. **Commit your changes**

   ```bash
   git add .
   git commit -m "Description of your changes"
   ```

5. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```
   Then create a pull request on GitHub

## 🎯 Areas for Contribution

- Additional monitoring checks
- Support for more application types
- Integration with notification services (SNS, Slack, etc.)
- Documentation improvements
- Bug fixes
- Performance optimizations

## 📚 Documentation

- Update README.md for new features
- Add examples to `examples/` directory
- Document any new configuration options
- Include usage examples

## ❓ Questions?

- Open an issue for questions or discussions
- Check existing documentation first
- Review closed issues for similar questions

## 🙏 Thank You!

Your contributions make this project better for everyone. We appreciate your time and effort!

---

**Remember:** Always use example files, never commit secrets, and test thoroughly before submitting!
