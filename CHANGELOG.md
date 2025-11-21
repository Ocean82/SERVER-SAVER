# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Pre-commit hook for secret detection
- Examples directory with template files
- Git hooks installation scripts
- Contribution guidelines
- Security best practices documentation
- SSH key rotation scripts
- Comprehensive project documentation

### Security
- Removed RSA private key from git history
- Added pre-commit hook to prevent future secret commits
- Updated .gitignore to protect sensitive files
- Created example files with placeholders

## [1.0.0] - 2025-11-21

### Added
- Initial release of AWS Server Failure Testing and Identification Tool
- EC2 instance status monitoring
- CloudWatch metrics analysis
- Disk space monitoring via SSM
- Memory usage tracking via SSM
- Security group validation
- PM2/Node process monitoring
- Health endpoint checks
- Log analysis
- Syntax checking capabilities
- Comprehensive reporting (text and JSON formats)
- Multiple output options
- AWS profile and region support

### Features
- **Infrastructure Monitoring**
  - EC2 instance state checks
  - System and instance status checks
  - CloudWatch metrics analysis (CPU, network, status checks)
  
- **System Monitoring**
  - Disk space monitoring (via SSM)
  - Memory usage tracking (via SSM)
  
- **Application Monitoring**
  - PM2 process status monitoring
  - Node.js process detection
  - Health endpoint HTTP checks
  - Log analysis and error detection
  
- **Code Quality**
  - Syntax checking
  - Error pattern detection
  
- **Security**
  - Security group misconfiguration detection

### Documentation
- Comprehensive README with usage examples
- AWS credentials setup guide
- Quick start guide
- Process monitoring guide
- Testing guide
- Multiple PowerShell command references

---

## Version History

- **1.0.0** (2025-11-21): Initial release with comprehensive monitoring capabilities

