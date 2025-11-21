# AWS Server Failure Testing and Identification Tool

A comprehensive Python tool for monitoring AWS EC2 instances and identifying various failure scenarios including system status checks, CloudWatch metrics anomalies, disk space issues, memory problems, and more.

## Features

- **EC2 Instance Status Monitoring**: Checks instance state and system/instance status checks
- **CloudWatch Metrics Analysis**: Monitors CPU utilization, network metrics, and status check failures
- **Disk Space Monitoring**: Uses AWS Systems Manager (SSM) to check disk usage
- **Memory Usage Tracking**: Monitors memory consumption via SSM
- **Security Group Validation**: Checks for common security group misconfigurations
- **Comprehensive Reporting**: Generates detailed failure reports with recommendations
- **Multiple Output Formats**: Supports text and JSON output formats

## Prerequisites

- Python 3.7 or higher
- AWS account with appropriate permissions
- AWS CLI configured (or environment variables set)
- EC2 instances with SSM agent installed (for disk/memory checks)

## Installation

1. Clone or download this repository

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Configure AWS credentials using one of these methods:
   - AWS CLI: `aws configure`
   - Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
   - IAM role (if running on EC2)
   - AWS profile: `export AWS_PROFILE=your-profile`

## Required AWS Permissions

The tool requires the following AWS permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeInstanceAttribute",
        "cloudwatch:GetMetricStatistics",
        "ssm:DescribeInstanceInformation",
        "ssm:SendCommand",
        "ssm:GetCommandInvocation"
      ],
      "Resource": "*"
    }
  ]
}
```

## Usage

### Basic Usage

Check all instances in the default region (us-east-1):
```bash
python server_monitor.py
```

### Check Specific Instance

```bash
python server_monitor.py --instance-id i-1234567890abcdef0
```

### Specify AWS Region

```bash
python server_monitor.py --region us-west-2
```

### Use AWS Profile

```bash
python server_monitor.py --profile my-aws-profile
```

### Skip SSM Checks (if SSM agent not available)

```bash
python server_monitor.py --no-ssm
```

### Skip CloudWatch Metrics

```bash
python server_monitor.py --no-metrics
```

### Save Report to File

```bash
python server_monitor.py --output report.txt
```

### JSON Output

```bash
python server_monitor.py --json --output report.json
```

### Complete Example

```bash
python server_monitor.py \
  --region us-west-2 \
  --instance-id i-1234567890abcdef0 \
  --profile production \
  --output failure_report.txt
```

## Failure Types Detected

### Critical Severity
- Instance not running
- System status check failures
- Status check failures (CloudWatch)

### High Severity
- Instance status check failures
- High CPU utilization (>80%)
- High memory usage (>90%)
- High disk usage (>85%)

### Medium Severity
- Security group misconfigurations
- SSM command failures

## Output Format

The tool generates detailed reports including:
- Timestamp of detection
- Instance ID and name
- Failure type and severity
- Detailed description
- Metrics data
- Actionable recommendations

### Example Report

```
================================================================================
AWS SERVER FAILURE REPORT
Generated: 2024-01-15 10:30:45 UTC
Total Failures: 2
================================================================================

[CRITICAL] Failures (1):
--------------------------------------------------------------------------------

Instance: web-server-01 (i-1234567890abcdef0)
Type: System Status Check
Time: 2024-01-15T10:30:00.000000
Description: System status check failed: impaired - failed
Metrics: {
  "system_status": "impaired",
  "details": "failed"
}
Recommendations:
  - Check EC2 console for detailed status information
  - Review instance logs via Systems Manager
  - Consider rebooting the instance if issue persists
  - Check for hardware failures
```

## Continuous Monitoring

For continuous monitoring, you can set up a cron job or scheduled task:

### Linux/Mac (cron)
```bash
# Run every 15 minutes
*/15 * * * * cd /path/to/SERVER-SAVER && python server_monitor.py --output reports/$(date +\%Y\%m\%d_\%H\%M\%S).txt
```

### Windows (Task Scheduler)
Create a scheduled task to run:
```powershell
python D:\SERVER-SAVER\server_monitor.py --output reports\report_%date%.txt
```

## Troubleshooting

### SSM Agent Not Available
If instances don't have SSM agent installed or configured:
- Use `--no-ssm` flag to skip SSM-based checks
- Install SSM agent on instances: https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent.html
- Ensure IAM role has SSM permissions

### CloudWatch Metrics Not Available
- Ensure CloudWatch monitoring is enabled (detailed monitoring recommended)
- Check IAM permissions for CloudWatch
- Use `--no-metrics` flag to skip CloudWatch checks

### Authentication Issues
- Verify AWS credentials are configured correctly
- Check IAM permissions
- Ensure the AWS region is correct

## Logging

The tool logs all activities to `server_monitor.log` and stdout. Check the log file for detailed debugging information.

## Exit Codes

- `0`: No failures detected or only non-critical failures
- `1`: Critical failures detected

This allows integration with monitoring systems and alerting tools.

## Examples

See the `examples/` directory for:
- Configuration file templates (`config.example.json`)
- Example scripts you can copy and customize
- Setup guides and best practices

**Important:** Copy example files to the root directory and update with your values. Your actual config files are protected by `.gitignore`.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Feel free to extend this tool with additional checks:
- Application-specific health checks
- Database connectivity tests
- Custom CloudWatch alarms
- Integration with notification services (SNS, Slack, etc.)

### Quick Setup for Contributors

1. Clone the repository
2. Copy `examples/config.example.json` to `config.json`
3. Update `config.json` with your test instance details
4. Install dependencies: `pip install -r requirements.txt`
5. Set up AWS credentials (see `AWS_CREDENTIALS_SETUP.md`)
6. Start contributing!

## License

This tool is provided as-is for server monitoring and failure identification purposes.

