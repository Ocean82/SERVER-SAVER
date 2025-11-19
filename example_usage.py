#!/usr/bin/env python3
"""
Example usage of the AWS Server Health Checker
Demonstrates how to use the tool programmatically
"""

from server_monitor import AWSHealthChecker, FailureSeverity
import json

def example_basic_check():
    """Basic example: Check all instances in a region"""
    print("Example 1: Basic Health Check")
    print("=" * 60)
    
    checker = AWSHealthChecker(region='us-east-1')
    failures = checker.run_full_check()
    
    print(f"\nFound {len(failures)} failure(s)")
    print(checker.generate_report())


def example_specific_instance():
    """Example: Check a specific instance"""
    print("\nExample 2: Check Specific Instance")
    print("=" * 60)
    
    # Replace with your actual instance ID
    instance_id = 'i-1234567890abcdef0'
    
    checker = AWSHealthChecker(region='us-east-1')
    failures = checker.run_full_check(instance_id=instance_id)
    
    if failures:
        print(f"\n⚠️  Found {len(failures)} issue(s) on instance {instance_id}")
        for failure in failures:
            print(f"  - [{failure.severity}] {failure.failure_type}: {failure.description}")
    else:
        print(f"\n✅ No issues found on instance {instance_id}")


def example_custom_checks():
    """Example: Run checks without SSM (for instances without SSM agent)"""
    print("\nExample 3: Custom Check Configuration")
    print("=" * 60)
    
    checker = AWSHealthChecker(region='us-east-1')
    
    # Skip SSM checks, only check CloudWatch metrics
    failures = checker.run_full_check(
        check_ssm=False,
        check_metrics=True
    )
    
    print(f"\nFound {len(failures)} failure(s) (SSM checks skipped)")


def example_json_output():
    """Example: Get failures as JSON for integration"""
    print("\nExample 4: JSON Output for Integration")
    print("=" * 60)
    
    checker = AWSHealthChecker(region='us-east-1')
    failures = checker.run_full_check()
    
    # Convert to JSON format
    failures_json = [f.to_dict() for f in failures]
    
    # Filter by severity
    critical_failures = [f for f in failures_json if f['severity'] == 'CRITICAL']
    
    print(f"\nTotal failures: {len(failures_json)}")
    print(f"Critical failures: {len(critical_failures)}")
    
    if critical_failures:
        print("\nCritical failures (JSON):")
        print(json.dumps(critical_failures, indent=2))


def example_alerting_logic():
    """Example: Implement alerting logic based on failures"""
    print("\nExample 5: Alerting Logic")
    print("=" * 60)
    
    checker = AWSHealthChecker(region='us-east-1')
    failures = checker.run_full_check()
    
    # Categorize failures
    critical = [f for f in failures if f.severity == FailureSeverity.CRITICAL.value]
    high = [f for f in failures if f.severity == FailureSeverity.HIGH.value]
    medium = [f for f in failures if f.severity == FailureSeverity.MEDIUM.value]
    
    # Alert logic
    if critical:
        print("🚨 ALERT: Critical failures detected!")
        print(f"   Count: {len(critical)}")
        print("   Action: Immediate attention required")
        # Here you could send email, Slack notification, etc.
    
    if high:
        print(f"⚠️  Warning: {len(high)} high-severity issue(s)")
        print("   Action: Review within 1 hour")
    
    if medium:
        print(f"ℹ️  Info: {len(medium)} medium-severity issue(s)")
        print("   Action: Review during next maintenance window")
    
    if not failures:
        print("✅ All systems operational")


if __name__ == '__main__':
    print("AWS Server Health Checker - Usage Examples")
    print("=" * 60)
    print("\nNote: Replace instance IDs and regions with your actual values")
    print("Make sure AWS credentials are configured before running\n")
    
    try:
        # Uncomment the example you want to run:
        # example_basic_check()
        # example_specific_instance()
        # example_custom_checks()
        # example_json_output()
        example_alerting_logic()
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("Make sure:")
        print("  1. AWS credentials are configured")
        print("  2. You have the required permissions")
        print("  3. The region/instance IDs are correct")

