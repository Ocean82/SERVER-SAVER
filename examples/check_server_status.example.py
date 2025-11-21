#!/usr/bin/env python3
"""
Example: Check Server Status
Copy this file and update with your instance details
"""

import sys
import os

# Add parent directory to path to import server_monitor
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server_monitor import AWSHealthChecker

# YOUR configuration - UPDATE THESE VALUES
INSTANCE_ID = "i-YOUR-INSTANCE-ID-HERE"
APP_PATH = "/home/ubuntu/your-app-name"
REGION = "us-east-1"

def main():
    print("Checking server status...")
    print(f"Instance ID: {INSTANCE_ID}")
    print(f"App Path: {APP_PATH}")
    print()
    
    checker = AWSHealthChecker(region=REGION)
    
    # Get instance details
    instances = checker.get_all_instances()
    target_instance = None
    
    for instance in instances:
        if instance['InstanceId'] == INSTANCE_ID:
            target_instance = instance
            break
    
    if not target_instance:
        print(f"❌ Instance {INSTANCE_ID} not found")
        return 1
    
    # Check instance status
    failure = checker.check_instance_status(target_instance)
    
    if failure:
        print(f"❌ Failure detected: {failure.failure_type}")
        print(f"   Severity: {failure.severity}")
        print(f"   Description: {failure.description}")
        return 1
    else:
        print("✅ Instance status: OK")
        return 0

if __name__ == "__main__":
    sys.exit(main())

