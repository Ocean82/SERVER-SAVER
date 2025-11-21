#!/usr/bin/env python3
"""
Example: Check SSH Access Logs
Copy this file and update with your server details
"""

import boto3
import sys
import os
import time
from pathlib import Path

# YOUR configuration - UPDATE THESE VALUES
INSTANCE_ID = "i-YOUR-INSTANCE-ID-HERE"
REGION = "us-east-1"
SSH_KEY_PATH = Path.home() / ".ssh" / "your_key_name"
SERVER_USER = "ubuntu"
SERVER_IP = "YOUR_SERVER_IP_HERE"

def check_ssh_logs_via_ssm():
    """Check SSH logs using AWS SSM"""
    print("=" * 60)
    print("SSH Access Log Analysis")
    print("=" * 60)
    print()
    
    # Initialize SSM client
    try:
        ssm_client = boto3.client('ssm', region_name=REGION)
        print("✅ Connected to AWS SSM")
        print()
    except Exception as e:
        print(f"❌ Error connecting to AWS: {e}")
        print("Please ensure AWS credentials are configured")
        return 1
    
    # Commands to check SSH logs
    commands = [
        "echo '=== Recent SSH Logins (last 30 days) ==='",
        "last -n 50 | head -20",
        "echo ''",
        "echo '=== Current SSH Sessions ==='",
        "who",
        "echo ''",
        "echo '=== SSH Auth Log (recent entries) ==='",
        "if [ -f /var/log/auth.log ]; then tail -100 /var/log/auth.log | grep -i ssh;",
        "elif [ -f /var/log/secure ]; then tail -100 /var/log/secure | grep -i ssh;",
        "else echo 'Auth log not found in standard locations'; fi",
    ]
    
    try:
        print("Sending commands to server via SSM...")
        response = ssm_client.send_command(
            InstanceIds=[INSTANCE_ID],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': commands},
            TimeoutSeconds=60
        )
        
        command_id = response['Command']['CommandId']
        print(f"Command ID: {command_id}")
        print("Waiting for results...")
        print()
        
        time.sleep(5)
        
        # Get output
        output = ssm_client.get_command_invocation(
            CommandId=command_id,
            InstanceId=INSTANCE_ID
        )
        
        if output['Status'] == 'Success':
            print(output.get('StandardOutputContent', ''))
            return 0
        else:
            print(f"❌ Command failed: {output['Status']}")
            return 1
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(check_ssh_logs_via_ssm())

