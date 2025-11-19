#!/usr/bin/env python3
"""
AWS Server Failure Testing and Identification Tool
Monitors AWS EC2 instances and identifies various failure scenarios.
"""

import boto3
import json
import time
import sys
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server_monitor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class FailureSeverity(Enum):
    """Severity levels for detected failures"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class FailureReport:
    """Structure for failure reports"""
    timestamp: str
    instance_id: str
    instance_name: str
    failure_type: str
    severity: str
    description: str
    metrics: Dict
    recommendations: List[str]
    
    def to_dict(self):
        return asdict(self)


class AWSHealthChecker:
    """Main class for checking AWS server health"""
    
    def __init__(self, region: str = 'us-east-1', profile: Optional[str] = None):
        """
        Initialize AWS clients
        
        Args:
            region: AWS region to check
            profile: AWS profile name (optional)
        """
        self.region = region
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        
        self.ec2_client = session.client('ec2', region_name=region)
        self.cloudwatch = session.client('cloudwatch', region_name=region)
        self.ssm_client = session.client('ssm', region_name=region)
        
        self.failures: List[FailureReport] = []
        
    def get_all_instances(self) -> List[Dict]:
        """Retrieve all EC2 instances in the region"""
        try:
            response = self.ec2_client.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}]
            )
            instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instances.append(instance)
            return instances
        except Exception as e:
            logger.error(f"Error retrieving instances: {e}")
            return []
    
    def check_instance_status(self, instance: Dict) -> Optional[FailureReport]:
        """Check basic EC2 instance status"""
        instance_id = instance['InstanceId']
        instance_name = self._get_instance_name(instance)
        state = instance['State']['Name']
        
        if state != 'running':
            return FailureReport(
                timestamp=datetime.utcnow().isoformat(),
                instance_id=instance_id,
                instance_name=instance_name,
                failure_type="Instance State",
                severity=FailureSeverity.CRITICAL.value,
                description=f"Instance is in '{state}' state instead of 'running'",
                metrics={"state": state},
                recommendations=[
                    f"Check why instance {instance_id} is in {state} state",
                    "Review instance logs and CloudWatch metrics",
                    "Verify if instance was intentionally stopped"
                ]
            )
        return None
    
    def check_system_status_checks(self, instance_id: str) -> Optional[FailureReport]:
        """Check EC2 system status checks"""
        try:
            response = self.ec2_client.describe_instance_status(InstanceIds=[instance_id])
            if not response['InstanceStatuses']:
                return None
                
            status = response['InstanceStatuses'][0]
            instance_name = self._get_instance_name_from_id(instance_id)
            
            # System status check
            system_status = status.get('SystemStatus', {}).get('Status', 'unknown')
            if system_status != 'ok':
                details = status.get('SystemStatus', {}).get('Details', [])
                detail_info = details[0].get('Status', 'unknown') if details else 'unknown'
                
                return FailureReport(
                    timestamp=datetime.utcnow().isoformat(),
                    instance_id=instance_id,
                    instance_name=instance_name,
                    failure_type="System Status Check",
                    severity=FailureSeverity.CRITICAL.value,
                    description=f"System status check failed: {system_status} - {detail_info}",
                    metrics={"system_status": system_status, "details": detail_info},
                    recommendations=[
                        "Check EC2 console for detailed status information",
                        "Review instance logs via Systems Manager",
                        "Consider rebooting the instance if issue persists",
                        "Check for hardware failures"
                    ]
                )
            
            # Instance status check
            instance_status = status.get('InstanceStatus', {}).get('Status', 'unknown')
            if instance_status != 'ok':
                details = status.get('InstanceStatus', {}).get('Details', [])
                detail_info = details[0].get('Status', 'unknown') if details else 'unknown'
                
                return FailureReport(
                    timestamp=datetime.utcnow().isoformat(),
                    instance_id=instance_id,
                    instance_name=instance_name,
                    failure_type="Instance Status Check",
                    severity=FailureSeverity.HIGH.value,
                    description=f"Instance status check failed: {instance_status} - {detail_info}",
                    metrics={"instance_status": instance_status, "details": detail_info},
                    recommendations=[
                        "Check application logs",
                        "Verify instance configuration",
                        "Review recent changes to the instance"
                    ]
                )
        except Exception as e:
            logger.error(f"Error checking status checks for {instance_id}: {e}")
        return None
    
    def check_cloudwatch_metrics(self, instance_id: str, minutes: int = 15) -> List[FailureReport]:
        """Check CloudWatch metrics for anomalies"""
        failures = []
        instance_name = self._get_instance_name_from_id(instance_id)
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=minutes)
        
        metrics_to_check = [
            ('CPUUtilization', 80.0, FailureSeverity.HIGH),
            ('NetworkIn', None, FailureSeverity.INFO),
            ('NetworkOut', None, FailureSeverity.INFO),
            ('StatusCheckFailed', 0, FailureSeverity.CRITICAL),
            ('StatusCheckFailed_Instance', 0, FailureSeverity.HIGH),
            ('StatusCheckFailed_System', 0, FailureSeverity.CRITICAL),
        ]
        
        for metric_name, threshold, severity in metrics_to_check:
            try:
                response = self.cloudwatch.get_metric_statistics(
                    Namespace='AWS/EC2',
                    MetricName=metric_name,
                    Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=300,  # 5-minute periods
                    Statistics=['Average', 'Maximum']
                )
                
                if not response['Datapoints']:
                    continue
                
                # Get latest datapoint
                latest = max(response['Datapoints'], key=lambda x: x['Timestamp'])
                avg_value = latest.get('Average', 0)
                max_value = latest.get('Maximum', 0)
                
                if threshold is not None and avg_value > threshold:
                    if metric_name == 'StatusCheckFailed' and avg_value > 0:
                        failure_type = "Status Check Failure"
                        desc = f"Status check failures detected: {avg_value:.2f} failures"
                    elif metric_name == 'CPUUtilization':
                        failure_type = "High CPU Usage"
                        desc = f"CPU utilization is {avg_value:.2f}% (threshold: {threshold}%)"
                    else:
                        failure_type = f"Metric Threshold Exceeded: {metric_name}"
                        desc = f"{metric_name} value {avg_value:.2f} exceeds threshold {threshold}"
                    
                    failures.append(FailureReport(
                        timestamp=datetime.utcnow().isoformat(),
                        instance_id=instance_id,
                        instance_name=instance_name,
                        failure_type=failure_type,
                        severity=severity.value,
                        description=desc,
                        metrics={
                            "metric": metric_name,
                            "average": avg_value,
                            "maximum": max_value,
                            "threshold": threshold
                        },
                        recommendations=self._get_recommendations_for_metric(metric_name)
                    ))
            except Exception as e:
                logger.warning(f"Error checking metric {metric_name} for {instance_id}: {e}")
        
        return failures
    
    def check_disk_space_via_ssm(self, instance_id: str) -> Optional[FailureReport]:
        """Check disk space using SSM Run Command"""
        instance_name = self._get_instance_name_from_id(instance_id)
        
        try:
            # Check if instance has SSM agent running
            response = self.ssm_client.describe_instance_information(
                Filters=[
                    {
                        'Key': 'InstanceIds',
                        'Values': [instance_id]
                    }
                ]
            )
            
            if not response['InstanceInformationList']:
                logger.warning(f"Instance {instance_id} not available via SSM")
                return None
            
            # Run disk space check command
            command = "df -h | awk 'NR>1 {print $1,$2,$3,$4,$5,$6}'"
            
            response = self.ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={'commands': [command]},
                TimeoutSeconds=30
            )
            
            command_id = response['Command']['CommandId']
            
            # Wait for command to complete
            time.sleep(2)
            
            output = self.ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            
            if output['Status'] != 'Success':
                return FailureReport(
                    timestamp=datetime.utcnow().isoformat(),
                    instance_id=instance_id,
                    instance_name=instance_name,
                    failure_type="SSM Command Failure",
                    severity=FailureSeverity.MEDIUM.value,
                    description=f"Unable to check disk space via SSM: {output.get('Status', 'Unknown')}",
                    metrics={"ssm_status": output.get('Status')},
                    recommendations=[
                        "Verify SSM agent is running on the instance",
                        "Check IAM permissions for SSM",
                        "Manually check disk space via SSH"
                    ]
                )
            
            # Parse disk usage
            stdout = output.get('StandardOutputContent', '')
            lines = stdout.strip().split('\n')
            
            critical_partitions = []
            for line in lines:
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 5:
                    filesystem = parts[0]
                    usage_pct = parts[4].rstrip('%')
                    try:
                        usage = float(usage_pct)
                        if usage > 85:
                            critical_partitions.append({
                                "filesystem": filesystem,
                                "usage": usage
                            })
                    except ValueError:
                        continue
            
            if critical_partitions:
                return FailureReport(
                    timestamp=datetime.utcnow().isoformat(),
                    instance_id=instance_id,
                    instance_name=instance_name,
                    failure_type="High Disk Usage",
                    severity=FailureSeverity.HIGH.value,
                    description=f"Disk usage exceeds 85% on {len(critical_partitions)} partition(s)",
                    metrics={"critical_partitions": critical_partitions},
                    recommendations=[
                        "Clean up old log files and temporary data",
                        "Archive old data to S3",
                        "Consider increasing EBS volume size",
                        "Review application logs for excessive logging"
                    ]
                )
        except Exception as e:
            logger.warning(f"Error checking disk space for {instance_id}: {e}")
        
        return None
    
    def check_memory_via_ssm(self, instance_id: str) -> Optional[FailureReport]:
        """Check memory usage via SSM"""
        instance_name = self._get_instance_name_from_id(instance_id)
        
        try:
            command = "free -m | awk 'NR==2{printf \"%.2f\", $3*100/$2}'"
            
            response = self.ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={'commands': [command]},
                TimeoutSeconds=30
            )
            
            command_id = response['Command']['CommandId']
            time.sleep(2)
            
            output = self.ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            
            if output['Status'] == 'Success':
                stdout = output.get('StandardOutputContent', '').strip()
                try:
                    memory_usage = float(stdout)
                    if memory_usage > 90:
                        return FailureReport(
                            timestamp=datetime.utcnow().isoformat(),
                            instance_id=instance_id,
                            instance_name=instance_name,
                            failure_type="High Memory Usage",
                            severity=FailureSeverity.HIGH.value,
                            description=f"Memory usage is {memory_usage:.2f}%",
                            metrics={"memory_usage_percent": memory_usage},
                            recommendations=[
                                "Identify memory-intensive processes",
                                "Consider upgrading instance type",
                                "Review application memory leaks",
                                "Check for memory leaks in applications"
                            ]
                        )
                except ValueError:
                    pass
        except Exception as e:
            logger.warning(f"Error checking memory for {instance_id}: {e}")
        
        return None
    
    def check_security_groups(self, instance: Dict) -> Optional[FailureReport]:
        """Check for common security group misconfigurations"""
        instance_id = instance['InstanceId']
        instance_name = self._get_instance_name(instance)
        security_groups = instance.get('SecurityGroups', [])
        
        if not security_groups:
            return FailureReport(
                timestamp=datetime.utcnow().isoformat(),
                instance_id=instance_id,
                instance_name=instance_name,
                failure_type="Security Group Configuration",
                severity=FailureSeverity.MEDIUM.value,
                description="No security groups attached to instance",
                metrics={"security_groups": []},
                recommendations=[
                    "Attach appropriate security groups",
                    "Review security group rules"
                ]
            )
        
        return None
    
    def _get_instance_name(self, instance: Dict) -> str:
        """Extract instance name from tags"""
        tags = instance.get('Tags', [])
        for tag in tags:
            if tag['Key'] == 'Name':
                return tag['Value']
        return instance['InstanceId']
    
    def _get_instance_name_from_id(self, instance_id: str) -> str:
        """Get instance name from instance ID"""
        try:
            response = self.ec2_client.describe_instances(InstanceIds=[instance_id])
            if response['Reservations']:
                instance = response['Reservations'][0]['Instances'][0]
                return self._get_instance_name(instance)
        except Exception:
            pass
        return instance_id
    
    def _get_recommendations_for_metric(self, metric_name: str) -> List[str]:
        """Get recommendations based on metric type"""
        recommendations_map = {
            'CPUUtilization': [
                "Investigate CPU-intensive processes",
                "Consider scaling horizontally or vertically",
                "Review application performance",
                "Check for runaway processes"
            ],
            'StatusCheckFailed': [
                "Review instance system logs",
                "Check application health",
                "Verify instance configuration",
                "Consider instance reboot if issue persists"
            ],
            'StatusCheckFailed_Instance': [
                "Check application logs",
                "Verify instance configuration",
                "Review recent changes"
            ],
            'StatusCheckFailed_System': [
                "Check for hardware issues",
                "Review EC2 console for detailed status",
                "Consider migrating to a new instance"
            ]
        }
        return recommendations_map.get(metric_name, ["Review metrics and investigate root cause"])
    
    def run_full_check(self, instance_id: Optional[str] = None, 
                      check_ssm: bool = True,
                      check_metrics: bool = True) -> List[FailureReport]:
        """
        Run comprehensive health check on instance(s)
        
        Args:
            instance_id: Specific instance ID to check (None for all instances)
            check_ssm: Whether to run SSM-based checks (requires SSM agent)
            check_metrics: Whether to check CloudWatch metrics
        
        Returns:
            List of FailureReport objects
        """
        self.failures = []
        
        if instance_id:
            instances = [self.ec2_client.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]]
        else:
            instances = self.get_all_instances()
        
        logger.info(f"Checking {len(instances)} instance(s)...")
        
        for instance in instances:
            inst_id = instance['InstanceId']
            inst_name = self._get_instance_name(instance)
            logger.info(f"Checking instance: {inst_name} ({inst_id})")
            
            # Basic status check
            failure = self.check_instance_status(instance)
            if failure:
                self.failures.append(failure)
            
            # Skip further checks if instance is not running
            if instance['State']['Name'] != 'running':
                continue
            
            # System status checks
            failure = self.check_system_status_checks(inst_id)
            if failure:
                self.failures.append(failure)
            
            # CloudWatch metrics
            if check_metrics:
                metric_failures = self.check_cloudwatch_metrics(inst_id)
                self.failures.extend(metric_failures)
            
            # SSM-based checks (requires SSM agent)
            if check_ssm:
                disk_failure = self.check_disk_space_via_ssm(inst_id)
                if disk_failure:
                    self.failures.append(disk_failure)
                
                memory_failure = self.check_memory_via_ssm(inst_id)
                if memory_failure:
                    self.failures.append(memory_failure)
            
            # Security group check
            sg_failure = self.check_security_groups(instance)
            if sg_failure:
                self.failures.append(sg_failure)
        
        return self.failures
    
    def generate_report(self, output_file: Optional[str] = None) -> str:
        """Generate formatted report of all failures"""
        if not self.failures:
            report = "✅ No failures detected. All checks passed.\n"
        else:
            report = f"\n{'='*80}\n"
            report += f"AWS SERVER FAILURE REPORT\n"
            report += f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            report += f"Total Failures: {len(self.failures)}\n"
            report += f"{'='*80}\n\n"
            
            # Group by severity
            by_severity = {}
            for failure in self.failures:
                severity = failure.severity
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(failure)
            
            for severity in [FailureSeverity.CRITICAL, FailureSeverity.HIGH, 
                           FailureSeverity.MEDIUM, FailureSeverity.LOW, FailureSeverity.INFO]:
                if severity.value in by_severity:
                    report += f"\n[{severity.value}] Failures ({len(by_severity[severity.value])}):\n"
                    report += "-" * 80 + "\n"
                    
                    for failure in by_severity[severity.value]:
                        report += f"\nInstance: {failure.instance_name} ({failure.instance_id})\n"
                        report += f"Type: {failure.failure_type}\n"
                        report += f"Time: {failure.timestamp}\n"
                        report += f"Description: {failure.description}\n"
                        report += f"Metrics: {json.dumps(failure.metrics, indent=2)}\n"
                        report += f"Recommendations:\n"
                        for rec in failure.recommendations:
                            report += f"  - {rec}\n"
                        report += "\n"
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            logger.info(f"Report saved to {output_file}")
        
        return report


def main():
    parser = argparse.ArgumentParser(
        description='AWS Server Failure Testing and Identification Tool'
    )
    parser.add_argument(
        '--region',
        default='us-east-1',
        help='AWS region to check (default: us-east-1)'
    )
    parser.add_argument(
        '--instance-id',
        help='Specific instance ID to check (default: all instances)'
    )
    parser.add_argument(
        '--profile',
        help='AWS profile name to use'
    )
    parser.add_argument(
        '--no-ssm',
        action='store_true',
        help='Skip SSM-based checks (disk space, memory)'
    )
    parser.add_argument(
        '--no-metrics',
        action='store_true',
        help='Skip CloudWatch metrics checks'
    )
    parser.add_argument(
        '--output',
        help='Output file for report (default: stdout)'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output report in JSON format'
    )
    
    args = parser.parse_args()
    
    try:
        checker = AWSHealthChecker(region=args.region, profile=args.profile)
        failures = checker.run_full_check(
            instance_id=args.instance_id,
            check_ssm=not args.no_ssm,
            check_metrics=not args.no_metrics
        )
        
        if args.json:
            report_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "total_failures": len(failures),
                "failures": [f.to_dict() for f in failures]
            }
            report = json.dumps(report_data, indent=2)
        else:
            report = checker.generate_report(output_file=args.output)
        
        print(report)
        
        # Exit with error code if failures found
        if failures:
            critical_count = sum(1 for f in failures if f.severity == FailureSeverity.CRITICAL.value)
            sys.exit(1 if critical_count > 0 else 0)
        
    except Exception as e:
        logger.error(f"Error running health check: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

