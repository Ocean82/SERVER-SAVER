#!/usr/bin/env python3
"""
Unit tests for server_monitor.py
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server_monitor import AWSHealthChecker, FailureReport, FailureSeverity


class TestAWSHealthChecker(unittest.TestCase):
    """Test cases for AWSHealthChecker class"""
    
    def setUp(self):
        """Set up test fixtures"""
        with patch('boto3.Session'):
            self.checker = AWSHealthChecker(region='us-east-1')
    
    def test_initialization(self):
        """Test AWSHealthChecker initialization"""
        self.assertIsNotNone(self.checker)
        self.assertEqual(self.checker.region, 'us-east-1')
        self.assertEqual(len(self.checker.failures), 0)
    
    def test_get_instance_name(self):
        """Test instance name extraction"""
        instance = {
            'Tags': [
                {'Key': 'Name', 'Value': 'test-server'}
            ]
        }
        name = self.checker._get_instance_name(instance)
        self.assertEqual(name, 'test-server')
    
    def test_get_instance_name_no_tags(self):
        """Test instance name when no Name tag exists"""
        instance = {'Tags': []}
        name = self.checker._get_instance_name(instance)
        self.assertEqual(name, 'Unknown')
    
    def test_failure_report_creation(self):
        """Test FailureReport creation"""
        report = FailureReport(
            timestamp="2025-11-21T00:00:00",
            instance_id="i-1234567890abcdef0",
            instance_name="test-instance",
            failure_type="Test Failure",
            severity="HIGH",
            description="Test description",
            metrics={"test": "value"},
            recommendations=["Fix this", "Fix that"]
        )
        
        self.assertEqual(report.instance_id, "i-1234567890abcdef0")
        self.assertEqual(report.severity, "HIGH")
        self.assertEqual(len(report.recommendations), 2)
    
    def test_failure_report_to_dict(self):
        """Test FailureReport serialization"""
        report = FailureReport(
            timestamp="2025-11-21T00:00:00",
            instance_id="i-1234567890abcdef0",
            instance_name="test-instance",
            failure_type="Test Failure",
            severity="HIGH",
            description="Test description",
            metrics={"test": "value"},
            recommendations=["Fix this"]
        )
        
        report_dict = report.to_dict()
        self.assertIsInstance(report_dict, dict)
        self.assertEqual(report_dict['instance_id'], "i-1234567890abcdef0")
        self.assertEqual(report_dict['severity'], "HIGH")


class TestFailureSeverity(unittest.TestCase):
    """Test cases for FailureSeverity enum"""
    
    def test_severity_levels(self):
        """Test all severity levels exist"""
        self.assertEqual(FailureSeverity.CRITICAL.value, "CRITICAL")
        self.assertEqual(FailureSeverity.HIGH.value, "HIGH")
        self.assertEqual(FailureSeverity.MEDIUM.value, "MEDIUM")
        self.assertEqual(FailureSeverity.LOW.value, "LOW")
        self.assertEqual(FailureSeverity.INFO.value, "INFO")


class TestInstanceStatusCheck(unittest.TestCase):
    """Test cases for instance status checking"""
    
    def setUp(self):
        """Set up test fixtures"""
        with patch('boto3.Session'):
            self.checker = AWSHealthChecker(region='us-east-1')
    
    def test_stopped_instance_detection(self):
        """Test detection of stopped instances"""
        instance = {
            'InstanceId': 'i-1234567890abcdef0',
            'State': {'Name': 'stopped'},
            'Tags': []
        }
        
        failure = self.checker.check_instance_status(instance)
        self.assertIsNotNone(failure)
        self.assertEqual(failure.failure_type, "Instance Not Running")
        self.assertEqual(failure.severity, "CRITICAL")
    
    def test_running_instance_no_failure(self):
        """Test that running instances don't generate failures"""
        instance = {
            'InstanceId': 'i-1234567890abcdef0',
            'State': {'Name': 'running'},
            'Tags': []
        }
        
        # Mock the status check to return no issues
        with patch.object(self.checker, 'check_instance_status_checks', return_value=None):
            failure = self.checker.check_instance_status(instance)
            # Should return None or a failure from status checks, not from state
            if failure:
                self.assertNotEqual(failure.failure_type, "Instance Not Running")


if __name__ == '__main__':
    unittest.main()

