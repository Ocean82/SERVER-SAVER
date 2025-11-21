#!/usr/bin/env python3
"""
Setup script for SERVER-SAVER
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = [
        line.strip() 
        for line in requirements_file.read_text().splitlines() 
        if line.strip() and not line.startswith('#')
    ]

setup(
    name="server-saver",
    version="1.0.0",
    description="AWS Server Failure Testing and Identification Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Ocean82",
    author_email="sammyjernigan@gmail.com",
    url="https://github.com/Ocean82/SERVER-SAVER",
    py_modules=["server_monitor"],
    install_requires=requirements,
    python_requires=">=3.7",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
    ],
    entry_points={
        "console_scripts": [
            "server-monitor=server_monitor:main",
        ],
    },
    keywords="aws ec2 monitoring cloudwatch ssm server health",
)

