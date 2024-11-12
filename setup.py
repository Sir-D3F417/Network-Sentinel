from setuptools import setup, find_packages
import os

# Read requirements
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

# Read README for long description
with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="network-sentinel",
    version="2.0.0",
    author="D3F417",
    author_email="info@d3f417.info",
    description="Advanced Network Security Monitoring Tool with ML capabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Sir-D3F417/Network-Sentinel",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'network-sentinel=network_sentinel.cli:cli',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
) 