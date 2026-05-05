from setuptools import setup, find_packages

setup(
    name="phantom",
    version="1.1.0",
    description="Offensive Security Framework — CLI shell per penetration testing",
    author="Terminalkid09",
    packages=find_packages(),
    install_requires=[
        "rich>=13.0.0",
        "requests>=2.31.0",
        "python-nmap>=0.7.1",
        "scapy>=2.5.0",
        "reportlab>=4.0.0",
        "python-whois>=0.8.0",
        "dnspython>=2.4.0",
    ],
    entry_points={
        "console_scripts": [
            "phantom=phantom.main:main",
        ],
    },
    python_requires=">=3.10",
)