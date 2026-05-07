from setuptools import setup, find_packages

setup(
    name="camille",
    version="1.0.0",
    description="Network Security Reconnaissance & Analysis Tool",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "colorama>=0.4.6",
        "rich>=13.7.0",
        "python-whois>=0.8.0",
        "dnspython>=2.4.2",
        "requests>=2.31.0",
        "cryptography>=41.0.0",
        "jinja2>=3.1.2",
        "click>=8.1.7",
    ],
    entry_points={
        "console_scripts": [
            "camille=camille.cli:main",
        ],
    },
)
