from setuptools import setup, find_packages

setup(
    name="prowler",
    version="0.1.0",
    description="Automated recon pipeline for bug bounty hunting",
    author="prowler",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "prowler=prowler.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
)
