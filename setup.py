from setuptools import setup, find_packages

setup(
    name="pyneat-cli",
    version="3.0.1",
    packages=find_packages(),
    install_requires=["click>=8.0.0", "libcst>=0.4.0"],
    entry_points={"console_scripts": ["pyneat=pyneat.cli:cli"]},
)
