from setuptools import setup, find_packages

setup(
    name="pyneat-cli",
    version="2.4.5",
    packages=find_packages(),
    install_requires=["click>=8.0.0", "libcst>=0.4.0"],
    entry_points={"console_scripts": ["pyneat=pyneat.cli:cli"]},
)
