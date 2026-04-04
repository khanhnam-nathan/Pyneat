from setuptools import setup, find_packages

setup(
    name="pyneat",
    version="1.0.0",
    packages=find_packages(),
    install_requires=["click>=8.0.0"],
    entry_points={"console_scripts": ["pyneat=pyneat.cli:cli"]},
)
