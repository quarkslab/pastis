#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="pastis-aflpp-broker-addon",
    version="0.2",
    description="AFLPP wrapper - Broker Addon",
    packages=find_packages(),
    install_requires=[
        "lief"        # Should install whether as client or broker !
    ],
)
