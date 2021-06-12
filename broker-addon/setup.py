#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="hfwrapper-broker-addon",
    version="0.2",
    description="Honggfuzz wrapper - Broker Addon",
    packages=find_packages(),
    install_requires=[
        "lief"        # Should install whether as client or broker !
    ],
)
