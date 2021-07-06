#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="pastis-hf",
    version="0.2",
    description="Pastis Honggfuzz driver",
    packages=find_packages(),
    install_requires=[
        "coloredlogs",
        "click",
        "watchdog"
    ],
    scripts=['bin/pastis-honggfuzz']
)
