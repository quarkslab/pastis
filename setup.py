#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="pastis-aflpp",
    version="0.2",
    description="Pastis AFLPP driver",
    packages=find_packages(),
    install_requires=[
        "click",
        "coloredlogs",
        "watchdog",
    ],
    scripts=['bin/pastis-aflpp']
)
