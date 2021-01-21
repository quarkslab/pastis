#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="hfwrapper",
    version="0.2",
    description="Honggfuzz wrapper",
    packages=find_packages(),
    install_requires=[
        "inotify",
        "coloredlogs",
        "click"
    ],
    scripts=['bin/pastis-honggfuzz']
)
