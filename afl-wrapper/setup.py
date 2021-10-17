#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="aflwrapper",
    version="0.2",
    description="AFL++ wrapper",
    packages=find_packages(),
    install_requires=[
        "inotify",
        "coloredlogs",
        "click"
    ],
    scripts=['bin/pastis-afl']
)
