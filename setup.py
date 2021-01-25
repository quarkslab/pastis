#!/usr/bin/env python3
# coding: utf-8
"""Installation script for the libpastis module."""

import sys
from setuptools import setup, find_packages

setup(
    name="pastisd",
    version="0.2",
    description="PASTIS deamon initializing connection with broker",
    packages=find_packages(),
    setup_requires=[],
    install_requires=["coloredlogs"],
    tests_require=[],
    license="qb",
    author="Quarkslab",
    classifiers=[
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
    ],
    test_suite="",
    scripts=['bin/pastisd']
)
