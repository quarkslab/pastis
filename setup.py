#!/usr/bin/env python3
# coding: utf-8
"""Installation script for the libpastis module."""

import sys
from setuptools import setup, find_packages

setup(
    name="libpastis",
    version="0.2",
    description="Python API to enable communication between PASTIS components",
    packages=find_packages(),
    setup_requires=[],
    install_requires=["protobuf", "pyzmq", "psutil", "aenum", "lief", "python-magic"],
    tests_require=[],
    license="qb",
    author="Quarkslab",
    classifiers=[
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
    ],
    test_suite=""
)
