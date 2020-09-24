#!/usr/bin/env python3
# coding: utf-8
"""Installation script for the pastis-broker."""

import sys
from setuptools import setup, find_packages

setup(
    name="pastis-broker",
    version="0.1",
    description="PASTIS broker that perform the proxy between all fuzzing engines",
    packages=find_packages(),
    setup_requires=[],
    install_requires=["click", "lief"],
    tests_require=[],
    license="qb",
    author="Quarkslab",
    classifiers=[
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
    ],
    test_suite="",
    scripts=['bin/pastis-broker']
)
