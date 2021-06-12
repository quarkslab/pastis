#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Installation of the pastis-dse module."""

import sys
from setuptools import setup, find_packages

setup(
    name="pastis-dse",
    version="0.2",
    description="A library and utility using tritondse to perform PASTIS-related DSE",
    packages=find_packages(),
    setup_requires=[],
    install_requires=["click", "coloredlogs"],
    tests_require=[],
    license="qb",
    author="Quarkslab",
    classifiers=[
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
    ],
    test_suite="",
    scripts=["bin/pastis-triton"]
)
