#!/usr/bin/env python

"""Installation of the pastis-dse broker addon module."""

import sys
from setuptools import setup, find_packages

setup(
    name="pastis-dse-broker-addon",
    version="0.3",
    description="The broker addon for Pastis-DSE",
    packages=find_packages(),
    setup_requires=[],
    install_requires=["lief"],
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
