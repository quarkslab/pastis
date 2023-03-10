#!/usr/bin/env python3
# coding: utf-8
<<<<<<< HEAD
"""Installation script for PASTIS."""
=======
"""Installation script for the libpastis module."""
>>>>>>> pastisd/master

import sys
from setuptools import setup, find_packages

setup(
<<<<<<< HEAD
    name="pastis",
    version="0.2.1",
    description="PASTIS framework for collaborative fuzzing",
    packages=find_packages(),
    setup_requires=[],
    install_requires=[
        "protobuf",
        "pyzmq",
        "psutil",
        "aenum",
        "lief",
        "python-magic"
        "click",
        "coloredlogs",
        "quokka-project",
    ],
    tests_require=[],
    license="qb",
    author="Quarkslab",
    classifiers=[
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
    ],
    test_suite="",
    scripts=[
        'bin/pastis-broker',
        'bin/pastisd',
    ]
)
