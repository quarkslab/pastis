#!/usr/bin/env python3
# coding: utf-8
"""Installation script for PASTIS."""

import sys
from setuptools import setup, find_packages

setup(
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
        "python-magic",
        "click",
        "coloredlogs",
        "quokka-project",
        "watchdog",
        "pydantic",
        "matplotlib",
        "joblib"
        # To add
        # "tritondse",
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
        'bin/pastis-benchmark',
        'bin/pastisd',
        'engines/pastis-honggfuzz/bin/pastis-honggfuzz',
        'engines/pastis-triton/bin/pastis-triton',
        'engines/pastis-aflpp/bin/pastis-aflpp'
    ]
)
