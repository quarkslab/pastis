#!/usr/bin/env python3
# coding: utf-8
"""Installation script for PASTIS."""

import sys
from setuptools import setup, find_packages

setup(
    name="pastis-framework",
    version="1.0.0",
    description="PASTIS framework for collaborative fuzzing",
    packages=[
        "libpastis",
        "libpastis.proto",
        "pastisbroker",
        "pastisbenchmark",
        "pastisaflpp",
        "aflppbroker",
        "pastishf",
        "hfbroker",
        "pastisdse",
        "pastisttbroker"
    ],
    package_dir={
        # AFL++
        "pastisaflpp": "engines/pastis-aflpp/pastisaflpp",
        "aflppbroker": "engines/pastis-aflpp/broker-addon/aflppbroker",
        # Honggfuzz
        "pastishf": "engines/pastis-honggfuzz/pastishf",
        "hfbroker": "engines/pastis-honggfuzz/broker-addon/hfbroker",
        # Triton
        "pastisdse": "engines/pastis-triton/pastisdse",
        "pastisttbroker": "engines/pastis-triton/broker-addon/pastisttbroker"
    },
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
        "joblib",
        "rich"
        "tritondse",
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
