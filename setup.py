#!/usr/bin/env python3
# coding: utf-8
"""Installation script for PASTIS."""

from setuptools import setup

with open("README.md") as f:
    lines = f.readlines()
    README = "\n".join(lines[4:7]+lines[51:])


setup(
    name="pastis-framework",
    version="1.0.12",
    description="PASTIS framework for collaborative fuzzing",
    long_description=README,
    long_description_content_type='text/markdown',
    python_requires='>=3.9',
    packages=[
        "libpastis",
        "libpastis.proto",
        "pastisbroker",
        "pastisbenchmark",
        "pastisaflpp",
        "pastishf",
        "pastisdse",
    ],
    package_dir={
        # AFL++
        "pastisaflpp": "engines/pastisaflpp",
        # Honggfuzz
        "pastishf": "engines/pastishf",
        # Triton
        "pastisdse": "engines/pastisdse",
    },
    url="https://github.com/quarkslab/pastis",
    project_urls={
        "Documentation": "https://quarkslab.github.io/pastis/",
        "Bug Tracker": "https://github.com/quarkslab/pastis/issues",
        "Source": "https://github.com/quarkslab/pastis"
    },
    setup_requires=[],
    install_requires=[
        "protobuf",
        "pyzmq",
        "psutil",
        "aenum",
        "lief>=v0.14.0",
        "python-magic",
        "click",
        "coloredlogs",
        "quokka-project",
        "watchdog",
        "pydantic",
        "matplotlib",
        "joblib",
        "rich",
        "tritondse>=v0.1.11",
    ],
    tests_require=[],
    license="AGPL-3.0",
    author="Quarkslab",
    classifiers=[
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
    ],
    test_suite="",
    entry_points={
        "console_scripts": [
            "pastis-aflpp = pastisaflpp.__main__:main",
            "pastis-honggfuzz = pastishf.__main__:main",
            "pastis-triton = pastisdse.__main__:main"
        ]
    },
    scripts=[
        'bin/pastis-broker',
        'bin/pastis-benchmark',
        'bin/pastisd',
    ]
)
