#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Installation of the pastis-dse module."""

import sys
from setuptools import setup, find_packages

setup(
    name="pastis-benchmark",
    version="0.1",
    description="An utility to perform benchmark",
    packages=find_packages(),
    setup_requires=[],
    install_requires=["click",
                      "coloredlogs",
                      "python-magic",
                      "quokka-project",
                      "pydantic",
                      "matplotlib"
                      # "libpastis @ git+ssh://gitlab@gitlab.qb/pastis/core/libpastis.git",
                      # "klocwork @ git+ssh://gitlab@gitlab.qb/pastis/core/klocwork.git",
                      # "tritondse @ git+ssh://gitlab@gitlab.qb/pastis/core/tritondse.git",
                      # "pastis-broker @ git+ssh://gitlab@gitlab.qb/pastis/core/pastis-broker.git",
                      # # pastis-triton (with broker addon)
                      # "pastis-dse @ git+ssh://gitlab@gitlab.qb/pastis/engines/pastis-dse.git",
                      # "pastis-dse-broker-addon @ git+ssh://gitlab@gitlab.qb/pastis/engines/pastis-dse.git#egg=pkg&subdirectory=broker-addon",
                      # # pastis-hongfuzz (with broker addon)
                      # "pastis-hf @ git+ssh://gitlab@gitlab.qb/pastis/engines/hf-wrapper.git",
                      # "hfwrapper-broker-addon @ git+ssh://gitlab@gitlab.qb/pastis/engines/hf-wrapper.git#egg=pkg&subdirectory=broker-addon",
                      # # pastis-afl++ (with broker addon)
                      # "pastis-aflpp @ git+ssh://gitlab@gitlab.qb/pastis/engines/pastis-aflpp.git",
                      # "pastis-aflpp-broker-addon @ git+ssh://gitlab@gitlab.qb/pastis/engines/pastis-aflpp.git#egg=pkg&subdirectory=broker-addon",
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
    scripts=["bin/pastis-benchmark"]
)
