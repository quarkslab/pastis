#!/usr/bin/env python3

import sys
import json
from pathlib import Path
from dataclasses import dataclass, field
import copy
import logging

@dataclass
class CovData(object):
    count: int = 0         # Total number of items
    covered: int = 0       # Number of covered items
    not_covered: int = 0   # Number of not covered items
    percent: int = 0       # Coverage percentage
    has_data: bool = False # Whether this data has been set or not

    def improved(self, other: 'CovData') -> bool:
        """
        Compare with another CovData and return True if this one is improved.
        """
        if not self.has_data and not other.has_data:
            return False
        elif not self.has_data and other.has_data:
            return True
        return self.covered < other.covered

    def diff(self, other: 'CovData') -> 'CovData':
        """
        Compute the difference between this CovData and another one.
        Returns a new CovData with the numeric differences.

        In the "set" sense, it performs: self - other
        """
        if self.has_data and not other.has_data:
            return copy.copy(self)
        elif not self.has_data and other.has_data:
            return copy.copy(other)
        elif self.has_data and other.has_data:
            return CovData(
                count=self.count,  # not meant to change
                covered=self.covered - other.covered,
                not_covered=self.not_covered - other.not_covered,
                percent=self.percent - other.percent,
                has_data=True
            )
        else:
            assert False, "Both CovData objects have no data, cannot compute diff"

@dataclass
class File(object):
    filename: str
    summary: dict[str, CovData] = field(default_factory=dict)

@dataclass
class Function(object):
    name: str
    filenames: list[str]
    count: int
    # branches
    # regions
    # mcdc_records

@dataclass
class CovSummary(object):
    functions: CovData = field(default_factory=CovData)
    regions: CovData   = field(default_factory=CovData)
    lines: CovData     = field(default_factory=CovData)
    instantiations: CovData = field(default_factory=CovData)
    branches: CovData  = field(default_factory=CovData)
    mcdc: CovData      = field(default_factory=CovData)

    def improve_coverage(self, other: 'CovSummary') -> bool:
        """
        Compare with another coverage summary and return True if this one is improved.
        """
        for attr in self.__dataclass_fields__.keys():
            if getattr(self, attr).improved(getattr(other, attr)):
                return True
        return False

    @staticmethod
    def from_json(cov_file: Path | str) -> 'CovSummary':
        raw_json = json.loads(Path(cov_file).read_text())
        data: list = raw_json['data']
        assert len(data) == 1, "Data list has more than one item"
        if len(data) > 1:
            print(f"[red]Warning:[/red] Coverage file contains multiple data entries, only the first will be used.")
        
        # File summary infos
        summary = CovSummary()
        for name, item in data[0]['totals'].items():
            count = item['count']
            covered = item['covered']
            not_covered = item['notcovered'] if 'notcovered' in item else -1
            percent = item['percent']
            setattr(summary, name, CovData(count, covered, not_covered, percent, has_data=True))
        return summary

    def diff(self, other: 'CovSummary') -> 'CovSummary':
        """
        Compute the difference between this summary and another one.
        Returns a new CovSummary with the numeric differences.

        In the "set" sense, it performs: self - other
        """
        diff = CovSummary()
        for attr in self.__dataclass_fields__.keys():
            self_data = getattr(self, attr)
            other_data = getattr(other, attr)
            setattr(diff, attr, self_data.diff(other_data))
        return diff

    def to_json(self) -> str:
        """
        Compute the difference between this summary and another one.
        Returns a new CovSummary with the numeric differences.

        In the "set" sense, it performs: self - other
        """
        return json.dumps({k: getattr(self, k).__dict__ for k in self.__dataclass_fields__.keys()})


@dataclass
class ProfileCoverageFile(object):
    """
    JSON representation of a ProfData coverage file.
    """
    version: str
    type: str
    summary: CovSummary = field(default_factory=CovSummary)
    files: list[File] = field(default_factory=list)
    functions: list[Function] = field(default_factory=list)

    @staticmethod
    def from_json(cov_file: Path | str) -> 'ProfileCoverageFile':
        raw_json = json.loads(Path(cov_file).read_text())

        typ = raw_json['type']
        version = raw_json['version']
        data: list = raw_json['data']
        assert len(data) == 1, "Data list has more than one item"

        coverage = ProfileCoverageFile(version=version, type=typ)

        if len(data) > 1:
            print(f"[red]Warning:[/red] Coverage file contains multiple data entries, only the first will be used.")

        totals = data[0]['totals']

        # File summary infos
        summary = CovSummary()
        for name, item in totals.items():
            count = item['count']
            covered = item['covered']
            not_covered = item['notcovered'] if 'notcovered' in item else -1
            percent = item['percent']
            setattr(summary, name, CovData(count, covered, not_covered, percent, has_data=True))
        coverage.summary = summary


        # Parse all files data
        files = data[0]['files']
        for file in files:
            file_obj = File(filename=file['filename'])
            for info, item in file['summary'].items():
                count = item['count']
                covered = item['covered']
                not_covered = item['notcovered'] if 'notcovered' in item else -1
                percent = item['percent']
                file_obj.summary[info] = CovData(count, covered, not_covered, percent)
            coverage.files.append(file_obj)

        # Parse all functions data
        functions = data[0]['functions']
        for func in functions:
            func_obj = Function(name=func['name'], filenames=func['filenames'], count=func['count'])
            coverage.functions.append(func_obj)

        return coverage
