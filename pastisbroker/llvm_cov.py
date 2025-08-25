#!/usr/bin/env python3

import sys
import json
from pathlib import Path
from dataclasses import dataclass, field
import copy
import logging
from enum import IntEnum

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
        
        return CovSummary.from_dict(data[0]['totals'])

    @staticmethod
    def from_dict(data: dict) -> 'CovSummary':
        """
        Populate this CovSummary from a dictionary.
        The dictionary should have the same structure as the one returned by to_dict().
        """
        summary = CovSummary()
        for name, item in data.items():
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
        return json.dumps(self.to_dict())

    def to_dict(self) -> dict:
        """
        Compute the difference between this summary and another one.
        Returns a new CovSummary with the numeric differences.

        In the "set" sense, it performs: self - other
        """
        return {k: getattr(self, k).__dict__ for k in self.__dataclass_fields__.keys()}


class RegionKind(IntEnum):
    """
    Enum representing the different kinds of regions in a coverage file.
    """
    # A CodeRegion associates some code with a counter
    CodeRegion = 0
    # An ExpansionRegion represents a file expansion region that associates
    # a source range with the expansion of a virtual source file, such as
    # for a macro instantiation or #include file.
    ExpansionRegion = 1

    # A SkippedRegion represents a source range with code that was skipped
    # by a preprocessor or similar means.
    SkippedRegion = 2

    # A GapRegion is like a CodeRegion, but its count is only set as the
    # line execution count when its the only region in the line.
    GapRegion = 3

    # A BranchRegion represents leaf-level boolean expressions and is
    # associated with two counters, each representing the number of times the
    # expression evaluates to true or false.
    BranchRegion = 4

    # A DecisionRegion represents a top-level boolean expression and is
    # associated with a variable length bitmap index and condition number.
    MCDCDecisionRegion = 5

    # A Branch Region can be extended to include IDs to facilitate MC/DC.
    MCDCBranchRegion = 6



@dataclass
class Segment(object):
    """
    Represents a segment in a source file.
    A segment marks the beginning of a new region or gap
    at the given line and column. The current segment holds
    until the next segment changes it.
    """
    line: int
    column: int
    count: int
    has_count: bool  # Whether count is set (some areas are disable by means of compilation)
    is_region: bool
    is_gap: bool

@dataclass
class Branch(object):
    """
    Represents a branch in a source file.
    """
    line_start: int
    column_start: int
    line_end: int
    column_end: int
    execution_count: int
    false_execution_count: int
    file_id: int
    expanded_file_id: int
    kind: RegionKind

@dataclass
class Region(object):
    """
    Represents a region in a coverage function.
    """
    line_start: int
    column_start: int
    line_end: int
    column_end: int
    execution_count: int
    file_id: int
    expanded_file_id: int
    kind: RegionKind


@dataclass
class File(object):
    filename: str
    summary: CovSummary
    segments: list[Segment] = field(default_factory=list)
    # Segments are solely used to distinguish "coverable" areas
    # from gaps in the source code.
    branches: list[Branch] = field(default_factory=list)
    # Branches aggregate all branches info accross instantiations!
    # For a given if/else, there might multiple branches informations!

    # TODO: expansions
    # TODO: mcdc_records

@dataclass
class Function(object):
    name: str
    filenames: list[str]
    count: int
    branches: list[Branch] = field(default_factory=list)
    regions: list[Region] = field(default_factory=list)
    # mcdc_records


@dataclass
class ProfileCoverageFile(object):
    """
    JSON representation of a ProfData coverage file.
    """
    filename: str
    version: str
    type: str
    summary: CovSummary = field(default_factory=CovSummary)
    files: list[File] = field(default_factory=list)
    functions: list[Function] = field(default_factory=list)

    @staticmethod
    def from_json(cov_file: Path | str) -> 'ProfileCoverageFile':
        cov_file = Path(cov_file)
        raw_json = json.loads(cov_file.read_text())

        typ = raw_json['type']
        version = raw_json['version']
        data: list = raw_json['data']
        assert len(data) == 1, "Data list has more than one item"

        coverage = ProfileCoverageFile(filename=cov_file.name, version=version, type=typ)

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
            file_obj = File(filename=file['filename'],
                            summary=CovSummary.from_dict(file['summary']))
            coverage.files.append(file_obj)

            # Parse segments
            for segment in file['segments']:
                file_obj.segments.append(Segment(*segment))

            for branch in file['branches']:
                file_obj.branches.append(Branch(*branch))

            # TODO: Parse expansions data

            # TODO: mcdc_records

            

        # Parse all functions data
        functions = data[0]['functions']
        for func in functions:
            func_obj = Function(name=func['name'],
                                filenames=func['filenames'],
                                count=func['count'])

            # Parse branches data
            for branch in func['branches']:
                func_obj.branches.append(Branch(*branch))

            # Parse regions data
            for region in func['regions']:
                func_obj.regions.append(Region(*region))

            # TODO: mcdc_records
    
            coverage.functions.append(func_obj)

        return coverage
