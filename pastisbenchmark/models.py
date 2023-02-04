from typing import List

from pydantic import BaseModel

class InputEntry(BaseModel):
    engine: str
    number: int
    unique: int
    useless: int
    condition: int
    symread: int
    symwrite: int
    symjump: int

class CoverageEntry(BaseModel):
    engine: str
    number: int
    unique: int
    first: int
    total: int

class ExecEntry(BaseModel):
    engine: str
    dse: float
    smt: float
    replay: float
    total: float
    wait: float

class SeedSharingEntry(BaseModel):
    engine: str
    accepted: int
    rejected: int
    total: int
    ratio: float

class SmtEntry(BaseModel):
    engine: str
    sat: int
    unsat: int
    timeout: int
    total: int
    avg_query: float
    cov_sat_ratio: float
    branch_solved: int
    branch_not_solved: int


class CampaignStats(BaseModel):
    input_stats: List[InputEntry]
    coverage_stats: List[CoverageEntry]
    exec_stats: List[ExecEntry]
    seed_sharing_stats: List[SeedSharingEntry]
    smt_stats: List[SmtEntry]
