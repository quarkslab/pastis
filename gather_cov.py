import subprocess, os, tempfile, json
import matplotlib.pyplot as plt
# TEST
import plotly.express as px
import pandas as pd

from datetime import datetime
from pathlib import Path
from dataclasses import dataclass

from tritondse import CoverageStrategy
from tritondse.trace import QBDITrace

# If True, trace instructions and basic blocks
# If False, only trace edges
# This incures a slowdown (~ *2.5)
TRACE_INST = True

#import logging; logging.basicConfig(level=logging.DEBUG)

# Change this:
#TARGET = "libjpeg"
#HARNESS = "libjpeg_turbo_fuzzer_tt"
#TARGET = "freetype"
#HARNESS = "ftfuzzer_tt"
#TARGET = "harfbuzz"
#HARNESS = "hb-shape-fuzzer_tt"
#TARGET = "libpng"
#HARNESS = "libpng_read_fuzzer_tt"
#TARGET = "jsoncpp"
#HARNESS = "jsoncpp_fuzzer_tt"
#TARGET = "zlib"
#HARNESS = "zlib_uncompress_fuzzer_tt"
#TARGET = "openthread"
#HARNESS = "ip6-send-fuzzer_tt"
TARGET = "vorbis"
HARNESS = "decode_fuzzer_tt"

#BINARY = f"/home/rac/bench/z3_bitwuzla/{TARGET}/bins/{HARNESS}"
#PASTIS_CORPUS_AFL = f"/home/rac/bench/z3_bitwuzla/{TARGET}/results/pastis_z3/corpus"
#RES_AFL = f"/home/rac/bench/z3_bitwuzla/{TARGET}/results/res_{TARGET}_afl"
#PASTIS_CORPUS_COMBO = f"/home/rac/bench/z3_bitwuzla/{TARGET}/results/pastis_bit/corpus"
#RES_COMBO = f"/home/rac/bench/z3_bitwuzla/{TARGET}/results/res_{TARGET}_combo"

BINARY = f"/home/rac/bench/{TARGET}/bins/{HARNESS}"

AFL = f"/home/rac/bench/{TARGET}/results/afl_bitwuzla/corpus"
RES_AFL = f"/home/rac/bench/{TARGET}/results/res_{TARGET}_afl"
AFL_CMPLOG = f"/home/rac/bench/{TARGET}/results/afl_cmplog_bitwuzla/corpus"
RES_AFL_CMPLOG = f"/home/rac/bench/{TARGET}/results/res_{TARGET}_afl_cmplog"
AFL_TT = f"/home/rac/bench/{TARGET}/results/afl_tt_bitwuzla/corpus"
RES_AFL_TT = f"/home/rac/bench/{TARGET}/results/res_{TARGET}_afl_tt"
AFL_TT_CMPLOG = f"/home/rac/bench/{TARGET}/results/afl_tt_cmplog_bitwuzla/corpus"
RES_AFL_TT_CMPLOG = f"/home/rac/bench/{TARGET}/results/res_{TARGET}_afl_tt_cmplog"

Z3 = f"/home/rac/bench/{TARGET}/results/tt_z3/corpus"
RES_Z3 = f"/home/rac/bench/{TARGET}/results/res_{TARGET}_z3"
BITW = f"/home/rac/bench/{TARGET}/results/tt_bitwuzla/corpus"
RES_BITW = f"/home/rac/bench/{TARGET}/results/res_{TARGET}_bitw"

PASTIS_CORPUS_AFL = f"/home/rac/bench/{TARGET}/results_2/pastis_afl/corpus"
PASTIS_CORPUS_AFL = f"/home/rac/bench/libpng/results/test"
RES_AFL = f"/home/rac/bench/{TARGET}/results_2/res_{TARGET}_afl"
PASTIS_CORPUS_COMBO = f"/home/rac/bench/{TARGET}/results_2/pastis_combo/corpus"
RES_COMBO = f"/home/rac/bench/{TARGET}/results_2/res_{TARGET}_combo"


# NOTE For this script to work, we assume that the inputs are in chronological order in 
# the corpus_path. This is the case with pastis's output directory.
# The utility function move_seeds, prepends the seed with "00" so that they appear at the start.

class CampaignResults():
    def __init__(self, target: str, binary_path: str, corpus_path: str, output_path: str):
        self.target = target
        self.binary_path = binary_path
        self.corpus_path = corpus_path
        self.output_path = output_path
        self.stat_items = []

        # Internal: keep track of the seeds because they follow a different naming
        # scheme.
        self._seeds = None

        # Global branch coverage
        self._global_cov_edge = set()
        # Global inst coverage
        self._global_cov_inst = set()

    # Use QBDI to trace a single file and collect edge coverage
    # Updates self._global_cov by adding the newly discovered edges
    def trace_file(self, filepath):
        coverage_edge = None
        coverage_inst = None
        trace = QBDITrace.run(CoverageStrategy.EDGE,
                              BINARY,
                              [filepath],
                              stdin_file=filepath,
                              cwd=Path(BINARY).parent)
        coverage_edge = trace.get_coverage()

        unique_cov = coverage_edge.covered_items.keys() - self._global_cov_edge

        for item in coverage_edge.covered_items:
            self._global_cov_edge.add(item)


        covered_insts, unique_insts = (0, set())

        if TRACE_INST:
            coverage_inst = None
            trace = QBDITrace.run(CoverageStrategy.BLOCK,
                                  BINARY,
                                  [filepath],
                                  stdin_file=filepath,
                                  cwd=Path(BINARY).parent)
            coverage_inst = trace.get_coverage()

            unique_cov_inst = coverage_inst.covered_instructions.keys() - self._global_cov_inst

            for inst in coverage_inst.covered_instructions:
                self._global_cov_inst.add(inst)
            print((len(coverage_inst.covered_instructions), len(self._global_cov_inst), len(unique_cov_inst)))
            covered_insts, unique_insts = (len(coverage_inst.covered_instructions), unique_cov_inst)


        return len(coverage_edge.covered_items), unique_cov, covered_insts, unique_insts

    def replay_inputs(self):
        os.chdir(self.corpus_path)
        files = filter(os.path.isfile, os.listdir(self.corpus_path))
        files = [os.path.join("", f) for f in files] # add path to each file
        files.sort()

        n_files = len(files)
        for i, f in enumerate(files):
            print(f"{i+1}/{n_files}  --  {f}")
            elapsed, fuzzer = parse_filename(f)
            edges, unique_edges, insts, unique_insts = self.trace_file(os.path.join(self.corpus_path, f))
            statitem = StatItem(elapsed, f, 

                    edges, 
                    len(self._global_cov_edge), 
                    len(unique_edges), 

                    insts, 
                    len(self._global_cov_inst),
                    len(unique_insts), 

                    fuzzer, 
                    unique_edges,
                    unique_insts)
            print(statitem)
            self.stat_items.append(statitem)

    def to_json(self):
        data = {
                "target" : self.target,
                "binary_path" : self.binary_path,
                "corpus_path" : self.corpus_path,
                "output_path" : self.output_path,
                "stat_items" : [x.to_dict() for x in self.stat_items],
                }
        return json.dumps(data, indent=2)

    def process(self):
        self.replay_inputs()
        with open(self.output_path, "w") as fd:
            fd.write(self.to_json())

    # Read a CampaignResult from a json file (created wiht to_json)
    def from_file(filepath):
        with open(filepath, "r") as fd:
            data = json.load(fd)

        res = CampaignResults(data["target"], 
                            data["binary_path"], 
                            data["corpus_path"], 
                            data["output_path"])

        res.stat_items = [StatItem.from_dict(x) for x in data["stat_items"]]
        return res


    def add_to_plot(self, ax, label, annotate_tt=False):
        X = [x.time_elapsed for x in  self.stat_items]
        Y = [x.total_coverage_insts for x in  self.stat_items]
        #Y = [x.total_coverage for x in  self.stat_items]
        F = [x.fuzzer for x in  self.stat_items]

        ax.plot(X, Y, label=label)

        if annotate_tt:
            T, Y = find_tt_inp(X, Y, F)
            ax.plot(T, Y, 'bo', label="TT input")



@dataclass
class StatItem():
    time_elapsed: float
    # Name of the input file
    input_name: str
    # The coverage of this one input (len(covered_items))
    coverage: int
    # The total coverage of the fuzz campaign at this point
    total_coverage: int
    # len of coverage found by this seed that was not previsouly hit (not in global_coverage)
    unique_coverage_len: int


    coverage_insts: int
    total_coverage_insts: int
    unique_coverage_len_insts: int

    # The fuzzer that found that input
    fuzzer: str
    # Coverage found by this seed that was not previsouly hit (not in global_coverage)
    unique_coverage: set
    unique_coverage_insts: set

    def to_dict(self):
        data = {
                "time_elapsed": self.time_elapsed,
                "input_name": self.input_name, 
                "coverage": self.coverage, 
                "total_coverage": self.total_coverage,
                "unique_coverage_len": self.unique_coverage_len,

                "coverage_insts": self.coverage_insts, 
                "total_coverage_insts": self.total_coverage_insts,
                "unique_coverage_len_insts": self.unique_coverage_len_insts,

                "fuzzer": self.fuzzer,
                "unique_coverage": list(self.unique_coverage),
                "unique_coverage_insts": list(self.unique_coverage),
                }
        return data

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)

    def __str__(self):
        data = {
                "time_elapsed": self.time_elapsed,
                "input_name": self.input_name, 
                "coverage": self.coverage, 
                "total_coverage": self.total_coverage,
                "unique_coverage_len": self.unique_coverage_len,

                "coverage_insts": self.coverage_insts, 
                "total_coverage_insts": self.total_coverage_insts,
                "unique_coverage_len_insts": self.unique_coverage_len_insts,

                "fuzzer": self.fuzzer,
                }
        return json.dumps(data, indent=2)

    def from_dict(data: dict):
        return StatItem(data["time_elapsed"], 
                data["input_name"], 
                data["coverage"], 
                data["total_coverage"], 
                data["unique_coverage_len"], 

                data["coverage_insts"], 
                data["total_coverage_insts"], 
                data["unique_coverage_len_insts"], 

                data["fuzzer"],
                data["unique_coverage"], 
                data["unique_coverage_insts"], 
                )


def find_tt_inp(X, Y, F):
    t = []
    y = []
    for i in range(len(X)):
        if F[i] and "TT" in F[i]:
            t.append(X[i])
            y.append(Y[i])

    return t, y

# Parse a Pastis filename and return the time and the name of the fuzzer which found the input
def parse_filename(filename):
    if "seed" in filename:
        return 0, None
    info = filename.split("_")
    try: 
        t, elapsed, fuzzer = info[1], info[2], info[3]
        h,m,s = [float(i) for i in elapsed.split(":")]
        e = h*3600 + m*60 + s
    except: # seeds
        e, fuzzer = 0, ""

    return e, fuzzer


def move_seeds(dirpath):
    c = 0
    for file in os.listdir(dirpath):
        if file.startswith("2022"): continue
        filepath = f"{dirpath}/{file}"
        new_path = f"{dirpath}/00_SEED_{c}"
        c += 1
        print(f"moving {filepath} to {new_path}")
        os.system(f"mv {filepath} {new_path}")

def find_longjmp_plt(binary_path):
    try:
        proc1 = subprocess.Popen(['objdump', '-D', f'{binary_path}'], stdout=subprocess.PIPE)
        proc2 = subprocess.Popen(['grep', '<longjmp@plt>:'], stdin=proc1.stdout,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc1.stdout.close() # Allow proc1 to receive a SIGPIPE if proc2 exits.
        out, err = proc2.communicate()
        return int(out.split()[0], 16)
    except:
        return 0



def replay(target, binary, corpus, res_file):
    move_seeds(corpus)
    campaign = CampaignResults(target, binary, corpus, res_file)
    campaign.process()
    return campaign

if __name__ == "__main__":
    # TODO This is very hacky. 
    # QBDITrace doesn't work if the program calls longjmp. Because of this we hook longjmp@plt and
    # exit if reached. QBDITrace expects the address of lonjmp@plt to be in the 
    # env["TT_LONGJMP_ADDR"]. Would be nice to have something more robust.
    longjmp_plt = find_longjmp_plt(BINARY)
    print(hex(longjmp_plt))
    os.environ["TT_LONGJMP_ADDR"] = str(longjmp_plt)


    # TEST
#    z3 = None
#    bitw = None 
#
#    z3 = CampaignResults.from_file(RES_Z3)
#    bitw = CampaignResults.from_file(RES_BITW)
#
#    try:
#        z3 = CampaignResults.from_file(RES_Z3)
#        bitw = CampaignResults.from_file(RES_BITW)
#    except: 
#        pass
#
#    # Replay the inputs found by Z3
#    if not z3:
#        move_seeds(Z3)
#        z3 = CampaignResults(TARGET, BINARY, Z3, RES_Z3)
#        z3.process()
#
#    # Replay the inputs found by Z3 + Triton
#    if not bitw:
#        move_seeds(BITW)
#        bitw = CampaignResults(TARGET, BINARY, BITW, RES_BITW)
#        bitw.process()
#
#    # Plots using matplotlib
#    fig, (ax1, ax2) = plt.subplots(1, 2)
#
#    bitw.add_to_plot(ax1, "afl_tt", True)
#    ax1.set_title(f"{TARGET}")
#    z3.add_to_plot(ax1, "afl", False)
#    ax1.set(xlabel='seconds', ylabel='coverage (edge)')
#    ax1.legend()
#
#
#    bitw.add_to_plot(ax2, "afl_tt", True)
#    z3.add_to_plot(ax2, "afl", False)
#    ax2.set_title(f"{TARGET} (logscale)")
#    ax2.set(xlabel='seconds', ylabel='coverage (edge)')
#    ax2.legend()
#    ax2.set_xscale("log")
#
#    plt.show()
#    exit()
#    # endTEST

    # TEST 
    afl = None
    afl_cmplog = None
    afl_tt = None
    afl_tt_cmplog = None

    try:
        afl = CampaignResults.from_file(RES_AFL)
        afl_cmplog = CampaignResults.from_file(RES_AFL_CMPLOG)
        afl_tt = CampaignResults.from_file(RES_AFL_TT)
        afl_tt_cmplog = CampaignResults.from_file(RES_AFL_TT_CMPLOG)
    except: 
        pass

    # Replay the inputs found by AFL
    if not afl:
        afl = replay(TARGET, BINARY, AFL, RES_AFL)
    if not afl_cmplog:
        afl_cmplog = replay(TARGET, BINARY, AFL_CMPLOG, RES_AFL_CMPLOG)
    if not afl_tt:
        afl_tt = replay(TARGET, BINARY, AFL_TT, RES_AFL_TT)
    if not afl_tt_cmplog:
        afl_tt_cmplog = replay(TARGET, BINARY, AFL_TT_CMPLOG, RES_AFL_TT_CMPLOG)

    # Plots using matplotlib
    fig, (ax1, ax2) = plt.subplots(1, 2)

    afl.add_to_plot(ax1, "afl", False)
    afl_cmplog.add_to_plot(ax1, "afl_cmplog", False)
    afl_tt.add_to_plot(ax1, "afl_tt", True)
    afl_tt_cmplog.add_to_plot(ax1, "afl_tt_cmplog", True)
    ax1.set_title(f"{TARGET}")
    ax1.set(xlabel='seconds', ylabel='coverage (edge)')
    ax1.legend()


    afl.add_to_plot(ax2, "afl", False)
    afl_cmplog.add_to_plot(ax2, "afl_cmplog", False)
    afl_tt.add_to_plot(ax2, "afl_tt", True)
    afl_tt_cmplog.add_to_plot(ax2, "afl_tt_cmplog", True)
    ax2.set_title(f"{TARGET} (logscale)")
    ax2.set(xlabel='seconds', ylabel='coverage (edge)')
    ax2.legend()
    ax2.set_xscale("log")

    plt.show()
    exit()
    # endTEST


    campaign_afl = None
    campaign_combo = None 

    try:
        campaign_afl = CampaignResults.from_file(RES_AFL)
        campaign_combo = CampaignResults.from_file(RES_COMBO)
    except: 
        pass

    # Replay the inputs found by AFL
    if not campaign_afl:
        move_seeds(PASTIS_CORPUS_AFL)
        campaign_afl = CampaignResults(TARGET,
                        BINARY,
                        PASTIS_CORPUS_AFL,
                        RES_AFL)
        campaign_afl.process()

    # Replay the inputs found by AFL + Triton
    if not campaign_combo:
        move_seeds(PASTIS_CORPUS_COMBO)
        campaign_combo = CampaignResults(TARGET,
                        BINARY,
                        PASTIS_CORPUS_COMBO,
                        RES_COMBO)
        campaign_combo.process()


    # Plots using matplotlib
    fig, (ax1, ax2) = plt.subplots(1, 2)

    campaign_combo.add_to_plot(ax1, "afl_tt", True)
    ax1.set_title(f"{TARGET}")
    campaign_afl.add_to_plot(ax1, "afl", False)
    ax1.set(xlabel='seconds', ylabel='coverage (edge)')
    ax1.legend()


    campaign_combo.add_to_plot(ax2, "afl_tt", True)
    campaign_afl.add_to_plot(ax2, "afl", False)
    ax2.set_title(f"{TARGET} (logscale)")
    ax2.set(xlabel='seconds', ylabel='coverage (edge)')
    ax2.legend()
    ax2.set_xscale("log")

    plt.show()


    # Plots using plotly

#    X = [x.time_elapsed for x in  campaign_combo.stat_items]
#    Y = [x.total_coverage for x in  campaign_combo.stat_items]
#    F = [x.fuzzer for x in  campaign_combo.stat_items]
#    df = pd.DataFrame({'x_data':X, 'y_data':Y})
#    fig = px.line(df, x='x_data', y='y_data', title="Testing")
#    fig.show()
