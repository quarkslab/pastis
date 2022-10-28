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

#import logging; logging.basicConfig(level=logging.DEBUG)

# Change this:
TARGET = "libjpeg"
HARNESS = "libjpeg_turbo_fuzzer_tt"
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
#TARGET = "vorbis"
#HARNESS = "decode_fuzzer_tt"


BINARY = f"/home/rac/bench/{TARGET}/bins/{HARNESS}"
PASTIS_CORPUS_AFL = f"/home/rac/bench/{TARGET}/results/pastis_afl/corpus"
RES_AFL = f"/home/rac/bench/{TARGET}/results/res_{TARGET}_afl"
PASTIS_CORPUS_COMBO = f"/home/rac/bench/{TARGET}/results/pastis_combo/corpus"
RES_COMBO = f"/home/rac/bench/{TARGET}/results/res_{TARGET}_combo"


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

        self._global_cov = set()

    def find_seeds(self):
        self._seeds = []
        for file in os.listdir(self.corpus_path):
            if file.startswith("2022"): continue
            self._seeds.append(file)
            filepath = os.path.join(self.corpus_path, file)
            new= os.path.join(self.corpus_path, file)
            filepath = f"{dirpath}/{file}"
            new_path = f"{dirpath}/00_SEED_{c}"
            c += 1
            print(filepath)
            print(new_path)
            os.system(f"mv {filepath} {new_path}")


    # Use QBDI to trace a single file and collect edge coverage
    # Updates self._global_cov by adding the newly discovered edges
    def trace_file(self, filepath):
        coverage = None
        trace = QBDITrace.run(CoverageStrategy.EDGE,
                              BINARY,
                              [filepath],
                              stdin_file=filepath,
                              cwd=Path(BINARY).parent)
        coverage = trace.get_coverage()

        for item in coverage.covered_items:
            self._global_cov.add(item)

        return len(coverage.covered_items), len(self._global_cov)

    def replay_inputs(self):
        os.chdir(self.corpus_path)
        files = filter(os.path.isfile, os.listdir(self.corpus_path))
        files = [os.path.join("", f) for f in files] # add path to each file
        files.sort()

        n_files = len(files)
        for i, f in enumerate(files):
            print(f"{i}/{n_files}  --  {f}")
            elapsed, fuzzer = parse_filename(f)
            cov, global_cov = self.trace_file(os.path.join(self.corpus_path, f))
            statitem = StatItem(elapsed, cov, global_cov, fuzzer)
            print(statitem.to_json())
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
        Y = [x.total_coverage for x in  self.stat_items]
        F = [x.fuzzer for x in  self.stat_items]

        ax.plot(X, Y, label=label)

        if annotate_tt:
            T, Y = find_tt_inp(X, Y, F)
            ax.plot(T, Y, 'bo', label="TT input")



@dataclass
class StatItem():
    time_elapsed: float
    # The coverage of this one input (len(covered_items))
    coverage: int
    # The total coverage of the fuzz campaign at this point
    total_coverage: int
    # The fuzzer that found that input
    fuzzer: str

    def to_dict(self):
        data = {
                "time_elapsed": self.time_elapsed,
                "coverage": self.coverage, 
                "total_coverage": self.total_coverage,
                "fuzzer": self.fuzzer
                }
        return data

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)

    def from_dict(data: dict):
        return StatItem(data["time_elapsed"], 
                data["coverage"], 
                data["total_coverage"], 
                data["fuzzer"])


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
        print(filepath)
        print(new_path)
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

if __name__ == "__main__":
    # TODO This is very hacky. 
    # QBDITrace doesn't work if the program calls longjmp. Because of this we hook longjmp@plt and
    # exit if reached. QBDITrace expects the address of lonjmp@plt to be in the 
    # env["TT_LONGJMP_ADDR"]. Would be nice to have something more robust.
    longjmp_plt = find_longjmp_plt(BINARY)
    print(hex(longjmp_plt))
    os.environ["TT_LONGJMP_ADDR"] = str(longjmp_plt)


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
