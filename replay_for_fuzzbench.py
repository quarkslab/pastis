import tempfile, os, subprocess, json, shutil
from math import ceil
from pathlib import Path
from typing import List

"""
This script takes a path to a -fsanizit-cov instrumented binary and a pastis workspace
and outputs a csv that has the same structure as FuzzBench results.
The goal being to integrate pastis results in a FuzzBench generated plot.

You can download the coverage binaries from 
http://commondatastorage.googleapis.com/fuzzbench-data/index.html?prefix=2022-04-22-aflpp/coverage-binaries/

This codes was adapted from https://github.com/google/fuzzbench/tree/master/experiment/measurer

We split the Pastis corpus in 15-min intervals and compute the coverage for each using the instrumented binaries.

"""

COVERAGE_BINARY = "./libjpeg_turbo_fuzzer"
CORPUS = "./corpus_libjpeg"


PROFDATA_FILE = "test.profdata"

# Time buffer for libfuzzer merge to gracefully exit.
EXIT_BUFFER = 15

# Memory limit for libfuzzer merge.
RSS_LIMIT_MB = 2048

# Per-unit processing timeout for libfuzzer merge.
UNIT_TIMEOUT = 10

# Max time to spend on libfuzzer merge.
MAX_TOTAL_TIME = 3600

def do_coverage_run(  # pylint: disable=too-many-locals
        coverage_binary: str, new_units_dir: List[str],
        profraw_file_pattern: str) -> List[str]:
    """Does a coverage run of |coverage_binary| on |new_units_dir|. Writes
    the result to |profraw_file_pattern|. Returns a list of crashing units."""
    with tempfile.TemporaryDirectory() as merge_dir:
        command = [
            coverage_binary, '-merge=1', '-dump_coverage=1',
            '-timeout=%d' % UNIT_TIMEOUT,
            '-rss_limit_mb=%d' % RSS_LIMIT_MB,
            '-max_total_time=%d' % (MAX_TOTAL_TIME - EXIT_BUFFER), merge_dir,
            new_units_dir
        ]
        coverage_binary_dir = os.path.dirname(coverage_binary)
        env = os.environ.copy()
        env['LLVM_PROFILE_FILE'] = profraw_file_pattern
        result = subprocess.run(command,
                                     env=env,
                                     cwd=coverage_binary_dir,
                                     timeout=MAX_TOTAL_TIME)

    if result.returncode != 0:
        logger.error('Coverage run failed.',
                     extras={
                         'coverage_binary': coverage_binary,
                         'output': result.output[-new_process.LOG_LIMIT_FIELD:],
                     })

def find_crashing_units(artifacts_dir: str) -> List[str]:
    """Returns the crashing unit in coverage_binary_output."""
    return [
        # This assumes the artifacts are named {crash,oom,timeout,*}-$SHA1_HASH
        # and that input units are also named with their hash.
        filename.split('-')[1]
        for filename in os.listdir(artifacts_dir)
        if os.path.isfile(os.path.join(artifacts_dir, filename))
    ]


def generate_coverage_information(profraw_files, profdata_file, coverage_binary, json_output):
    """Generate the .profdata file and then transform it into
    json summary."""
    generate_profdata([Path(profraw_files) / Path(x) for x in os.listdir(profraw_files)], profdata_file)
    generate_json_summary(coverage_binary, profdata_file, json_output)


def merge_profdata_files(src_files, dst_file):
    """Uses llvm-profdata to merge |src_files| to |dst_files|."""
    command = ['llvm-profdata-12', 'merge', '-sparse']
    command.extend(src_files)
    command.extend(['-o', dst_file])
    result = subprocess.run(command)
    return result


def generate_profdata(profraw_files, profdata_file):
    """Generate .profdata file from .profraw file."""
    files_to_merge = profraw_files
    if os.path.isfile(profdata_file):
        # If coverage profdata exists, then merge it with
        # existing available data.
        files_to_merge += [profdata_file]

    result = merge_profdata_files(files_to_merge, profdata_file)
    if result.returncode != 0:
        print('Coverage profdata generation failed for cycle: %d.', cycle)

def generate_json_summary(coverage_binary,
                          profdata_file,
                          output_file,
                          summary_only=True):
    """Generates the json summary file from |coverage_binary|
    and |profdata_file|."""
    command = [
        'llvm-cov', 'export', '-format=text', '-num-threads=1',
        '-region-coverage-gt=0', '-skip-expansions', coverage_binary,
        '-instr-profile=%s' % profdata_file
    ]

    if summary_only:
        command.append('-summary-only')

    with open(output_file, 'w') as dst_file:
        result = subprocess.call(command, stdout=dst_file)
    return result


def generate_json_cov(coverage_binary, corpus, profraw_dir, profdata_file, json_output):
    try:
        os.mkdir(profraw_dir)
    except: pass

    do_coverage_run(coverage_binary, 
            corpus, 
            f"{profraw_dir}/test-%m.cov"
            )

    generate_coverage_information(profraw_dir, profdata_file, coverage_binary, json_output)
    with open(json_output, "r") as fd:
        summary = json.load(fd)
        r = summary["data"][-1]["totals"]
    return r


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

# Split the corpus into 15 min cycles
def split_corpus(corpus):
    cycles = dict()
    for x in os.listdir(corpus):
        e, f = parse_filename(x)
        cycle = ceil(e) // (15*60)
        path = Path(corpus) / Path(x)
        if cycle not in cycles:
            cycles[cycle] = [path]
        else:
            cycles[cycle].append(path)

    for i in range(len(cycles)):
        if i not in cycles:
            cycles[i] = []
    return cycles


def gen_fuzzbench_json(coverage_binary, corpus, profdata_file):
    branches = []
    regions = []
    cov = []

    cycles = split_corpus(corpus)
    for i in range(len(cycles)):
        with tempfile.NamedTemporaryFile() as json_output:
            with tempfile.TemporaryDirectory() as crashes_dir:
                with tempfile.TemporaryDirectory() as profraw_dir:
                    with tempfile.TemporaryDirectory() as cycle_dir:
                        for p in cycles[i]:
                            shutil.copy(p, cycle_dir)

                        cov_info = generate_json_cov(coverage_binary, 
                                                    cycle_dir, 
                                                    profraw_dir, 
                                                    profdata_file, 
                                                    #f"{i}.profdata",
                                                    json_output.name)
                        branches.append(cov_info["branches"]["covered"])
                        regions.append(cov_info["regions"]["covered"])
                        cov.append(cov_info)
    return branches, regions

def to_csv(fuzzer, target, coverage):
    experiment_name = "myexp"
    for cycle, cov in enumerate(coverage):
        d = [cycle, "hash", "/tmp/experiment-data", experiment_name, fuzzer, target, "time", "", 1, 900*(cycle + 1), cov, "", "", 0]

        print(",".join([str(x) for x in d]))

if __name__ == "__main__":
    with tempfile.NamedTemporaryFile() as profdata_file:
        branches, regions = gen_fuzzbench_json(COVERAGE_BINARY, CORPUS, profdata_file.name)

    to_csv("pastis", "libjpeg-turbo-07-2017", regions)

    #import matplotlib.pyplot as plt
    #plt.plot([15*i for i in range(len(regions))], regions)
    #plt.show()

