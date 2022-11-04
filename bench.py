import subprocess, os
from time import sleep

BENCH_DIR = "/home/rac/bench"

# Change this 
#TARGET = "libpng"
#harness_name = "libpng_read_fuzzer"
TARGET = "openthread"
harness_name = "ip6-send-fuzzer"
#TARGET = "zlib"
#harness_name = "zlib_uncompress_fuzzer"

def run_instance(port, afl: bool, tt: bool, cmplog: bool, solver: str, hide_output=False):
    output_stream = subprocess.DEVNULL if hide_output else None

    pastis_corpus = ""
    if afl: pastis_corpus += "afl_"
    if tt: pastis_corpus += "tt_"
    if cmplog: pastis_corpus += "cmplog_"
    pastis_corpus += solver

    pastis = ["pastis-broker", 
            "-b", f"{BENCH_DIR}/{TARGET}/bins", 
            "--chkmode", "CHECK_ALL", 
            "--seed", f"{BENCH_DIR}/{TARGET}/seeds", 
            "--workspace", f"{BENCH_DIR}/{TARGET}/results/{pastis_corpus}", 
            "-p", f"{port}"]

    print(pastis)
    subprocess.Popen(pastis, stdout=output_stream, stderr=output_stream)

    if afl:
        afl = ["pastis-aflpp", "online", 
                "-p", f"{port}"]
        if cmplog: afl.append(f"-c {BENCH_DIR}/{TARGET}/cmplog/{harness_name}")
        subprocess.Popen(afl, stdout=output_stream, stderr=output_stream)


    if tt: 
        tt = ["pastis-triton", "online", 
                "-p", f"{port}",
                "-s", f"{solver}",
                "--workspace", f"{BENCH_DIR}/{TARGET}/results/{pastis_corpus}/ttdse"]
        print(tt)
        subprocess.Popen(tt, stdout=output_stream, stderr=output_stream)

if __name__ == "__main__":
    port = 4333
    run_instance(port,   afl=True, tt=False, cmplog=False, solver="bitwuzla")
    run_instance(port+1, afl=True, tt=True, cmplog=False, solver="bitwuzla")
    run_instance(port+2, afl=True, tt=False, cmplog=True, solver="bitwuzla")
    run_instance(port+3, afl=True, tt=True, cmplog=True, solver="bitwuzla")

    #run_instance(port,   afl=False, tt=True, cmplog=False, solver="z3")
    #run_instance(port+1, afl=False, tt=True, cmplog=False, solver="bitwuzla")
