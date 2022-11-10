import subprocess, os
from time import sleep

BENCH_DIR = "/home/rac/bench"

# Change this 
TARGET = "libpng"
# Name of the binary in `cmplog`
harness_name = "libpng_read_fuzzer"
#TARGET = "vorbis"
#harness_name = "decode_fuzzer"
#TARGET = "zlib"
#harness_name = "zlib_uncompress_fuzzer"
#TARGET = "harfbuzz"
#harness_name = "hb-shape-fuzzer"
#TARGET = "freetype"
#harness_name = "ftfuzzer"
#TARGET = "openthread"
#harness_name = "ip6-send-fuzzer"
#TARGET = "libjpeg"
#harness_name = "libjpeg_turbo_fuzzer"

#TARGET = "openthread"
#harness_name = "ip6-send-fuzzer"

def run_instance(port, afl: bool, tt: bool, cmplog: bool, solver: str, covmode="edge", hide_output=False):
    output_stream = subprocess.DEVNULL if hide_output else None

    pastis_corpus = ""
    if afl: pastis_corpus += "afl_"
    if tt: pastis_corpus += "tt_"
    if cmplog: pastis_corpus += "cmplog_"
    pastis_corpus += f"{covmode}_"
    pastis_corpus += solver

    pastis = ["pastis-broker", 
            "-b", f"{BENCH_DIR}/{TARGET}/bins", 
            "--chkmode", "CHECK_ALL", 
            "--seed", f"{BENCH_DIR}/{TARGET}/seeds", 
            #"--workspace", f"{BENCH_DIR}/{TARGET}/results_cov/{pastis_corpus}", 
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
                "-cov", f"{covmode}",
                #"--workspace", f"{BENCH_DIR}/{TARGET}/results_cov/{pastis_corpus}/ttdse"]
                "--workspace", f"{BENCH_DIR}/{TARGET}/results/{pastis_corpus}/ttdse"]
        print(tt)
        subprocess.Popen(tt, stdout=output_stream, stderr=output_stream)

if __name__ == "__main__":
    port = 4539
    run_instance(port,   afl=True, tt=False, cmplog=False, solver="bitwuzla")
    run_instance(port+1, afl=True, tt=True, cmplog=False, solver="bitwuzla")
    run_instance(port+2, afl=True, tt=False, cmplog=True, solver="bitwuzla")
    run_instance(port+3, afl=True, tt=True, cmplog=True, solver="bitwuzla")

    #run_instance(port,   afl=False, tt=True, cmplog=False, solver="z3")
    #run_instance(port+1, afl=False, tt=True, cmplog=False, solver="bitwuzla")

    #run_instance(port,     afl=False, tt=True, cmplog=False, solver="bitwuzla", covmode="edge")
    #run_instance(port+1,   afl=False, tt=True, cmplog=False, solver="bitwuzla", covmode="block")
    #run_instance(port+2,   afl=False, tt=True, cmplog=False, solver="bitwuzla", covmode="path")
    #run_instance(port+3,   afl=False, tt=True, cmplog=False, solver="bitwuzla", covmode="PREFIXED_EDGE")
