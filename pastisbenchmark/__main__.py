# built-in imports
import shutil

import os
import click
import sys
import logging
import json
from typing import Optional, Tuple
from pathlib import Path

# Thirs-party imports
import coloredlogs
import joblib

# Local imports
from pastisbroker import PastisBroker, BrokingMode
from pastisbroker.utils import load_engine_descriptor
from pastisbroker.workspace import Workspace
from libpastis.types import CheckMode, SeedInjectLoc

# Engines imports
from pastishonggfuzz import HonggfuzzDriver, spawn_online_honggfuzz
from pastisaflpp import spawn_online_aflpp, check_scaling_frequency
from pastistritondse import spawn_online_triton

from pastisbenchmark.replayer import ReplayType, Replayer
from pastisbenchmark.plotter import Plotter
from pastisbenchmark.results import CampaignResult

class Bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def pp_good(s: str) -> str:
    return Bcolors.OKGREEN + s + Bcolors.ENDC

def pp_bad(s: str) -> str:
    return Bcolors.FAIL + s + Bcolors.ENDC

def pp_warning(s: str) -> str:
    return Bcolors.WARNING + s + Bcolors.ENDC



def configure_logging(level: int, fmt="%(message)s"):
    logging.root.name = f"\033[7m\033[39m[ BROKER ]\033[0m"
    coloredlogs.install(level=level,
                        fmt=fmt,
                        level_styles={'debug': {'color': 'blue'}, # 10
                                      'info': {}, # 20
                                      'warning': {'color': 'yellow'},  # 30
                                      'success': {'bold': True, 'color': 'green'}, # 35
                                      'error': {'color': 'red'},
                                      'critical': {'bold': True, 'color': 'red'}})

def iterate_file(file):
    p = Path(file)
    if p.is_file():  # Add the seed file
        yield p
    elif p.is_dir():  # Add all file contained in the directory as triton configuration
        for sub_s in p.iterdir():
            yield sub_s


def iterate_seeds(root):
    root = Path(root)
    if root.is_file():
        yield root
    elif root.is_dir():
        for item in root.iterdir():
            if item.is_file():
                yield item
            elif item.is_dir():
                yield from iterate_seeds(item)


@click.group()
def cli():
    pass


@cli.command(context_settings=dict(show_default=True))
@click.argument('workspace', type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True))
def clean(workspace: str):
    p = Path(workspace)
    dirs = [Workspace.INPUT_DIR,
            Workspace.HANGS_DIR,
            Workspace.CRASH_DIR,
            Workspace.LOG_DIR,
            Workspace.BINS_DIR,
            Workspace.ALERTS_DIR,
            Workspace.SEED_DIR,
            Replayer.QBDI_REPLAY_DIR,
            CampaignResult.REPLAYS_DELTA,
            CampaignResult.COVERAGE_DIR,
            Plotter.PLOT_DIR,
            "clients_ws"]

    for file in (p / x for x in dirs):
        if file.exists():
            shutil.rmtree(file)

    files = [Workspace.SAST_REPORT_COPY,
             Workspace.CSV_FILE,
             Workspace.TELEMETRY_FILE,
             Workspace.CLIENTS_STATS,
             Workspace.LOG_FILE,
             Workspace.STATUS_FILE,
             Workspace.RUNTIME_CONFIG_FILE]

    for file in (p / x for x in files):
        file.unlink(missing_ok=True)


@cli.command(context_settings=dict(show_default=True))
@click.argument('bins', type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True))
def showmap(bins: str):

    MAP = {
              "Triton": "pastistritondse.addon",
              "Honggfuzz": "pastishonggfuzz.addon",
              "AFL++": "pastisaflpp.addon"
    }
    mapping = {k: load_engine_descriptor(v) for k,v in MAP.items()}
    for file in iterate_file(bins):
        print(file)
        for engine, desc in mapping.items():
            acc, exmode, fuzzmode = desc.accept_file(file)
            if acc:
                print(f"    - {engine} [{exmode.name}][{fuzzmode.name}]")


@cli.command(context_settings=dict(show_default=True))
@click.option('-w', '--workspace', type=click.Path(), default="workspace", help="Workspace directory to store data")
@click.option('-b', '--bins', type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True), required=True, help="Directory containing binaries")
@click.option('-s', '--seeds', type=click.Path(exists=True, file_okay=True, dir_okay=True, readable=True), help="Directory containing initial corpus")
@click.option('-m', '--mode', type=click.Choice([x.name for x in BrokingMode]), default=BrokingMode.FULL.name, help="Mode of broking")
@click.option('-i', '--injloc', type=click.Choice([x.name for x in list(SeedInjectLoc)]), default=SeedInjectLoc.STDIN.name, help="Seed injection location")
@click.option('--aflpp', is_flag=True, type=bool, default=False, help="Enable AFL++")
@click.option('--hfuzz', is_flag=True, type=bool, default=False, help="Enable Honggfuzz")
@click.option('--triton', is_flag=True, type=bool, help="Enable TritonDSE")
@click.option('--debug', type=bool,  is_flag=True, show_default=True, default=False, help='Enable debug logs')
@click.option('-t', "--timeout", type=int, default=None, help="Timeout of the campaign. Time after which stopping the campaign")
@click.option('-p', '--port', type=int, default=5555, help="Port to bind to", multiple=False)
@click.option('--hfuzz-path', type=click.Path(exists=True, file_okay=True, dir_okay=True, readable=True), required=False, help="Custom Honggfuzz path")
@click.option('--hfuzz-threads', type=int, default=0, help="Number of threads to launch Honggfuzz with")
@click.option('--spawn/--no-spawn', type=bool, is_flag=True, default=True, help="Either to spawn engines or not")
@click.option("--allow-remote", type=bool, is_flag=True, default=False, help="Enable remote connection")
@click.option('--probe', type=str, help="Probe to load as a python module (should contain a ProbeInterface)", multiple=True)
@click.option('--skip-cpufreq', is_flag=True, type=bool, default=False, help="Skip CPU frequency scaling check")
@click.option('--mem-threshold', type=int, default=85, help="RAM consumption limit", show_default=True)
@click.option('--start-quorum', type=int, default=0, help="Number of client connection to receive before triggering startup", show_default=True)
@click.option('--filter-inputs', type=bool, is_flag=True, default=False, help="Filter inputs that do not generate coverage", show_default=True)
@click.option('--stream', type=bool, is_flag=True, default=False, help="Stream input and coverage info in the given file", show_default=True)
@click.option('--replay-threads', type=int, default=4, help="number of threads to use for input replay", show_default=True)
@click.option('--replay-timeout', type=int, default=60, help="Timeout for seed replay", show_default=True)
@click.option('--proxy', type=str, default="", help="Run the broker as a proxy to another broker: pymodule@ip:port")
@click.argument('pargs', nargs=-1)
def run(workspace: str, bins: str, seeds: str, mode: str, injloc: str, aflpp: bool, hfuzz: bool, triton: bool,
        debug: bool, timeout: Optional[int], port: int, hfuzz_path: str, hfuzz_threads: int, spawn: bool,
        allow_remote: bool, probe: Tuple[str], skip_cpufreq: bool,  mem_threshold: int, start_quorum: int,  proxy: str,
        filter_inputs: bool, stream: bool, replay_threads: int, replay_timeout: int, pargs: Tuple[str]):

    configure_logging(logging.DEBUG if debug else logging.INFO, "%(asctime)s %(name)s [%(levelname)s] %(message)s")

    broker = PastisBroker(workspace,
                          bins,
                          BrokingMode[mode],
                          CheckMode.CHECK_ALL,
                          SeedInjectLoc[injloc],
                          None,
                          list(pargs),
                          mem_threshold,
                          start_quorum,
                          filter_inputs,
                          stream,
                          replay_threads,
                          replay_timeout)

    if proxy:  # proxy format should be:  IP:port@py_module
        try:
            py_module, url = proxy.split("@")
            proxy_ip, proxy_port = url.split(":")
            broker.set_proxy(proxy_ip, int(proxy_port), py_module)
        except ValueError:
            logging.error(f"Cannot parse proxy: {proxy}, format need to be: py_module@ip:port")
            return

    # Add all given seeds as initial seed
    if seeds is None:
        logging.warning("no initial corpus provided")
    else:
        for s in iterate_seeds(seeds):  # File if one file, or iterate dir if directory
            broker.add_seed_file(s, initial=True)

    ws_root = broker.workspace.root

    clients_ws = ws_root / "clients_ws"

    if clients_ws.exists():
        logging.error("benchmarks have already been runnned in that directory")
        sys.exit(1)
    else:
        clients_ws.mkdir()

    if aflpp:
        # create a workspace directory and launch it
        if not skip_cpufreq and not check_scaling_frequency():
            logging.error("CPU is not configured on performance (system uses on-demande CPU freq scaling)")
            logging.info("try: echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")
            sys.exit(1)
        aflpp_ws = clients_ws / "aflpp"
        aflpp_ws.mkdir()
        if spawn:
            spawn_online_aflpp(aflpp_ws, port)

    if hfuzz:
        # create a workspace directory and launch it
        hf_exe_path = None

        if not HonggfuzzDriver.honggfuzz_available() and hfuzz_path:
            hf_exe_path = hfuzz_path

        if not HonggfuzzDriver.honggfuzz_available():
            logging.error("Can't find custom Honggfuzz directory (please set HFUZZ_PATH, or --hfuzz-path variable)")
            sys.exit(1)
        else:  # Honggfuzz is available
            hf_ws = clients_ws / "hfuzz"
            hf_ws.mkdir()
            if spawn:
                spawn_online_honggfuzz(hf_ws, hf_exe_path, port, hfuzz_threads)

    # Look for configuration files, add them to the broker and launch as many triton instances
    tt_confs = ws_root / "triton_confs"
    if not tt_confs.exists():  # if folder is empty
        logging.info(f"{tt_confs} not found fall back current workdir")
        tt_confs = Path("triton_confs")
    broker.load_engine_addon("pastistritondse.addon")
    if tt_confs.exists():
        for i, conf in enumerate(sorted(tt_confs.iterdir())):
            with open(conf, "r+") as fd:
                tt_ws = clients_ws / f"ttdse_{i}"
                c = json.load(fd)
                c["workspace"] = str(tt_ws)
                fd.seek(0)
                json.dump(c, fd, indent=2)
                fd.truncate()
            logging.info(f"Add Triton configuration: {conf}")
            broker.add_engine_configuration("TRITON", conf)
            if triton and spawn:
                spawn_online_triton(port, probe)
    else:
        if not triton:
            logging.warning("Triton enabled but no configuration found")

    # Bind it and start listening (clients can connect)
    ip = "*" if allow_remote else "127.0.0.1"
    broker.bind(port, ip)
    broker.run(timeout)


@cli.command(context_settings=dict(show_default=True))
@click.argument('workspace', type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True))
@click.option('-t', '--type', type=click.Choice([x.name for x in list(ReplayType)]), default=ReplayType.qbdi.name, help="Replay type")
@click.option('-i', '--injloc', type=click.Choice([x.name for x in list(SeedInjectLoc)]), default=SeedInjectLoc.STDIN.name, help="Seed injection location")
@click.option('--live', type=bool, is_flag=True, default=False, help="Enable replaying input files during the campaign")
@click.option('--stream', type=bool, is_flag=True, default=False, help="Enable streaming coverage on a ZMQ socket")
@click.option("-t", "--timeout", type=int, default=60, help="Replay timeout")
@click.option('--full/--no-full', type=bool, is_flag=True, default=True, help="Replay with full instructions and trace")
@click.option("--max-threads/--no-max-threads", type=bool, is_flag=True, default=False, help="Enable maximum parrallelizing")
@click.option("--debug", type=bool, is_flag=True, default=False, help="Enable debugging")
@click.argument('program', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True))
@click.argument('pargvs', nargs=-1)
def replay(workspace: str, type: str, injloc: str, live: bool, stream: bool, timeout: int, full: bool,  max_threads: bool, debug: bool, program: str, pargvs: Tuple[str]):

    configure_logging(logging.DEBUG if debug else logging.INFO)

    rtype = ReplayType[type]
    injloc = SeedInjectLoc[injloc]

    replayer = Replayer(Path(program), Path(workspace), rtype, injloc, stream, full, timeout, *pargvs)

    def replay_one(replayer, file, i, tot):
        result = replayer.replay(file)

        res = pp_good("OK") if result else pp_bad("KO")
        logging.info(f"[{i + 1}/{tot}] replay: {file.name} [{res}]")


    if live:
        replayer.start()
    else:
        count = sum(1 for _ in replayer.iter())
        if max_threads:
            job_count = os.cpu_count()
            joblib.Parallel(n_jobs=job_count)(joblib.delayed(replayer.replay)(file) for file in replayer.iter())
            #joblib.Parallel(n_jobs=job_count)(joblib.delayed(replay_one(replayer, file, i, count) for i, file in enumerate(replayer.iter())))
        else:
            for i, file in enumerate(replayer.iter()):
                replay_one(replayer, file, i, count)

    replayer.print_stats()
    replayer.save_fails()

@cli.command(context_settings=dict(show_default=True))
@click.option('--show/--no-show', type=bool, is_flag=True, default=True, help="Show the plots")
@click.option('--show-tt-inputs', type=bool, is_flag=True, default=False, help="Show the Triton inputs")
@click.option('--union/--no-union', type=bool, is_flag=True, default=True, help="Show union of analyses")
@click.option('-t', "--timeout", type=int, default=86400, help="Duration of the campaign (timeout)")
@click.option('-n', '--name', type=str, required=True, help="Name to give to the plotting")
@click.option('--is-proxy', type=bool, is_flag=True, default=False, help="Fuzzer is a proxy")
@click.option('--plot-dir', type=click.Path(exists=False, file_okay=False, dir_okay=True, readable=False), default=None, help="Plot output directory")
@click.option('-c', '--colors', type=str, required=False, help="Comma-separated list of colors to use in the plots")
@click.argument('workspace', type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True), nargs=-1)
def plot(show: bool, show_tt_inputs: bool, union: bool, timeout: int, name: str, is_proxy: bool, plot_dir: Tuple[str], colors: str, workspace: Tuple[str]):

    configure_logging(logging.INFO)

    color_list = [c for c in colors.split(',')] if colors else []

    plotter = Plotter(name, timeout, color_list)
    for ws in workspace:
        logging.info(f"Load workspace: {ws}")
        campaign = CampaignResult(Path(ws))

        # FIXME: Rework this.
        if is_proxy:
            campaign.SEED_FUZZER = 'PROXY'

        if plot_dir:
            plotter.PLOT_DIR = plot_dir

        campaign.load()  # by default load in qbdi

        if campaign.replay_ok():
            plotter.add_campaign_to_plot(campaign, show_union=union)

            if show_tt_inputs:
                plotter.add_triton_input(campaign)

            # save stats
            stats = plotter.calculate_stats(campaign)
            out_file = (Path(ws) / plotter.PLOT_DIR) / "stats.json"
            if not out_file.parent.exists():
                out_file.parent.mkdir()
            print(f"save stats in: {out_file}")
            out_file.write_text(stats.json())

            plotter.print_stats(campaign, stats)
            # plotter.print_input_number_stats(campaign)
            # plotter.print_coverage_stats(campaign)
            # plotter.print_triton_stats(campaign)
        else:
            logging.warning(f"workspace: {ws} has not been replayed")


    for ws in [Path(x) for x in workspace]:
        out_dir = ws / plotter.PLOT_DIR
        if not out_dir.exists():
            out_dir.mkdir()
        plotter.save_to(out_dir)
        logging.info(f"plot written to: {out_dir}")

    if show:
        logging.info("Show plot")
        plotter.show()



@cli.command(context_settings=dict(show_default=True))
@click.argument('workspace', type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True))
def history(workspace: str):

    logging.info(f"Load workspace: {workspace}")
    campaign = CampaignResult(Path(workspace))
    campaign.load()

    plotter = Plotter(workspace, 0, [])
    plotter.show_delta_history(campaign)


def main():
    cli()


if __name__ == "__main__":
    main()
