# built-in imports
import click
import sys
import logging
from typing import Optional, Tuple
from pathlib import Path

# Thirs-party imports
import coloredlogs
import lief
import tritondse.logging

# Local imports
from pastisbroker import PastisBroker, BrokingMode, __version__
from libpastis.types import CheckMode, SeedInjectLoc, ReplayType
import tritondse

tritondse.logging.enable(level=logging.DEBUG)

#logging.basicConfig(level=logging.DEBUG)
logging.root.name = f"\033[7m\033[39m[ BROKER ]\033[0m"
coloredlogs.install(level=logging.DEBUG,
                    fmt="%(asctime)s %(name)s [%(levelname)s] %(message)s",
                    level_styles={'debug': {'color': 'blue'}, # 10
                                  'info': {}, # 20
                                  'warning': {'color': 'yellow'},  # 30
                                  'success': {'bold': True, 'color': 'green'}, # 35
                                  'error': {'color': 'red'},
                                  'critical': {'bold': True, 'color': 'red'}})

broker = None


def iterate_file(file):
    p = Path(file)
    if p.is_file():  # Add the seed file
        yield p
    elif p.is_dir():  # Add all file contained in the directory as triton configuration
        for sub_s in p.iterdir():
            yield sub_s


def coverage_binary_checks(binary: Path, type: ReplayType) -> bool:
    """
    Sanitization checks, make sure the provided binary (does not have any instrumentation
    for QBDI or do contains llvm_profile functions for LLVM. 
    """
    # Parse executable with LIEF
    p = lief.parse(str(binary))
    fun_names = list(x.name for x in p.functions)

    if type == ReplayType.qbdi:
        BLACKLIST = ["hfuzz_", "__afl_", "__gcov_", "__asan_"]
        for name in fun_names:
            for token in BLACKLIST:
                if token in name:
                    logging.warning(f"{binary} do contains: {token} which is not expected for coverage binary")
                    return False
        return True
    
    elif type == ReplayType.llvm_profile:
        BLACKLIST = ["hfuzz_", "__afl_", "__asan_"]
        WHITELIST = "llvm_profile"
        found = False
        for name in fun_names:
            for token in BLACKLIST:
                if token in name:
                    logging.warning(f"{binary} do contains: {token} which is not expected for coverage binary")
                    return False
            if WHITELIST in name:
                found = True
        return found
    
    else:
        return False


@click.command()
@click.version_option(__version__)
@click.option('-w', '--workspace', type=click.Path(), default="workspace",
              help="Workspace directory to store data", show_default=True)
@click.option('-r', '--sast-report',
              type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
              help="SAST report to use")
@click.option('-b', '--bins', type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True),
              required=True, help="Directory containing binaries")
@click.option('-m', '--mode', type=click.Choice([x.name for x in BrokingMode]),
              default=BrokingMode.FULL.name, help="Mode of broking", show_default=True)
@click.option('-c', '--chkmode', type=click.Choice([x.name for x in list(CheckMode)]),
              default=CheckMode.CHECK_ALL.name, help="Check mode (all or alert driven)", show_default=True)
@click.option('-i', '--injloc', type=click.Choice([x.name for x in list(SeedInjectLoc)]),
              default=SeedInjectLoc.STDIN.name, help="Seed injection location", show_default=True)
@click.option('-e', '--engine', type=str, help="Fuzzing engine module to load (python module)", multiple=True)
@click.option("-E", "--env", type=str, help="Environment variable to forward to the target", multiple=True)
@click.option('--tt-config', type=click.Path(exists=True, file_okay=True, dir_okay=True, readable=True),
              help="Triton configuration file")
@click.option('--hf-config', type=click.Path(exists=True, file_okay=True, dir_okay=True, readable=True),
              help="Honggfuzz configuration file")
@click.option('-s', "--seed", type=click.Path(exists=True, file_okay=True, dir_okay=True, readable=True),
              help="Initial seed or directory of seeds to give as initial corpus", multiple=True)
@click.option('-t', "--timeout", type=int, default=None,
              help="Whole campaign timeout (in s). Time after which stopping the campaign")
@click.option('-p', '--port', type=int, default=5555, help="Port to bind to",
              multiple=False, show_default=True)
@click.option('--mem-threshold', type=int, default=85, help="RAM consumption limit",
              show_default=True)
@click.option('--start-quorum', type=int, default=0,
              help="Number of client connection to receive before triggering startup", show_default=True)
@click.option('--filter-inputs', type=bool, is_flag=True, default=False,
              help="Filter inputs that do not generate coverage", show_default=True)
@click.option("--cov-binary", type=click.Path(exists=True, file_okay=True, dir_okay=False, executable=True, path_type=Path),
              required=False, help="Binary executable to use for coverage")
@click.option("--cov-type", type=click.Choice([x.name for x in list(ReplayType)]),
              required=False, help="Coverage type")
@click.option('--stream', type=bool, is_flag=True, default=False,
              help="Stream input and coverage info in the given file", show_default=True)
@click.option('--replay-threads',
              type=int, default=4, help="number of threads to use for input replay", show_default=True)
@click.option('--replay-timeout', type=int, default=60,
              help="timeout for replaying inputs", show_default=True)
@click.argument('pargvs', nargs=-1)
def main(workspace: str,
         sast_report: Optional[str],
         bins: str,
         mode: str,
         chkmode: str,
         injloc: str,
         engine: Tuple[str],
         env: Tuple[str],
         tt_config: Optional[str],
         hf_config: Optional[str],
         seed: Tuple[str],
         timeout: Optional[int],
         port: int,
         pargvs: Tuple[str],
         mem_threshold: int,
         start_quorum: int,
         filter_inputs: bool,
         cov_binary: Path,
         cov_type: str,
         stream: bool,
         replay_threads: int,
         replay_timeout: int) -> None:
    global broker
    # Instanciate the broker

    chkmode = CheckMode[chkmode] # type: ignore
    if chkmode in [CheckMode.ALERT_ONLY, CheckMode.ALERT_ONE] and not sast_report:
        logging.error(f"Check mode {chkmode.name} requires a SAST report (use -r) to provide it")
        sys.exit(1)

    # if input filtering or streaming enabled check that a coverage replay binary is provided
    if filter_inputs or stream:
        if not cov_binary or not cov_type:
            logging.error(f"if filter_inputs or stream activated need --cov-binary and --cov-type")
            sys.exit(1)
        replay_type = ReplayType[cov_type]

        if not coverage_binary_checks(cov_binary, replay_type):
            sys.exit(1)
    else:
        replay_type = None

    # Unpack environment variables
    env_vars = {k: v for k, v in (x.split('=', 1) for x in list(env))}

    # Instanciate the broker
    broker = PastisBroker(workspace,
                          bins,
                          BrokingMode[mode],
                          chkmode,
                          SeedInjectLoc[injloc],
                          list(pargvs),
                          sast_report,
                          mem_threshold,
                          start_quorum,
                          filter_inputs,
                          stream,
                          replay_threads,
                          replay_timeout,
                          cov_binary,
                          replay_type,
                          env=env_vars)

    # Preload all Fuzzing engine if needed
    for eng in engine:
        broker.load_engine_addon(eng)

    # Add all the triton configuration if the parameter was a directory
    if tt_config:
        for conf in iterate_file(tt_config):
            logging.info(f"Add Triton configuration: {conf}")
            broker.add_engine_configuration("TRITON", conf)

    # Add all the Honggfuzz configuration
    if hf_config:
        for conf in iterate_file(hf_config):
            logging.info(f"Add Honggfuzz configuration: {conf}")
            broker.add_engine_configuration("HONGGFUZZ", conf)

    # Add all given seeds as initial seed
    for s_src in seed:
        for s in iterate_file(s_src):  # File if one file, or iterate dir if directory
            broker.add_seed_file(s, initial=True)

    # Bind it and start listening (clients can connect)
    broker.bind(port)
    broker.run(timeout)


if __name__ == "__main__":
    main()
