# PYTHONPATH=. ./bin/fuzz_cyclone.py offline -s out.frames micro_http_server_tt_fuzz_single_with_vuln wlp0s20f3 48:e2:44:f5:9b:01 10.0.13.86 255.255.255.0 10.0.13.254


# built-in imports
import logging
from pathlib import Path
from typing import List, Tuple, Optional
from importlib import import_module
from inspect import getmembers, isclass
import sys

# Third-party imports
import click
import coloredlogs
from libpastis import ClientAgent, FileAgent
from libpastis.types import ExecMode, CoverageMode, SeedInjectLoc, CheckMode, FuzzingEngineInfo, SeedType, FuzzMode

# Local imports
from pastistritondse import TritonDSEDriver, __version__
from tritondse import CoverageStrategy, ProbeInterface, Config, SmtSolver
from tritondse.probes.basic_trace import BasicDebugTrace
import tritondse.logging

pastis = None


def configure_logs(level: int):
    tritondse.logging.enable(level)  # Enable tritondse to print logging information
    coloredlogs.install(level=level,
                        fmt="%(asctime)s %(threadName)s [%(levelname)s] %(message)s",
                        level_styles={'debug': {'color': 'blue'}, 'info': {'color': 'white'}, 'warning': {'color': 'yellow'},
                                      'error': {'color': 'red'}, 'critical': {'bold': True, 'color': 'red'}},
                        field_styles={'asctime': {'color': 'white'}, 'levelname': {'bold': True}})


def load_probe_module(module) -> Optional[ProbeInterface]:
    # base = module_id.split(":")z
    try:
        module = import_module(module)
    except ImportError as e:
        logging.error(f"Can't load module: {module}")
        return
    classes = getmembers(module, lambda m: isclass(m) and issubclass(m, ProbeInterface) and m != ProbeInterface)
    if classes:
        return classes[0][1]()
    else:
        logging.error(f"Can't find a ProbeInterface in module: {module}")


@click.group()
@click.version_option(__version__)
def cli():
    pass


@cli.command()
@click.option('-h', '--host', type=str, default='localhost', help='Host to connect to')
@click.option('-p', '--port', type=int, default=5555, help='Port to connect to')
@click.option('--debug', type=bool,  is_flag=True, show_default=True, default=False, help='Enable debug logs')
@click.option('--probe', type=str, help="Probe to load as a python module (should contain a ProbeInterface)", multiple=True)
def online(host: str, port: int, debug: bool, probe: Tuple[str]):
    """
    This is the online mode of the pastis-tritondse exploration. With this mode,
    the client (pastis-tritondse) will try to connect to the broker. Then, the broker
    will send us the binary to explore, the configuration and initiale seeds.

    :param host: The remote host to connect
    :param port: The remote host's port to connect
    :param debug: Configure debugging logs
    :param probe: Probes to enable (Python modules imported with importlib)
    """

    configure_logs(logging.DEBUG if debug else logging.INFO)

    # Create the network agent and connect to the broker
    agent = ClientAgent()

    # Instanciate the pastis that will register the appropriate callbacks
    pastis = TritonDSEDriver(agent)

    for p in list(probe):
        probe = load_probe_module(p)
        if probe:
            pastis.add_probe(probe)

    pastis.init_agent(host, port)

    try:
        logging.info(f'Starting fuzzer...')
        pastis.run(online=True)
    except KeyboardInterrupt:
        logging.info(f'Stopping fuzzer... (Ctrl+C)')
        pastis.stop()


@cli.command(context_settings=dict(show_default=True))
@click.argument('program', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True))
@click.option('-r', '--sast-report', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True), help='SAST report to use')
@click.option('-c', "--count", type=int, default=0, help="Number of execution")
@click.option('--config', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True), help="Triton configuration file")
@click.option('-s', "--seed", type=click.Path(exists=True, file_okay=True, dir_okay=True, readable=True), help="Seed or directory of seeds to give to the exploration", multiple=True)
@click.option('-x', '--exmode', type=click.Choice([x.name for x in list(ExecMode)]), help="Execution mode", default=ExecMode.SINGLE_EXEC.name)
@click.option('-fmod', '--fuzzmode', type=click.Choice([x.name for x in list(FuzzMode)]), help="Fuzz mode", default=FuzzMode.BINARY_ONLY.name)
@click.option('-chk', '--chkmode', type=click.Choice([x.name for x in list(CheckMode)]), help="Check mode", default=CheckMode.CHECK_ALL.name)
@click.option('-cov', '--covmode', type=click.Choice([x.value for x in CoverageStrategy]), help="Coverage strategy", default=CoverageStrategy.EDGE.value)
@click.option('-i', '--seedinj', type=click.Choice([x.name for x in list(SeedInjectLoc)]), help="Location where to inject input", default=SeedInjectLoc.STDIN.name)
@click.option("--solver", type=click.Choice([x.name for x in list(SmtSolver)]), help="SMT solver to use", default=None)
@click.option('-n', '--name', type=str, default='', help="Name of the executable if program is an archive containing multiple files")
@click.option('-t', '--target', type=str, help="Target alert address in case of ALERT_ONE checkmode")
@click.option('-p', '--probe', type=str, help="Probe to load as a python module (should contain a ProbeInterface)", multiple=True)
@click.option('-w', '--workspace', type=str, default="", help='Path to TritonDSE workspace')
@click.option('--debug', type=bool,  is_flag=True, show_default=True, default=False, help='Enable debug logs')
@click.option('--debug-pp', type=bool,  is_flag=True, show_default=True, default=False, help='Enable debugging path predicate')
@click.option("--trace", type=bool, is_flag=True, show_default=True, default=False, help="Show execution trace in debug logging")
@click.argument('pargvs', nargs=-1)
def offline(program: str,
            sast_report: Optional[str],
            count: int,
            config: str,
            seed: Tuple[str],
            exmode: ExecMode,
            fuzzmode: FuzzMode,
            chkmode: CheckMode,
            covmode: CoverageStrategy,
            seedinj: SeedInjectLoc,
            solver: SmtSolver,
            name: str,
            target: str,
            pargvs: Tuple[str],
            probe: Tuple[str],
            workspace: Optional[str],
            debug: bool,
            debug_pp: bool,
            trace: bool):
    """
    This is the offline mode of the pastis-tritondse exploration. With this mode,
    the client (pastis-tritondse) will be able to work without a remote broker. In
    this mode, we have to provide all information about the configuration via
    the command line option.

    :param program: The program to explore
    :param sast_report: The SAST report if provided
    :param count: The limit of execution (0 = unlimited)
    :param config: The path the to TritonDSE configuration file (json)
    :param seed: The initial seed to inject
    :param exmode: The mode of the exploration
    :param fuzzmode: Fuzzing mode to apply
    :param chkmode: The mode of vulnerability check
    :param covmode: The mode of coverage
    :param seedinj: The location where to inject input
    :param name: name of the binary of program is an archive
    :param target: target alert address to cover and validate
    :param pargvs: The program arguments
    :param probe: Python module containing a ProbeInterface to attach to the execution
    :param workspace: Workspace where to store data
    :param debug: Enable debug logs
    :param debug_pp: Enable debugging path predicate
    :param trace: show execution trace in debug logging
    """
    global pastis

    # Transform the type of parameters
    program = Path(program)
    exmode = ExecMode[exmode]
    fuzzmode = FuzzMode[fuzzmode]
    chkmode = CheckMode[chkmode]
    covmode = CoverageMode(covmode)
    seedinj = SeedInjectLoc[seedinj]
    pargvs = list(pargvs)

    # Create a dummy FileAgent
    agent = FileAgent()

    # Instanciate the pastis that will register the appropriate callbacks
    pastis = TritonDSEDriver(agent)

    if config:
        config = Config.from_file(config)
    else:
        config = Config()

    configure_logs(logging.DEBUG if debug else logging.INFO)

    if trace:
        pastis.add_probe(BasicDebugTrace())

    if workspace:
        config.workspace = workspace

    if solver:
        config.smt_solver = solver

    for p in list(probe):
        probe = load_probe_module(p)
        if probe:
            pastis.add_probe(probe)

    # Load the report if anyone provided
    report = Path(sast_report).read_text() if sast_report else ""

    if chkmode == CheckMode.ALERT_ONE:
        if target:
            value = int(target, 16) if target.startswith("0x") else int(target)
            # Small hack to embed the target address in the config file
            config.custom['target'] = value
        else:
            logging.error(f"CheckMode {chkmode.name} requires a target (use -t)")
            sys.exit(1)

    # Reserialize config file
    config = config.to_json()

    # Mimick a callback to start_received
    pastis.start_received(name if name else program.name,
                          program.read_bytes(),
                          FuzzingEngineInfo("TRITON", __version__, ""),
                          exmode,
                          fuzzmode,
                          chkmode,
                          covmode,
                          seedinj,
                          config,
                          pargvs,
                          report)

    # Set the number of execution limit
    pastis._config.exploration_limit = count

    # Provide it all our seeds
    for s in seed:
        s_path = Path(s)
        if s_path.is_file():  # Add the seed file
            pastis.add_initial_seed(s_path)
        elif s_path.is_dir():  # Add all file contained in the directory as seeds
            for sub_s in s_path.iterdir():
                pastis.add_initial_seed(sub_s)

    try:
        logging.info(f'Starting fuzzer...')
        pastis.run(online=False, debug_pp=debug_pp)
    except KeyboardInterrupt:
        logging.info(f'Stopping fuzzer... (Ctrl+C)')
        pastis.stop()

def main():
    cli()


if __name__ == "__main__":
    main()
