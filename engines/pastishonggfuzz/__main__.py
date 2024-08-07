# To run it offline
# pastis-honggfuzz offline [OPTS] BINARY PARAMS
#
# To run if online
# pastis-honggfuzz online

# built-in imports
import logging
import sys
from pathlib import Path
from typing import Tuple, Optional

# Third-party imports
import click
import coloredlogs
from libpastis import ClientAgent, FileAgent
from libpastis.types import ExecMode, CoverageMode, SeedInjectLoc, CheckMode, FuzzingEngineInfo, FuzzMode

# Local imports
from pastishonggfuzz import HonggfuzzDriver, __version__


coloredlogs.install(level=logging.DEBUG,
                    fmt="%(asctime)s %(levelname)s %(message)s",
                    level_styles={'debug': {'color': 'blue'}, 'info': {}, 'warning': {'color': 'yellow'},
                                  'error': {'color': 'red'}, 'critical': {'bold': True, 'color': 'red'}})


honggfuzz = None


@click.group()
@click.version_option(__version__)
def cli():
    pass


@cli.command()
@click.option('-h', '--host', type=str, default='localhost', help='Host to connect to')
@click.option('-p', '--port', type=int, default=5555, help='Port to connect to')
@click.option('-tf', '--telemetry-frequency', type=int, default=30, help='Frequency at which send telemetry (in sec)')
def online(host: str, port: int, telemetry_frequency: int):
    agent = ClientAgent()

    if not HonggfuzzDriver.honggfuzz_available():
        logging.error("Cannot find HFUZZ_PATH environment variable or invalid value")
        return

    hfuzz = HonggfuzzDriver(agent, telemetry_frequency=telemetry_frequency)

    hfuzz.init_agent(host, port)
    try:
        logging.info(f'Starting fuzzer...')
        hfuzz.run()
    except KeyboardInterrupt:
        logging.info(f'Stopping fuzzer... (Ctrl+C)')
        hfuzz.stop()


@cli.command()
@click.argument('program', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True))
@click.option('-r', '--sast-report', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True), help='SAST report to use')
@click.option('-s', "--seed", type=click.Path(exists=True, file_okay=True, dir_okay=True, readable=True), help="Seed or directory of seeds to give to the exploration", multiple=True)
@click.option('-x', '--exmode', type=click.Choice([x.name for x in ExecMode]), help="Execution mode", default=ExecMode.SINGLE_EXEC.name)
@click.option('-fmod', '--fuzzmode', type=click.Choice([x.name for x in FuzzMode]), help="Fuzz mode", default=FuzzMode.INSTRUMENTED.name)
@click.option('-chk', '--chkmode', type=click.Choice([x.name for x in CheckMode]), help="Check mode", default=CheckMode.ALERT_ONLY.name)
@click.option('-i', '--seedinj', type=click.Choice([x.name for x in SeedInjectLoc]), help="Location where to inject input", default=SeedInjectLoc.STDIN.name)
@click.option('--logfile', type=str, default="hf-fileagent-broker.log", help='Log file of all messages received by the broker')
@click.argument('pargvs', nargs=-1)
def offline(program: str, sast_report: Optional[str], seed: Tuple[str], exmode, fuzzmode, chkmode, seedinj, logfile, pargvs: Tuple[str]):
    global honggfuzz

    # Transform the type of parameters
    program = Path(program)
    exmode = ExecMode[exmode]
    fuzzmode = FuzzMode[fuzzmode]
    chkmode = CheckMode[chkmode]
    seedinj = SeedInjectLoc[seedinj]
    pargvs = list(pargvs)

    # Create a dummy FileAgent
    agent = FileAgent(level=logging.DEBUG, log_file=logfile)

    # Check the HFUZZ_PATH variable is found
    if not HonggfuzzDriver.honggfuzz_available():
        logging.error("Cannot find HFUZZ_PATH environment variable or invalid value")
        return

    # Instanciate the pastis that will register the appropriate callbacks
    honggfuzz = HonggfuzzDriver(agent)

    # Load the report if anyone provided
    report = Path(sast_report).read_text() if sast_report else ""

    # Mimick a callback to start_received
    honggfuzz.start_received(program.name, program.read_bytes(), FuzzingEngineInfo("HONGGFUZZ", __version__, None), exmode, fuzzmode, chkmode, CoverageMode.EDGE, seedinj, "", pargvs, report)

    # Provide it all our seeds
    for s in seed:
        s_path = Path(s)
        if s_path.is_file():  # Add the seed file
            honggfuzz.add_initial_seed(s_path)
        elif s_path.is_dir():  # Add all file contained in the directory as seeds
            for sub_s in s_path.iterdir():
                honggfuzz.add_initial_seed(sub_s)

    try:
        logging.info(f'Starting fuzzer...')
        honggfuzz.run()
    except KeyboardInterrupt:
        logging.info(f'Stopping fuzzer... (Ctrl+C)')
        honggfuzz.stop()


def main():
    cli()


if __name__ == "__main__":
    main()
