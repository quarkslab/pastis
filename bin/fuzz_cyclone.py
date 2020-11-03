#!/usr/bin/env python3

# PYTHONPATH=. ./bin/fuzz_cyclone.py offline -s out.frames micro_http_server_tt_fuzz_single_with_vuln wlp0s20f3 48:e2:44:f5:9b:01 10.0.13.86 255.255.255.0 10.0.13.254


# built-in imports
import logging
from pathlib import Path
from typing import List, Tuple, Optional

# Third-party imports
import click
from libpastis import ClientAgent, FileAgent
from libpastis.types import ExecMode, CoverageMode, SeedInjectLoc, CheckMode, FuzzingEngine, SeedType

# Local imports
from pastisdse import PastisDSE

pastis = None

@click.group()
def cli():
    pass


@cli.command()
def api():
    pass
    # Create the network client agent
    # register de start_receive callback
    # send the hello_msg
    # start_receive_triggered
    # instanciate PastisDSE or Honggfuzz (and register additional callbacks)
    # forward the start_received to pastisdse or honggfuzz
    # Call function run()


@cli.command()
@click.option('-h', '--host', type=str, default='localhost', help='Host to connect to')
@click.option('-p', '--port', type=int, default=5555, help='Port to connect to')
def online(host: str, port: int):
    # Create the network agent and connect to the broker
    agent = ClientAgent()

    # Instanciate the pastis that will register the appropriate callbacks
    pastis = PastisDSE(agent)

    pastis.init_agent(host, port)
    pastis.run(wait_idle=True)


@cli.command()
@click.argument('program', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True))
@click.option('-k', '--kl-report', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True), help='Klocwork report to use')
@click.option('-c', "--count", type=int, default=0, help="Number of execution")
@click.option('--config', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True), help="Triton configuration file")
@click.option('-s', "--seed", type=click.Path(exists=True, file_okay=True, dir_okay=True, readable=True), help="Seed or directory of seeds to give to the exploration", multiple=True)
@click.option('-x', '--exmode', type=click.Choice([x.name for x in ExecMode]), help="Execution mode", default=ExecMode.SINGLE_EXEC.name)
@click.option('-chk', '--chkmode', type=click.Choice([x.name for x in CheckMode]), help="Check mode", default=CheckMode.ALERT_ONLY.name)
@click.option('-cov', '--covmode', type=click.Choice([x.name for x in CoverageMode]), help="Coverage strategy", default=CoverageMode.EDGE.name)
@click.option('-i', '--seedinj', type=click.Choice([x.name for x in SeedInjectLoc]), help="Location where to inject input", default=SeedInjectLoc.STDIN.name)
@click.argument('pargvs', nargs=-1)
def offline(program: str, kl_report: Optional[str], count: int, config: str, seed: Tuple[str], exmode, chkmode, covmode, seedinj, pargvs: Tuple[str]):
    global pastis
    # Transform the type of parameters
    program = Path(program)
    exmode = ExecMode[exmode]
    chkmode = CheckMode[chkmode]
    covmode = CoverageMode[covmode]
    seedinj = SeedInjectLoc[seedinj]
    pargvs = list(pargvs)

    # Create a dummy FileAgent
    agent = FileAgent()

    # Instanciate the pastis that will register the appropriate callbacks
    pastis = PastisDSE(agent)

    # Set the number of execution limit
    pastis.config.exploration_limit = count

    #pastis.init_agent(host, port)  # Does not even call init_agent as it does nothing for the FileAgent
    if config:
        config = Path(config).read_text()
    else:
        config = ""

    # Mimick a callback to start_received
    pastis.start_received(program.name, program.read_bytes(), FuzzingEngine.TRITON, exmode, chkmode, covmode, seedinj, config, pargvs, kl_report)

    # Provide it all our seeds
    for s in seed:
        s_path = Path(s)
        if s_path.is_file():  # Add the seed file
            pastis.seed_received(SeedType.INPUT, Path(s).read_bytes(), origin=FuzzingEngine.HONGGFUZZ)
        elif s_path.is_dir():  # Add all file contained in the directory as seeds
            for sub_s in s_path.iterdir():
                pastis.seed_received(SeedType.INPUT, sub_s.read_bytes(), origin=FuzzingEngine.HONGGFUZZ)

    # Call run to start exploration
    pastis.run(wait_idle=False)


if __name__ == "__main__":
    cli()



