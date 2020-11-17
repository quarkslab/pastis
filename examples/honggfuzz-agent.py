#! /usr/bin/env python3

import logging

from hfwrapper import Honggfuzz
from libpastis.agent import ClientAgent
import coloredlogs

coloredlogs.install(level=logging.DEBUG,
                    fmt="%(asctime)s %(levelname)s %(message)s",
                    level_styles={'debug': {'color': 'blue'}, 'info': {}, 'warning': {'color': 'yellow'},
                                  'error': {'color': 'red'}, 'critical': {'bold': True, 'color': 'red'}})


def main():
    agent = ClientAgent()
    hfuzz = Honggfuzz(agent)

    try:
        logging.info(f'Starting fuzzer...')
        hfuzz.run()
    except KeyboardInterrupt:
        print("[!] CTRL+C detected! Aborting...")

        logging.info(f'Stopping fuzzer...')
        hfuzz.stop()


if __name__ == "__main__":
    main()
