#! /usr/bin/env python3

import logging

from hfwrapper import Honggfuzz
from libpastis.agent import ClientAgent


logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(message)s")


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
