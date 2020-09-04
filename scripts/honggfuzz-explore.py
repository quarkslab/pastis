#! /usr/bin/env python3

import argparse
import logging
import pathlib

from hfwrapper import Honggfuzz
from libpastis.agent import FileAgent


logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(message)s")


def init_arg_parser():
    description = "Honggfuzz explorer."

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=description)

    parser.add_argument("--target", required=True,
                        type=pathlib.Path, help="Target path")

    parser.add_argument("--target-arguments",
                        type=str, help="Target arguments")

    return parser


def main(args):
    agent = FileAgent()
    hfuzz = Honggfuzz(agent)

    try:
        logging.info(f'Starting fuzzer...')

        logging.debug(f'Target: {args.target}')
        logging.debug(f'Target arguments: {args.target_arguments}')

        hfuzz.run(target=args.target, target_arguments=args.target_arguments)
    except KeyboardInterrupt:
        print("[!] CTRL+C detected! Aborting...")

        logging.info(f'Stopping fuzzer...')
        hfuzz.stop()


if __name__ == "__main__":
    main(init_arg_parser().parse_args())
