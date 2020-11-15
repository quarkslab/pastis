#! /usr/bin/env python3

import argparse
import logging
import pathlib

from hfwrapper import Honggfuzz
from libpastis.agent import FileAgent


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")


def init_arg_parser():
    description = "Honggfuzz explorer."

    parser = argparse.ArgumentParser(description=description)

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

        logging.info(f'Target: {args.target}')
        logging.info(f'Target arguments: {args.target_arguments}')

        arguments = '' if args.target_arguments is None else args.target_arguments

        hfuzz.run(target=args.target, target_arguments=arguments)
    except KeyboardInterrupt:
        print("[!] CTRL+C detected! Aborting...")

        logging.info(f'Stopping fuzzer...')
        hfuzz.stop()


if __name__ == "__main__":
    main(init_arg_parser().parse_args())
