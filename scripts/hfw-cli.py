#! /usr/bin/env python3

import argparse
import hfwrapper
import logging
import os
import pathlib
import sys
import time


logging.basicConfig(level=logging.INFO)


def init_arg_parser():
    description = "HF Wrapper CLI."

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=description)

    parser.add_argument("--target", required=True,
                        type=pathlib.Path, help="Path to the target file")

    parser.add_argument("--target-arguments",
                        type=str, help="Target arguments")

    parser.add_argument("--seeds-directory",
                        type=pathlib.Path, help="Path to the seeds directory")

    return parser


def main(args):
    logging.info(f'Target: {args.target}')
    logging.info(f'Target arguments: {args.target_arguments}')
    logging.info(f'Seeds directory: {args.seeds_directory}')

    if not os.environ['HFUZZ_PATH']:
        print('HFUZZ_PATH variable not defined.')
        sys.exit(1)

    if not os.environ['HFUZZ_WS']:
        print('HFUZZ_WS variable not defined.')
        sys.exit(1)

    hfuzz_path = pathlib.Path(os.environ['HFUZZ_PATH'])
    if not hfuzz_path.exists():
        raise Exception('Path does not exists.')

    hfuzz_workspace = pathlib.Path(os.environ['HFUZZ_WS'])
    if not hfuzz_workspace.exists():
        raise Exception('Path does not exists.')

    logging.info(f'Target arguments: {args.target_arguments}')
    logging.info(f'Seeds directory: {args.seeds_directory}')

    job_manager = hfwrapper.HonggfuzzJobManager(hfuzz_path / 'honggfuzz', hfuzz_workspace)

    logging.info(f'Starting...')
    job_id = job_manager.start(args.target.absolute(), args.target_arguments, args.seeds_directory)

    # Add some arbitrary delay for testing purposes.
    logging.info(f'Waiting some time...')
    time.sleep(10)

    logging.info(f'Stopping...')
    job_manager.stop(job_id)

    print('coverage_files:')
    for file in job_manager.get_coverage_files(job_id):
        print(f'\t{file}')

    print('crash_files:')
    for file in job_manager.get_crash_files(job_id):
        print(f'\t{file}')

    print(f'stats file:')
    print(f'\t{job_manager.get_stats_file(job_id)}')


if __name__ == '__main__':
    main(init_arg_parser().parse_args())
