.. _hfwrapper_api_usage:

API Usage
=========

Basic usage
-----------

A mandatory field of the :py:class:`Honggfuzz` is a libpastis agent. When running
honggfuzz locally one can provide a :py:class:`FileAgent` that will act as a stub
by simply logging messages that shall have been sent in online mode. The script
shown below shows a basic exemple on how to kickstart honggfuzz with an initial
seed.

.. code-block:: python

    import sys
    from pathlib import Path
    from libpastis import FileAgent
    from libpastis.types import ExecMode, CoverageMode, SeedInjectLoc, CheckMode, FuzzingEngine
    from hfwrapper import Honggfuzz, HonggfuzzNotFound

    # Create a dummy FileAgent
    agent = FileAgent(level=logging.DEBUG, log_file=logfile)

    # Target to fuzz
    program = Path("/tmp/my_target.exe")

    # Instanciate the pastis that will register the appropriate callbacks
    try:
        honggfuzz = Honggfuzz(agent)
    except HonggfuzzNotFound:
        logging.error("Cannot find HFUZZ_PATH environement variable")
        sys.exit(1)

    # Mimick a callback to start_received
    honggfuzz.start_received(program.name,
                             program.read_bytes(),
                             FuzzingEngine.HONGGFUZZ,
                             ExecMode.PERSISTENT,
                             CheckMode.CHECK_ALL,
                             CoverageMode.EDGE,
                             SeedInjectLoc.STDIN,
                             "-n 16",  # arguments forward to honggfuzz command line
                             "a b c",  # program argv
                             "")

    # Provide an initial seed
    honggfuzz.add_initial_seed("/tmp/seed.cov")

    try:
        honggfuzz.run()
    except KeyboardInterrupt:
        honggfuzz.stop()


Replaying inputs
----------------

The Python module, provide a very basic replay engine allowing to re-run the
target with a given input, to check its return code or its output. Using the
``subprocess`` module it is being used to analyse inputs *(for checking
coverage and validating klocwork alerts)*. At the moment the :py:class:`Replay`
search for specific pattern ``rb".*REACHED ID (\d+)"`` to identify PASTIS
intrinsics covered. The following snippet shows how to re-run the target on
a given input and checking various properties.


.. code-block:: python

    from hfwrapper.replay import Replay

    # Rerun the program with the seed
    run = Replay.run("/tmp/target.bin",
                     "a b c",  # argv
                     stdin_file="/tmp/seed.cov",
                     timeout=5,  # To bound execution time
                     cwd="/tmp/") # If the binary is sensitive to location where it runs

    if run.has_crashed():  # Returncode != 0
        print("Crash")
    elif run.has_hanged():  # Timeout was triggered
        print("hang")
    else:
        if run.is_asan_without_crash():  # Some ASAN warnings yielded but without crash
            print("something suspicious")
        else:
            print("ok")

The complete API of the :py:class:`Replay` is described in :ref:`label_replay`.
