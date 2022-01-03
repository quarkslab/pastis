.. _label_hfwrapper:

Honggfuzz
---------

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
    from pastishf import HonggfuzzProcess, HonggfuzzNotFound

    # Create a dummy FileAgent
    agent = FileAgent(level=logging.DEBUG, log_file=logfile)

    # Target to fuzz
    program = Path("/tmp/my_target.exe")

    # Instanciate the pastis that will register the appropriate callbacks
    try:
        honggfuzz = HonggfuzzProcess(agent)
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


``pastishf.Honggfuzz``
----------------------


.. autoclass:: pastishf.Honggfuzz
    :members:
    :show-inheritance:
    :inherited-members:
    :undoc-members:
    :exclude-members:
