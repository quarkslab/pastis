.. _label_aflpp:

AFL++
-----

A mandatory field of the :py:class:`AFLPP` is a ``libpastis`` agent. When
running AFL++ locally one can provide a :py:class:`FileAgent` that will
act as a stub by simply logging messages that shall have been sent in online
mode. The script shown below shows a basic exemple on how to kickstart
``afl-fuzz`` with an initial seed.

.. code-block:: python

    import sys
    from pathlib import Path
    from libpastis import FileAgent
    from libpastis.types import ExecMode, CoverageMode, SeedInjectLoc, CheckMode, FuzzingEngine
    from pastisaflpp import AFLPPProcess, AFLPPNotFound

    # Create a dummy FileAgent
    agent = FileAgent(level=logging.DEBUG, log_file=logfile)

    # Target to fuzz
    program = Path("/tmp/my_target.exe")

    # Instanciate the pastis that will register the appropriate callbacks
    try:
        aflpp = AFLPPProcess(agent)
    except AFLPPNotFound:
        logging.error("Cannot find AFLPP_PATH environment variable")
        sys.exit(1)

    # Mimic a callback to start_received
    aflpp.start_received(program.name,
                         program.read_bytes(),
                         FuzzingEngine.AFLPP,
                         CheckMode.CHECK_ALL,
                         CoverageMode.AUTO,
                         SeedInjectLoc.STDIN,
                         "-n 16",  # arguments forward to aflpp command line
                         "a b c",  # program argv
                         "")

    # Provide an initial seed
    aflpp.add_initial_seed("/tmp/seed.cov")

    try:
        aflpp.run()
    except KeyboardInterrupt:
        aflpp.stop()


``pastisaflpp.aflpp``
----------------------

.. autoclass:: pastisaflpp.aflpp
    :members:
    :show-inheritance:
    :inherited-members:
    :undoc-members:
    :exclude-members:
