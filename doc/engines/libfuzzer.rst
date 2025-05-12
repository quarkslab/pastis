*********
Libfuzzer
*********

Libfuzzer works in a different way than the other engines. It is not a standalone fuzzer binary
but the whole fuzzing logic is embedded in the target binary. Thus there is no installation steps
required.


Running pastis-libfuzzer
========================

The program ``pastis-libfuzzer`` wraps all interaction with the broker.
It can either be launched locally in offline mode or with the broker in
an online mode.

Online mode
-----------

Launching the ``pastis-libfuzzer`` in online mode is as simple as:

.. code-block:: bash

    $ pastis-aflpp online

Without further argument the binary the server reached is localhost on port
5555. Otherwise one can specify ``-h`` and ``-p`` respectively for the host
and port. There is no other parameters as all of them will be received
through the broker.

Offline mode
------------

In offline mode, all parameters normally received by the broker have to be
specified on the command line. Options are:

.. highlight:: none

.. code-block:: bash

    $ pastis-libfuzzer offline --help
    Usage: pastis-libfuzzer offline [OPTIONS] PROGRAM [PARGVS]...

    Options:
      -r, --sast-report FILE          SAST report to use
      -s, --seed PATH                 Seed or directory of seeds to give to the exploration
      -chk, --chkmode [CHECK_ALL|ALERT_ONLY] Check mode
      --logfile TEXT                  Log file of all messages received by the broker
      --help                          Show this message and exit.


Note that by design, libfuzzer works in a persistent manner and there is no input
injection location (argv, stdin). Thus there are less option in offline mode than
other fuzzers.
