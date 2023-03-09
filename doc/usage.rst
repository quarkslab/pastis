.. _pastisaflpp_bin:

pastis-aflpp usage
==================

The program ``pastis-aflpp`` is the main binary using the pastis-aflpp library
to interact with the broker. It can either be launched locally in offline
mode or with the broker in an online mode.

Online mode
-----------

Launching the ``pastis-aflpp`` in online mode is as simple as:

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

    $ pastis-aflpp offline --help
    Usage: pastis-aflpp offline [OPTIONS] PROGRAM [PARGVS]...

    Options:
      -r, --sast-report FILE          SAST report to use
      -s, --seed PATH                 Seed or directory of seeds to give to the exploration
      -x, --exmode [SINGLE_EXEC|PERSISTENT] Execution mode
      -chk, --chkmode [CHECK_ALL|ALERT_ONLY] Check mode
      -i, --seedinj [STDIN|ARGV]      Location where to inject input
      --logfile TEXT                  Log file of all messages received by the broker
      --help                          Show this message and exit.

The only mandatory argument is the binary itself. One can provide binary argvs
as argv on the command line. Optional arguments allows providing a SAST
report, one or multiple initial seed files and tuning parameters to run the
fuzzer.