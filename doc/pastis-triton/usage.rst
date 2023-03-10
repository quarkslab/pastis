<<<<<<< HEAD
.. _pastis_dse_usage:

pastis-triton usage
===================

The utility ``pastis-triton`` enables launching a program exploration. It can be launched
in an alert driven manner in ``ALERT_ONLY`` or in independent manner with ``CHECK_ALL``.
This later mode, can be applied to any target outside of PASTIS context. Also, it can
be run in two modes, `online` to interact with a ``pastis-broker`` server or `offline`
to run locally on its own.

Online
------

The online mode only requires an IP and a port to run as all subsequent parameters
will be provided by the broker. The default IP and port are *localhost* on *5555*.

If the broker is running on the same machine ``pastis-triton`` can be launched with:

::

    $ pastis-triton online

If the broker runs on a different machine it can then be launched with:

::

    $ pastis-triton online -h 8.8.8.8 -p 5555


The utility will then automatically receive the parameters, the binary to test and
will start performing its coverage.


Offline
-------

Running locally, all parameters normally through the network then have to be provided
on the commande line. The help message is the following:

.. highlight:: none

::

    Usage: pastis-triton offline [OPTIONS] PROGRAM [PARGVS]...

    Options:
      -r, --sast-report FILE          SAST report to use
      -c, --count INTEGER             Number of execution
      --config FILE                   Triton configuration file
      -s, --seed PATH                 Seed or directory of seeds to give to the
                                      exploration

      -x, --exmode [SINGLE_EXEC|PERSISTENT]
                                      Execution mode
      -chk, --chkmode [CHECK_ALL|ALERT_ONLY]
                                      Check mode
      -cov, --covmode [BLOCK|EDGE|PATH|STATE]
                                      Coverage strategy
      -i, --seedinj [STDIN|ARGV]      Location where to inject input
      --help                          Show this message and exit.


Details:

* ``--sast-report`` SAST report if any
* ``--count`` limit the number of iterations to perform (number of program execution)
* ``--config`` tritondse configuration file to use
* ``--seed`` initial seed file or directory to use as initial corpus
* ``--exmode`` only ``SINGLE_EXEC`` is supported at the moment
* ``--chkmode`` change the running mode
* ``--covmode`` coverage strategy to apply
* ``--seedinj`` location where to inject the input file. Only ``STDIN`` is supported at the moment


Configuration & Results
-----------------------

The project handles PASTIS parameters and translate them in their counterpart
in tritondse. For instance the running mode ``CHECK_ALL`` and ``ALERT_ONLY`` are
PASTIS parameters. That parameter will be put in practice by register different
callbacks. As such, ``ALERT_ONLY`` will only register a callback on the intrinsic
function while ``CHECK_ALL`` requires registering callbacks on many more events.

.. note:: The configuration file, and workspace uses the tritondse mechanism. Thus,
  one must refers to tritondse documentation for additional information about the
  configuration file or the workspace organization.
=======
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
>>>>>>> pastisaflpp/master
