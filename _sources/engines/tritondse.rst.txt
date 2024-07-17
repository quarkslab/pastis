TritonDSE
=========

The utility ``pastis-tritondse`` enables launching a TritonDSE. It can be launched
in an alert driven manner in ``ALERT_ONLY`` or in independent manner with ``CHECK_ALL``.
Also, it can be run in two modes, `online` to interact with a ``pastis-broker`` server or `offline`
to run locally on its own.

Online
------

The online mode only requires an IP and a port to run as all subsequent parameters
will be provided by the broker. The default IP and port are *localhost* on *5555*.

If the broker is running on the same machine ``pastis-tritondse`` can be launched with:

::

    $ pastis-tritondse online

If the broker runs on a different machine it can then be launched with:

::

    $ pastis-tritondse online -h 8.8.8.8 -p 5555


The utility will then automatically receive the parameters, the binary to test and
will start performing its coverage.


Offline
-------

Running locally, all parameters normally through the network then have to be provided
on the commande line. The help message is the following:

.. highlight:: none

::

    Usage: pastis-tritondse offline [OPTIONS] PROGRAM [PARGVS]...

    Options:
      -r, --sast-report FILE          SAST report to use
      -c, --count INTEGER             Number of execution  [default: 0]
      --config FILE                   Triton configuration file
      -s, --seed PATH                 Seed or directory of seeds to give to the
                                      exploration
      -x, --exmode [AUTO|SINGLE_EXEC|PERSISTENT]
                                      Execution mode  [default: SINGLE_EXEC]
      -fmod, --fuzzmode [AUTO|INSTRUMENTED|BINARY_ONLY]
                                      Fuzz mode  [default: BINARY_ONLY]
      -chk, --chkmode [CHECK_ALL|ALERT_ONLY|ALERT_ONE]
                                      Check mode  [default: CHECK_ALL]
      -cov, --covmode [block|edge|path|PREFIXED_EDGE]
                                      Coverage strategy  [default: edge]
      -i, --seedinj [STDIN|ARGV]      Location where to inject input  [default:
                                      STDIN]
      -n, --name TEXT                 Name of the executable if program is an
                                      archive containing multiple files
      -t, --target TEXT               Target alert address in case of ALERT_ONE
                                      checkmode
      -p, --probe TEXT                Probe to load as a python module (should
                                      contain a ProbeInterface)
      -w, --workspace TEXT            Path to TritonDSE workspace
      --debug                         Enable debug logs
      --debug-pp                      Enable debugging path predicate
      --trace                         Show execution trace in debug logging


Details:

* ``--sast-report`` SAST report if any
* ``--count`` limit the number of iterations to perform (number of program execution)
* ``--config`` tritondse configuration file to use
* ``--seed`` initial seed file or directory to use as initial corpus
* ``--exmode`` only ``SINGLE_EXEC`` is supported at the moment
* ``--fuzzmod`` only ``BINARY_ONLY`` applies for TritonDSE
* ``--chkmode`` change the running mode
* ``--covmode`` coverage strategy to apply
* ``--seedinj`` location where to inject the input file.
* ``--name`` name of the executable of the `PROGRAM` provided is an archive
* ``--target`` target address to try reaching when launched in `ALERT_ONE`
* ``--probe`` External Probe module that should be attached to the exploration
* ``--workspace`` workspace directory (if not provided in the configuration file)
* ``--debug`` show debug logs
* ``--debug-pp`` Enable debugging the path predicate **(debugging only)**
* ``--trace`` Log the complete execution trace in a file (to be combined with ``--count 1``)

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
