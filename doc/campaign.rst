**************
Running PASTIS
**************

Before running PASTIS, the target must be harnessed, and all variants compiled for
each engines. In order one should launch:

* the broker with all parameters of the campaign
* the fuzzing engines (with no specific order)


Broker
======

The broker can be launched with ``pastis-broker`` binary. Command line arguments are
the following:

.. highlight:: none

::

    Usage: pastis-broker [OPTIONS] [PARGVS]...

    Options:
      --version                       Show the version and exit.
      -w, --workspace PATH            Workspace directory to store data
      -r, --sast-report FILE          SAST report to use
      -b, --bins DIRECTORY            Directory containing binaries  [required]
      -m, --mode [FULL|NO_TRANSMIT]   Mode of broking
      -c, --chkmode [CHECK_ALL|ALERT_ONLY|ALERT_ONE]
                                      Check mode (all or alert driven)
      -i, --injloc [STDIN|ARGV]       Seed injection location
      -e, --engine TEXT               Fuzzing engine module to load (python
                                      module)
      --tt-config PATH                Triton configuration file
      --hf-config PATH                Honggfuzz configuration file
      -s, --seed PATH                 Initial seed or directory of seeds to give
                                      as initial corpus
      -t, --timeout INTEGER           Timeout of the campaign. Time after which
                                      stopping the campaign
      -p, --port INTEGER              Port to bind to
      --mem-threshold INTEGER         RAM consumption limit
      --help                          Show this message and exit.



* ``--workspace`` defines the directory where all runtime data will be stored.
  If it does not exists it is created, otherwise information are partially loaded
  from it. The utility can thus load all corpus and crash files from an existing
  workspace. Other files are essentially not reused.

* ``--sast-report`` SAST report to use if any. If a report is provided, clients
  are automatically launched in ``ALERT_ONLY`` mode otherwise they are launched in
  ``CHECK_ALL``.

* ``--bins`` is the only mandatory parameter as it indicates an executable binary or
  a directory containing various variant of the same binary. Indeed, ``honggfuzz``
  requires the binary to be compiled with instrumentation while ``tritondse`` need not.
  Similarly, depending on clients architecture the appropriate variant in the right
  architecture can be provided. ``pastis-broker`` automatically detects the various
  variant in a given directory which simplifies the broker usage as it will automatically
  provide the appropriate variant depending on client's capabilities.

.. warning:: At the moment solely ELF Linux binaries are supported. Supporting other
   platforms would require extra engineering effort.

* ``--mode`` defines the "broking" behavior for ``pastis-broker``. Possible values are:

  * ``FULL``: transmit all seeds to other clients. Performs the maximal sharing between peers
  * ``NO_TRANSMIT``: receive data from clients but does not forward to one-another seeds

* ``--chkmode``: Indicate engines, the mode they are meant to run.
    * ``CHECK_ALL``: normal exploration and global vulnerability discovery
    * ``ALERT_ONLY``: only perform security checks on alerts taken from the SAST report.
      Also enables reporting when an alert is covered or validated
    * ``ALERT_ONE``: Directed exploration toward a single alert (TritonDSE only)

* ``--injloc``: Whether the input is given on ``STDIN`` or via ``ARGV``

* ``--engine``: Name of a broker-addon to load, that describes an engine capabilities.

* ``--seed`` allows specifying a file or a directory of files containing the initial corpus
  for the campain.

* ``--tt-config`` Triton specific parameters to be sent as configuration to any Triton clients
  The file is a JSON file as defined in ``tritondse``. If the parameter is a directory all files
  contained inside will be considered as different configuration files. That enables launching
  different Triton instances with different parameters. In this case ``pastis-broker`` will
  launch a triton instance in each configuration and will loop if there is more.

* ``--hf-config`` Honggfuzz specific parameters to be sent to ``hf-wrapper``. The file is text
  file that will be transmitted as-is to honggfuzz command line. The parameter can also be a
  directory with various configuration files.

* ``--timeout`` fuzzing campaign timeout

* ``--port`` Network port on which to listen on

* ``--mem-threshold``: Memory watchdog in percent, that will kill Triton instances if the limit
  is reached


.. note:: Without configuration specific files, pastis-broker will automatically equilibrate
  the coverage modes for clients. For instance three instances of TritonDSE will each be launched
  with different coverage criteria (block, edge, path). Similarly, if a client support different
  fuzzing engines pastis-broker will automatically balances honggfuzz instances and Triton instances.


Fuzzers
=======

Engines can be launched with theirs appropriate binary:

* AFL++: ``pastis-aflpp online [IP] [PORT]``
* Honggfuzz: ``pastis-honggfuzz online [IP] [PORT]``
* TritonDSE: ``pastis-triton online [IP] [PORT]``

If no IP or port is provided, they will automatically connect to *localhost:5555*.


pastisd
-------

The binary ``pastisd`` is meant to be used as a daemon. It will check the availability of all
fuzzers and will connect to the broker announcing all available engines. It is thus the broker
that will automatically decide which fuzzer to launch. The ``pastisd`` daemon will receive
the ``start`` message from the broker containing the fuzzer to launch and will do it.

::

    $ pastisd IP

If no IP, is provided it will automatically connect to **pastis.lan:5555**.

.. warning:: This program is under maintainance, please favor launching
             each fuzzers explicitely.






Analysing Results
=================

Corpus, crashes, clients logs and telemetry are stored in the broker workspace.
It thus aggregate all data related to a campaign. If a SAST report have been
provided it also provides for each alertes data returned by clients, inputs triggered
the crash of the alert etc. In this mode ``pastis-broker`` also export a final CSV
indicating which alerts have been covered or triggered. The workspace folder also
enables restarting an interrupted campaign. The workspace file structure is the following:

.. highlight:: none

::

    workspace/
        alerts_data/   (alert related data if a report was provided)
        binaries/      (binaries used, copied from --bins argument)
        corpus/        (corpus files)
        crashes/       (crash files)
        hangs/         (hang files)
        logs/          (log files, one file per client)
        broker.log     (log file of the broker)
        sastreport.bin (copy of the SAST report if provided)
        results.csv    (synthetic results of alerts, if a report is provided)
