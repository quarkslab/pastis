.. _pastis_broker_usage:

pastis-broker usage
===================

Once installed, the binary ``pastis-broker`` is available in the PATH to launch
the broker through command line. The command line arguments are the following:

.. highlight:: none

::

    Usage: pastis-broker [OPTIONS] [PARGVS]...

    Options:
      -w, --workspace PATH            Workspace directory to store data
      -k, --kl-report FILE            Klocwork report to use
      -b, --bins DIRECTORY            Directory containing binaries  [required]
      -m, --mode [FULL|NO_TRANSMIT|COVERAGE_ORDERED]
                                      Mode of broking
      --tt-config PATH                Triton configuration file
      --hf-config PATH                Honggfuzz configuration file
      -s, --seed PATH                 Initial seed or directory of seeds to give
                                      as initial corpus

      --help                          Show this message and exit.


* ``--workspace`` defines the directory where all runtime data will be stored.
  If it does not exists it is created, otherwise information are partially loaded
  from it. The utility can thus load all corpus and crash files from an existing
  workspace. Other files are essentially not reused.

* ``--kl-report`` Klocwork report to use if any. If a report is provided, clients
  are automatically launched in ``ALERT_ONLY`` mode otherwise they are launched in
  ``CHECK_ALL``.

* ``--bins`` is the only mandatory parameter as it indicates an executable binary or
  a directory containing various variant of the same binary. Indeed, ``honggfuzz``
  requires the binary to be compiled with instrumentation while ``triton`` need not.
  Similarly, depending on clients architecture the appropriate variant in the right
  architecture can be provided. ``pastis-broker`` automatically detects the various
  variant in a given directory which simplifies the broker usage as it will automatically
  provide the appropriate variant depending on client's capabilities. By using
  `LIEF <https://lief.quarkslab.com>` the following variants are detected:

  * architecture : from ELF header
  * instrumentation : from functions of the program. If it contains references
    to “__sanitizer” then it is considered for ``honggfuzz``otherwise for Triton
  * persistence : detect persistence through ``HF_ITER`` function presence or the
    presence of a token added in .rodata by Honggfuzz in the target.

.. warning:: At the moment solely ELF Linux binaries are supported. Supporting other
   platforms would require extra engineering effort.

* ``--mode`` defines the "broking" behavior for ``pastis-broker``. Possible values are:
  * ``FULL``: transmit all seeds to other clients. Performs the maximal sharing between peers
  * ``NO_TRANSMIT``: receive data from clients but does not forward to one-another seeds
  * ``COVERAGE_ORDERED``: transmit a seed to a client only if it has been launch with the
  same or more broad coverage metric. The relation order between metrics are block < edge < path.
  *(not implemented)*

* ``--seed`` allows specifying a file or a directory of files containing the initial corpus
  for the campain.

* ``--tt-config`` Triton specific parameters to be sent as configuration to any Triton clients
  The file is a JSON file as defined in ``tritondse``. If the parameter is a directory all files
  contained inside will be considered as different configuration files. That enables launching
  different Triton instances with different parameters. In this case ``pastis-broker`` will
  launch a triton instance in each configuration and will loop if there is more.

* ``--hf-config`` Honggfuzz specific parameters to be sent to ``hf-wrapper``. The file is text
  file that will be transmitted as-is to honggfuzz command line. The parameter can also be a
  directory.

.. note:: Without configuration specific files, pastis-broker will automatically equilibrate
  the coverage modes for clients. For instance three instances of Triton will each be launched
  with different coverage criteria (block, edge, path). Similarly, if a client support different
  fuzzing engines pastis-broker will automatically balances honggfuzz instances and Triton instances.
