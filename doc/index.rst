<<<<<<< HEAD
Pastis Triton
=============

.. figure:: figs/pastisdse.*
   :scale: 85 %
   :align: center
   :alt: pastis-triton overview

The project Pastis-DSE provides a tritondse-tool built for PASTIS constraints.
Among other things, it performs the communication with the broker, it handles
the SAST report, handles the coverage and validation of alertes and ensure
to send and share all appropriate data with the broker. It shows a concrete
exemple of using the tritondse library to build an utility ``pastis-triton``
that satisfy some specific constraints.
=======
Pastis-AFLPP documentation
==========================

**Pastis-AFLPP** is a Python API to run ``AFL++`` via Python. More
specifically, this module built for the PASTIS project, interact with AFL++
allowing to inject new input files and to get telemetry about the current
running state. Built around the inotify module, it also allows getting
notified when a new corpus or crash file is being generated. In the context
of PASTIS it is thightly bound to ``libpastis`` for interacting with the
broker.


>>>>>>> pastisaflpp/master

.. toctree::
   :caption: Getting started
   :maxdepth: 2

    Installation <installation>
    Usage <usage>

<<<<<<< HEAD
=======
.. toctree::
    :caption: Python API
    :maxdepth: 3

    api

>>>>>>> pastisaflpp/master

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
