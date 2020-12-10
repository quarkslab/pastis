HF-Wrapper documentation
========================

**Hf-Wrapper** is a Python API to run ``honggfuzz`` via Python.
More specifically, this module built for the PASTIS project, interact
with a custom version of honggfuzz allowing to inject new input files
and to get telemetry about the current running state. Built around
the inotify module, it also allows getting notified when a new corpus
or crash file is being generated. In the context of PASTIS it is
thightly bound to ``libpastis`` for interacting with the broker.


.. toctree::
   :caption: Getting started
   :maxdepth: 2

    Installation <installation>
    Usage <usage>
    API usage <api_usage>

.. toctree::
    :caption: Python API
    :maxdepth: 3

    Honggfuzz <api/hfwrapper>
    Replay <api/replay>


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
