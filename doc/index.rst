Pastisd
=======

Pastisd is an utility meant to be able to run either Honggfuzz either Triton
if they are both installed. It enables the broker to choose which engine to
run on such or such machine. As such, it allows the broker to equilibrate the
Triton and Honggfuzz instances, or applying any other strategy. Pastis-DSE and
HF-wrapper are architectured to be used as libraries. Thus the ``pastisd``
first checks if one or both are available and installed and advertize it to the
broker *(which then choose which one to launch)*.

``pastisd`` is meant to be run as a daemon. As such, it just wait for a broker
to be available on the specified domain and port. By default domain is **pastis.lan**
and port 5555.

.. toctree::
   :caption: Getting started
   :maxdepth: 2

    Installation <installation>
    Usage <usage>


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
