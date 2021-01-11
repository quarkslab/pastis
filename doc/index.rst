Pastis Broker
=============

Pastis-broker is the head of the infrastructure, acting as an intermediate between each
clients connected. In a general manner it is in charge of ensuring a maximal sharing of
seeds between clients. Ensuring this sharing enable theoretically to have the same coverage
for all clients.

That project is the main interface with the analyst as all configuration options of a
campain are set in pastis-broker and propagated to all clients automatically. Indeed,
it will transmit the appropriate binary, configuration, klocwork report, and initial
seeds. Similarly all relevant information are meant to be returned to the broker thus
it centralizes telemetry data. Upon timeout, or test requirement fulfillment and stop
message will be transmitted to all connected nodes so that they stop their testing
operations.

From a technical perspective, pastis-broker implement the broker side of libpastis by
implementing the associated callbacks. It is possible to write its own broker by using
directly libpastis or by sub-classing pastis-broker to take advantages of its existing
functionnalities.

.. figure:: figs/broker.*
   :scale: 50 %
   :align: center
   :alt: pastis-broker overview


.. toctree::
   :caption: Getting started
   :maxdepth: 2

    Installation <installation>
    Usage <usage>
    Workspace <workspace>


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
