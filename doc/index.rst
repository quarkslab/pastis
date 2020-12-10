libpastis documentation
=======================

Libpastis is a pure python library designed perform all network communications
in the context of PASTIS. Its API mostly expose two classes :py:class:`ClientAgent`
and :py:class:`BrokerAgent` that enable acting as a client or a broker respectively.
It also exposes common types between components.

Underneath it uses `ZeroMQ <https://zeromq.org>`_ for message exchanges.
All data transmitted are serialized in `Protobuf <https://developers.google.com/protocol-buffers>`_.
However, for later interoperability, the user never manipulates directly zmq
sockets nor Protobuf types.


Installation
------------

Libpastis can be installed through pip:


.. code-block:: bash

    $ cd libpastis
    $ pip3 install .



.. toctree::
    :caption: Python API
    :maxdepth: 3

    API usage <api/agent>
    Types <api/types>




Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
