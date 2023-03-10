Pastis-HF Installation
=======================

Installing ``pastis-hf`` works by providing the honggfuzz binary path through
environment variable. It thus has to be installed before the Python module.

Installing Honggfuzz
--------------------

Compiling the Honggfuzz tailored for PASTIS is as simple as:

.. code-block:: bash

    $ sudo apt install binutils-dev libunwind-dev -y
    $ cd honggfuzz
    $ make
    $ echo "export HFUZZ_PATH=$PWD" >> ~/.profile

The only tricky part is the export of the honggfuzz directory as environment variable to make
it discoverable by ``pastis-hf``. At the moment the module does not intent to find automatically
the honggfuzz binary.


Installing Pastis-HF
---------------------

The only external dependency is ``libpastis``. It thus need to be installed first (see appropriate
section). Then getting in the pastis-hf directory and install the module with:

.. code-block:: bash

    $ pip3 install .
