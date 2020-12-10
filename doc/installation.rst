Installation
============

Installing ``hf-wrapper`` works by providing the honggfuzz binary path through
environment variable. It thus has to be installed before the Python module.

Installing Honggfuzz
--------------------

Compiling the Honggfuzz tailored for PASTIS is as simple as:

.. code-block:: bash

    $ cd honggfuzz
    $ make
    $ echo "export HFUZZ_PATH=$PWD" >> ~/.profile

The only tricky part is the export of the honggfuzz directory as environment variable to make
it discoverable by ``hf-wrapper``. At the moment the module does not intent to find automatically
the honggfuzz binary.


Installing HF-Wrapper
---------------------

The only external dependency is ``libpastis``. It thus need to be installed first (see appropriate
section). Then getting in the hf-wrapper directory and install the module with:

.. code-block:: bash

    $ pip3 install .
