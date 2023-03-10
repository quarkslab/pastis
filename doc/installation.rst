Pastis-AFLPP Installation
=========================

Installing ``pastis-aflpp`` works by providing the ``afl-fuzz`` binary path
through environment variable. It thus has to be installed before the Python
module.

Installing AFL++
----------------

Compiling the AFL++ (with QEMU support) is as simple as:

.. code-block:: bash

    $ git clone https://github.com/AFLplusplus/AFLplusplus.git
    $ cd AFLplusplus
    $ make distrib
    $ cd qemu_mode/
    $ ./build_qemu_support.sh
    $ echo "export AFLPP_PATH=$PWD" >> ~/.profile

The only tricky part is the export of the AFL++ directory as environment
variable to make it discoverable by ``pastis-aflpp``. At the moment the
module does not intent to find automatically the ``afl-fuzz`` binary.


Installing Pastis-AFLPP
-----------------------

The only external dependency is ``libpastis``. It thus need to be installed
first (see appropriate section). Then getting in the pastis-aflpp directory
and install the module with:

.. code-block:: bash

    $ pip3 install .
