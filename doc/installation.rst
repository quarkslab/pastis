Pastis-DSE Installation
=======================

Pastis-dse relies on multiple dependencies. That must be installed beforehand.
The steps to install it are:

* Installing libpastis
* Installing klocwork module
* Installing Triton `(documentation) <https://triton.quarkslab.com/documentation/doxygen/index.html#install_sec>`_
* Installing tritondse

Then once all these dependencies are installed the installation can be made
with:

.. code-block:: bash

    $ cd pastis-dse
    $ pip3 install .

After installation the utility ``pastis-triton`` should be available in the PATH.
