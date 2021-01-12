Installation
============

As the ultimate top component of PASTIS, ``pastisd`` relies on all underlying components, namely hf-wrapper
and pastisdse. The utility checks that both project can be imported which means they are installed before
advertizing their availability to the broker. So ``pastisd`` is not dependent, however having only one of
them strongly reduces the relevancy of such utility.

* Installing pastisdse
* Installing hf-wrapper

Then the utility can be installed with:

.. code-block:: bash

    $ cd pastisd
    $ pip3 install .

After installation the utility ``pastisd`` should be available in the $PATH.
