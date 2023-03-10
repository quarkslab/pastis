.. _pastisd_usage:

pastisd usage
=============

The utility ``pastisd`` is solely meant to be used with a broker. It can be run with:

::

    $ pastisd

Under these settings the host reached is **pastis.lan:5555**. Otherwise the host can
be specified with:

::

    $ pastisd 8.8.8.8

.. warning:: In both cases, to use Honggfuzz the environment variable ``HF_PATH`` should be exported.

