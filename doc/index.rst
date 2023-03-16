
.. figure:: figs/logo_pastis_background.png
  :width: 550
  :align: center
  :figclass: align-center


Project Overview
================

The PASTIS project is a fuzzing framework aiming at combining various software testing techniques
within the same workflow to perform collaborative fuzzing also called ensemble fuzzing.

..
    The following
    video gives a very brief overview of challenges and goals PASTIS is trying to achieve;

    TODO: Put video link


Code Components
===============

The codebase is articulated around 3 main components, which, combined together
forms the whole PASTIS infrastructure.

**libpastis**: Pure python library designed perform all network communications
in the context of PASTIS. Its API mostly expose two classes :py:class:`ClientAgent`
and :py:class:`BrokerAgent` that enable acting as a client or a broker respectively.
It also exposes common types between components.

**broker**: head of the infrastructure, acting as an intermediate between each
engines connected. It is in charge of ensuring a maximal sharing of
seeds between clients. Ensuring this sharing enable theoretically to have the same coverage
for all clients. That project is the main interface with the analyst as all configuration options of a
campain are set in pastis-broker and propagated to all clients automatically.

**engines**: They are fuzzing agents, testing the target. They connect to
the broker to receive the fuzzing configuration and initial corpus. Then,
these agents send back to the broker the test-cases produced and absorb
new ones received from the broker.



PASTIS in action
----------------

.. raw:: html

    <video width="700" height="350" controls>
      <source src="_static/demo.ogv" type="video/mp4">
    Your browser does not support the video tag.
    </video>
    <br/>



.. toctree::
   :caption: Getting Started
   :maxdepth: 2

    Installation <installation>
    Running PASTIS <campaign>
    Adding a Fuzzer <adding-fuzzer>


.. toctree::
   :caption: Fuzzing Engines
   :maxdepth: 3

    AFL++ <engines/aflpp>
    Honggfuzz <engines/honggfuzz>
    TritonDSE <engines/tritondse>


.. toctree::
   :caption: Tutorials
   :maxdepth: 3

    Demo FSM <tutorials/demo-fsm>

.. toctree::
    :caption: Python API
    :maxdepth: 2

    libpastis <api/libpastis>

..
    pastis-aflpp <api/aflpp>
    pastis-honggfuzz <api/honggfuzz>
    pastis-triton <api/tritondse>



Credits
=======

Sponsors and supporters of the project.

.. figure:: figs/quarkslab_logo.png
  :width: 200
  :align: right
  :alt: Quarkslab Logo
  :figclass: align-center

.. figure:: figs/dga_logo.png
  :width: 200
  :align: right
  :alt: DGA Logo
  :figclass: align-center
