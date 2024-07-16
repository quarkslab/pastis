FSM Demo
========

The FSM demo is a tiny software implementing a state-machine that contains a bug.
It shows how to combine the various approaches into a collaborative fuzzing campaign
within the PASTIS framework.

The code ``fsm.c`` read "packets" on stdin. Each packet is a struct composed of an ID
on 16 bits and a data integer on 32 bits. Depending on the ID and the data
the FSM switches state.

.. raw:: html

    <div style="text-align: center;"><a href="../_static/fsm-demo.tar.gz"><i class="fa fa-download fa-lg"></i><br/>code</a></div><br/>



Preparing the target
--------------------

To prepare the target it has to be compiled for all the supported engines in our
case AFL++, Honggfuzz and TritonDSE.

.. code-block:: bash

    tar xvf fsm-demo.tar.gz
    cd fsm-demo
    make

The Makefile is rather straighforward for such a simple case. Note
that TritonDSE compiles without any instrumentation.

.. code-block:: makefile

    CC=clang
    AFL-CC=afl-clang
    HF-CC=hfuzz-clang
    CFLAGS=-Wall -g -fno-pie
    CFLAGS=-Wall -g

    all: triton hfuzz afl
        echo "done"

    triton:
        $(CC) $(CFLAGS) src/fsm.c -o bin/fsm.tt

    hfuzz:
        $(HF-CC) $(CFLAGS) src/fsm.c -o bin/fsm.hf

    afl:
        $(AFL-CC) $(CFLAGS) src/fsm.c -o bin/fsm.afl


Running the Broker
------------------

Now that targets are compile it now time to run the broker and then engines.
By default engines contact localhost on port 5555. If run from a remote machine
the IP and port have to be provided. The broker can be run with:

.. code-block:: bash

    pastis-broker -b bin -s initial -w output

It will use *bin* as the directory containing compiled variants, *initial* as the
initial corpus and will write all its output to the workspace *output*. Once,
launched it should have detected the various variants and wait for clients to connect.


Running AFL++
-------------

The target is ready to be fuzzed. One can launch AFL++ on the target with:

.. code-block:: bash

    pastis-aflpp online


Running TritonDSE
-----------------

Once ready we can run TritonDSE on the target with:

.. code-block:: bash

    pastis-tritondse online

It will connect the broker that will send it the *fsm.tt* target with the right
configuration.

.. note:: If you want to run TritonDSE with a specific configuration it has to be
          be provided via the broker with ``-e pastistritondse.addon --tt-config conf.json``.
          The ``-e`` preload the tritondse addon in order to be able to load the
          configuration file.


Post campaign
-------------

Once the campaign terminated. You can retrieve the whole broker
workspace in the *output* directory.