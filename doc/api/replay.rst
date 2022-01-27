.. _label_replay:

Replay
------

The Python module, provide a very basic replay engine allowing to re-run the
target with a given input, to check its return code or its output. Using the
``subprocess`` module it is being used to analyse inputs *(for checking
coverage and validating klocwork alerts)*. At the moment the :py:class:`Replay`
search for specific pattern ``rb".*REACHED ID (\d+)"`` to identify PASTIS
intrinsics covered. The following snippet shows how to re-run the target on
a given input and checking various properties.


.. code-block:: python

    from pastisaflpp.replay import Replay

    # Rerun the program with the seed
    run = Replay.run("/tmp/target.bin",
                     "a b c",  # argv
                     stdin_file="/tmp/seed.cov",
                     timeout=5,  # To bound execution time
                     cwd="/tmp/") # If the binary is sensitive to location where it runs

    if run.has_crashed():  # Returncode != 0
        print("Crash")
    elif run.has_hanged():  # Timeout was triggered
        print("hang")
    else:
        if run.is_asan_without_crash():  # Some ASAN warnings yielded but without crash
            print("something suspicious")
        else:
            print("ok")

``pastisaflpp.replay``
----------------------

.. autoclass:: pastisaflpp.replay
    :members:
    :show-inheritance:
    :inherited-members:
    :undoc-members:
    :exclude-members:
