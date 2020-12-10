.. _label_agent_api:

Agents
======

Client Agent
------------

A full working example of a simple :py:class:`ClientAgent` is the following:

.. code-block:: python

    import logging
    from typing import List
    from libpastis.agent import ClientAgent
    from libpastis.types import SeedType, FuzzingEngine, ExecMode, CoverageMode, SeedInjectLoc, CheckMode, LogLevel, State

    def start_received(fname: str, binary: bytes, engine: FuzzingEngine, exmode: ExecMode, chkmode: CheckMode,
                       covmode: CoverageMode, seed_inj: SeedInjectLoc,
                       engine_args: str, argv: List[str], kl_report: str=None):
        pass # commencer la campagne

    def seed_received(typ: SeedType, seed: bytes):
        logging.info(f"[SEED] { seed.hex()} ({ typ} )")

    def stop_received():
        logging.info(f"[STOP]")

    if __name__ == "__main__":
        agent = ClientAgent()
        agent.connect() # default is localhost:5555
        agent.register_start_callback(start_received)
        agent.register_seed_callback(seed_received)
        agent.register_stop_callback(stop_received)
        agent.start() # start reception thread
        agent.send_hello([(FuzzingEngine.TRITON, "v0.8")])



.. autoclass:: libpastis.ClientAgent
    :members:
    :show-inheritance:
    :inherited-members:
    :undoc-members:
    :exclude-members:


Broker Agent
------------

.. autoclass:: libpastis.BrokerAgent
    :members:
    :show-inheritance:
    :inherited-members:
    :undoc-members:
    :exclude-members:


File Agent
----------

This class is a dummy agent that expose the same API that a :py:class:`ClientAgent` or
a :py:class:`BrokerAgent` but does nothing but logging results of messages that shall
have been sent.

.. autoclass:: libpastis.FileAgent
    :members:
    :inherited-members:
    :undoc-members:
    :exclude-members:
