from .types import FuzzingEngine


def do_engine_support_coverage_strategy(engine: FuzzingEngine) -> bool:
    """
    Utility function to check whether the fuzzing engine support
    different coverage strategy

    .. NOTE: Shall we return the list of supported strategies ?

    :param engine: engine to check
    :return: boolean if engine support variadic coverage strategies
    """
    return {FuzzingEngine.TRITON: True,
             FuzzingEngine.HONGGFUZZ: False}[engine]
