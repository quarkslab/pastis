# builtin imports
from pathlib import Path
from typing import List, Tuple, Optional

# Local imports
from libpastis.types import CoverageMode, ExecMode, FuzzMode


class EngineConfiguration(object):
    """
    Basic interface to represent an engine configuration file
    on broker side. A fuzzing engine have to provide such object
    so that the broker can load them and forwarding them to clients.
    """

    @staticmethod
    def new() -> 'EngineConfiguration':
        """
        Static method that should return a fresh configuration object.

        :return: Configuration object
        """
        raise NotImplementedError

    @staticmethod
    def from_file(filepath: Path) -> 'EngineConfiguration':
        """
        Load a configuration object from file.

        :param filepath: Path to the configuration
        :return: Configuration object
        """
        raise NotImplementedError

    @staticmethod
    def from_str(s: str) -> 'EngineConfiguration':
        """
        Parse a string to a configuration object.

        :param s: configuration as string
        :return: configuration object
        """
        raise NotImplementedError

    def to_str(self) -> str:
        """
        Serialize configuration object to string.

        :return: serialize configuration
        """
        raise NotImplementedError

    def get_coverage_mode(self) -> CoverageMode:
        """
        Should return the coverage mode defined in the configuration.
        For greybox fuzzer like AFL++, Honggfuzz one can return :py:obj:`CoverageMode.AUTO`.
        If the engine support different coverage metric it should return
        the one selected.

        :return: coverage mode used
        """
        raise NotImplementedError

    def set_target(self, target: int) -> None:
        """
        Set a specific target (address, index etc), that should be targeted by
        the fuzzing engine. This will be used when running in a targeted way.

        :param target: identifier of the target
        """
        pass


class FuzzingEngineDescriptor(object):
    """
    Abstract class describing a fuzzer engine. This object is used on
    broker side, to identify the name and version of a fuzzer and to
    know whether or not it accept a specific executable file.
    """

    NAME = "abstract-engine"
    #: Name of the fuzzing Engine
    SHORT_NAME = "AE"
    #: Short name of the fuzzing engine
    VERSION = "1.0"
    #: Version of the engine

    config_class = EngineConfiguration
    #: Configuration class associated with the engine

    @staticmethod
    def accept_file(binary_file: Path) -> Tuple[bool, Optional[ExecMode], Optional[FuzzMode]]:
        """
        Function called by the broker with all executable files detected in its directory.
        As an fuzzer developer, you have to implement this function to indicate whether
        a file is accepted as a target or not.

        :param binary_file: file path to an executable file
        :return: True if supported, and two optional attributes indicating the ExecMode and FuzzMode
        """
        raise NotImplementedError()

    @staticmethod
    def supported_coverage_strategies() -> List[CoverageMode]:
        """
        List of coverage metrics supported by the fuzzer. If it only
        support a single one, it should be :py:obj:`CoverageMode.AUTO`.

        :return: list of coverage modes
        """
        raise NotImplementedError()
