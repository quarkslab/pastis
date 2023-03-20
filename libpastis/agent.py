# built-ins
import time
from typing import Callable, Tuple, List, Union
from enum import Enum
import logging
import threading
from pathlib import Path
import socket

# third-party libs
import zmq
import psutil

# local imports
from libpastis.proto import InputSeedMsg, StartMsg, StopMsg, HelloMsg, LogMsg, \
                            TelemetryMsg, StopCoverageCriteria, DataMsg, EnvelopeMsg
from libpastis.types import SeedType, Arch, FuzzingEngineInfo, PathLike, ExecMode, CheckMode, CoverageMode, SeedInjectLoc, \
                            LogLevel, State, AlertData, Platform, FuzzMode
from libpastis.utils import get_local_architecture, get_local_platform

Message = Union[InputSeedMsg, StartMsg, StopMsg, HelloMsg, LogMsg, TelemetryMsg, StopCoverageCriteria, DataMsg]


class MessageType(Enum):  # Topics in the ZMQ terminology
    """
    Enum encoding the type of the message that can be received.
    """
    HELLO = 'hello_msg'
    # STATE = 1
    START = 'start_msg'
    INPUT_SEED = 'input_msg'
    TELEMETRY = 'telemetry_msg'
    LOG = 'log_msg'
    STOP_COVERAGE_DONE = 'stop_crit_msg'
    STOP = "stop_msg"
    DATA = "data_msg"


class AgentMode(Enum):
    """
    Internal enum identifying whether the agent is running as a broker
    or a client.
    """
    BROKER = 1
    CLIENT = 2


class NetworkAgent(object):
    """
    Base class for network-based PASTIS agents (both clients and servers)
    """
    def __init__(self):
        self.mode = None
        self.ctx = zmq.Context()
        self.socket = None
        self._stop = False
        self._th = None
        self._cbs = {x: [] for x in MessageType}

    def register_callback(self, typ: MessageType, callback: Callable) -> None:
        """
        Register a callback function on a given message type.

        :param typ: type of the message
        :param callback: Callback function taking the protobuf object as parameter
        :return: None
        """
        self._cbs[typ].append(callback)

    def bind(self, port: int = 5555, ip: str = "*") -> None:
        """
        Bind on the given IP and port, to listen incoming messages.

        :param port: listen port
        :param ip: IP, can be "*" to listen on all interfaces
        :return: None
        """
        self.socket = self.ctx.socket(zmq.ROUTER)
        self.socket.RCVTIMEO = 500  # 500 milliseconds
        self.socket.bind(f"tcp://{ip}:{port}")
        self.mode = AgentMode.BROKER

    def connect(self, remote: str = "localhost", port: int = 5555) -> bool:
        """
        Connect to a remote server on the given ``remote`` IP and ``port``.

        :param remote: IP address or DNS
        :param port: port to connect to
        :return: Always true
        """
        self.socket = self.ctx.socket(zmq.DEALER)
        self.socket.RCVTIMEO = 500  # 500 milliseconds
        self.socket.connect(f"tcp://{remote}:{port}")
        self.mode = AgentMode.CLIENT
        return True

    def start(self) -> None:
        """
        Start the listening thread.
        """
        self._th = threading.Thread(name="[LIBPASTIS]", target=self._recv_loop, daemon=True)
        self._th.start()

    def run(self) -> None:
        """
        Run receiving loop in a blocking manner.
        """
        self._recv_loop()

    def stop(self) -> None:
        """
        Stop the listening thread.
        """
        self._stop = True
        if self._th:
            self._th.join()

    def _recv_loop(self):
        #flags = 0 if blocking else zmq.DONTWAIT
        while 1:
            if self._stop:
                return
            try:
                if self.mode == AgentMode.BROKER:
                    uid, data = self.socket.recv_multipart()
                    self.__broker_transfer_to_callback(uid, data)
                else:
                    data = self.socket.recv()
                    self.__client_transfer_to_callback(data)
            except zmq.error.Again:
                pass

    def send_to(self, id: bytes, msg: Message, msg_type: MessageType = None) -> None:
        """
        Send a message to a given client. Only meant to be used when
        running as a server.

        :param id: bytes id of the client
        :param msg: protobuf :py:obj:`Message` object
        :param msg_type: type of the message
        """
        if self.mode == AgentMode.CLIENT:
            logging.error(f"cannot use sento_to() as {AgentMode.CLIENT.name}")
            return
        if msg_type is None:
            msg_type = self.msg_to_type(msg)
        final_msg = EnvelopeMsg()
        getattr(final_msg, msg_type.value).MergeFrom(msg)
        self.socket.send_multipart([id, final_msg.SerializeToString()])

    def send(self, msg: Message, msg_type: MessageType = None) -> None:
        """
        Send a message on the socket (thus to the broker). Should
        only be used as a client (fuzzing agent).

        :param msg: Protobuf message to send
        :param msg_type: Type of the message
        """
        if self.mode == AgentMode.BROKER:
            logging.error(f"cannot use sento() as {AgentMode.BROKER.name}")
            return
        if msg_type is None:
            msg_type = self.msg_to_type(msg)
        final_msg = EnvelopeMsg()
        getattr(final_msg, msg_type.value).CopyFrom(msg)
        self.socket.send(final_msg.SerializeToString())

    @staticmethod
    def msg_to_type(msg: Message) -> MessageType:
        """
        Get the :py:obj:`MessageType` from a protobuf object.

        :param msg: Protobuf message
        :return: message type
        """
        if isinstance(msg, InputSeedMsg):
            return MessageType.INPUT_SEED
        elif isinstance(msg, HelloMsg):
            return MessageType.HELLO
        elif isinstance(msg, TelemetryMsg):
            return MessageType.TELEMETRY
        elif isinstance(msg, LogMsg):
            return MessageType.LOG
        elif isinstance(msg, StopMsg):
            return MessageType.STOP
        elif isinstance(msg, StopCoverageCriteria):
            return MessageType.STOP_COVERAGE_DONE
        elif isinstance(msg, StartMsg):
            return MessageType.START
        elif isinstance(msg, DataMsg):
            return MessageType.DATA
        else:
            logging.error(f"invalid message type: {type(msg)} (cannot find associated topic)")

    def __broker_transfer_to_callback(self, id: bytes, message: bytes):
        try:
            msg = EnvelopeMsg()
            msg.ParseFromString(message)
        except:
            logging.error(f"can't parse message from {id} (len:{len(message)})")
            return
        message, topic = self._unpack_message(msg)
        if topic in [MessageType.START]:
            logging.error(f"Invalid message of type {topic.name} received")
        if not self._cbs[topic]:
            logging.warning(f"[broker] message of type {topic.name} (but no callback)")
        args = self._message_args(topic, message)
        for cb in self._cbs[topic]:
            cb(id, *args)

    def __client_transfer_to_callback(self, message: bytes):
        msg = EnvelopeMsg()
        msg.ParseFromString(message)
        message, topic = self._unpack_message(msg)
        if topic in [MessageType.HELLO, MessageType.TELEMETRY, MessageType.LOG, MessageType.STOP_COVERAGE_DONE]:
            logging.error(f"Invalid message of type {topic.name} received")
        if not self._cbs[topic]:
            logging.warning(f"[agent] message of type {topic.name} (but no callback)")
        args = self._message_args(topic, message)
        for cb in self._cbs[topic]:
            cb(*args)

    def _unpack_message(self, message: EnvelopeMsg) -> Tuple[MessageType, Message]:
        typ = message.WhichOneof('msg')
        return getattr(message, typ), MessageType(typ)

    def _message_args(self, topic: MessageType, msg: Message):
        if topic == MessageType.INPUT_SEED:
            return [SeedType(msg.type), msg.seed]
        elif topic == MessageType.LOG:
            return [LogLevel(msg.level), msg.message]
        elif topic == MessageType.TELEMETRY:
            return [msg.state, msg.exec_per_sec, msg.total_exec, msg.cycle, msg.timeout, msg.coverage_block,
                    msg.coverage_edge, msg.coverage_path, msg.last_cov_update]
        elif topic == MessageType.HELLO:
            engs = [(FuzzingEngineInfo.from_pb(x)) for x in msg.engines]
            return [engs, Arch(msg.architecture), msg.cpus, msg.memory, msg.hostname, Platform(msg.platform)]
        elif topic == MessageType.START:
            return [msg.binary_filename, msg.binary, FuzzingEngineInfo.from_pb(msg.engine), ExecMode(msg.exec_mode), FuzzMode(msg.fuzz_mode),
                    CheckMode(msg.check_mode), CoverageMode(msg.coverage_mode), SeedInjectLoc(msg.seed_location),
                    msg.engine_args, [x for x in msg.program_argv], msg.sast_report]
        elif topic == MessageType.DATA:
            return [msg.data]
        else:  # for stop and store_coverage_done nothing to unpack
            return []


class BrokerAgent(NetworkAgent):

    def send_seed(self, id: bytes, typ: SeedType, seed: bytes) -> None:
        """
        Send the given input to the client `id`.

        :param id: raw id of the client
        :param typ: Type of the input
        :param seed: Bytes the of input
        """
        msg = InputSeedMsg()
        msg.type = typ.value
        msg.seed = seed
        self.send_to(id, msg, msg_type=MessageType.INPUT_SEED)

    def send_start(self, id: bytes, name: str, package: PathLike, argv: List[str], exmode: ExecMode, fuzzmode: FuzzMode,
                   ckmode: CheckMode, covmode: CoverageMode, engine: FuzzingEngineInfo, engine_args: str,
                   seed_loc: SeedInjectLoc, sast_report: bytes = None) -> None:
        """
        Send a START message to a fuzzing agent with all the parameters it is meant to run with.

        :param id: raw id of the client
        :param name: name of the executable file or binary package
        :param package: filepath of :py:obj:`BinaryPackage` or program executable to send
        :param argv: argumnets to be provided on command line
        :param exmode: execution mode
        :param fuzzmode: fuzzing mode
        :param ckmode: checking mode
        :param covmode: coverage metric to use
        :param engine: descriptor of the fuzzing engine
        :param engine_args: engine's additional arguments or configuration file
        :param seed_loc: location where to provide inputs (stdin or argv)
        :param sast_report: SAST report if applicable
        """
        msg = StartMsg()
        if isinstance(package, str):
            package = Path(package)
        msg.binary_filename = name
        msg.binary = package.read_bytes()
        msg.engine.name = engine.name
        msg.engine.version = engine.version
        msg.exec_mode = exmode.value
        msg.fuzz_mode = fuzzmode.value
        msg.check_mode = ckmode.value
        msg.coverage_mode = covmode.value
        msg.seed_location = seed_loc.value
        msg.engine_args = engine_args
        if sast_report is not None:
            msg.sast_report = sast_report
        for arg in argv:
            msg.program_argv.append(arg)
        self.send_to(id, msg, msg_type=MessageType.START)

    def send_stop(self, id: bytes) -> None:
        """
        Send a stop message to the client.

        :param id: raw id of the client
        """
        msg = StopMsg()
        self.send_to(id, msg, msg_type=MessageType.STOP)

    def register_seed_callback(self, cb: Callable) -> None:
        self.register_callback(MessageType.INPUT_SEED, cb)

    def register_hello_callback(self, cb: Callable) -> None:
        self.register_callback(MessageType.HELLO, cb)

    def register_log_callback(self, cb: Callable) -> None:
        self.register_callback(MessageType.LOG, cb)

    def register_telemetry_callback(self, cb: Callable) -> None:
        self.register_callback(MessageType.TELEMETRY, cb)

    def register_stop_coverage_callback(self, cb: Callable) -> None:
        self.register_callback(MessageType.STOP_COVERAGE_DONE, cb)

    def register_data_callback(self, cb: Callable) -> None:
        self.register_callback(MessageType.DATA, cb)


class ClientAgent(NetworkAgent):
    """
    Subclass of NetworkAgent to connect to PASTIS as a fuzzing
    agent. The class provides helper methods to interact with
    the broker.
    """

    def send_hello(self, engines: List[FuzzingEngineInfo], arch: Arch = None, platform: Platform = None) -> bool:
        """
        Send the hello message to the broker. `engines` parameter is the list of fuzzing engines
        that "we" as client support. E.g: Pastisd is meant to be an interface for all engines
        locally, so it will advertise multiple engines.

        :param engines: list of engines, the client is able to launch
        :param arch: the architecture supported (if None, local one is used)
        :param platform: the platform supported (if None local one used)
        """
        msg = HelloMsg()
        arch = get_local_architecture() if arch is None else arch
        if arch is None:
            logging.error(f"current architecture: {platform.machine()} is not supported")
            return False
        plfm = get_local_platform() if platform is None else platform
        if plfm is None:
            logging.error(f"current platform is not supported")
            return False
        msg.architecture = arch.value
        msg.cpus = psutil.cpu_count()
        msg.memory = psutil.virtual_memory().total
        msg.hostname = socket.gethostname()
        msg.platform = plfm.value
        for eng in engines:
            msg.engines.add(name=eng.name, version=eng.version, pymodule=eng.pymodule)
        self.send(msg, msg_type=MessageType.HELLO)

    def send_log(self, level: LogLevel, message: str) -> None:
        """
        Log message to be sent and printed by the broker. All
        logs received by the broker are logged in a client specific
        logfile.

        :param level: level of the log message
        :param message: message as a string
        """
        self.send(LogMsg(level=level.value, message=message), MessageType.LOG)

    def debug(self, message: str) -> None:
        """
        Send a debug message to the broker

        :param message: message as a string
        """
        self.send_log(LogLevel.DEBUG, message)

    def info(self, message: str) -> None:
        """
        Send an info (level) message to the broker

        :param message: message to send
        """
        self.send_log(LogLevel.INFO, message)

    def warning(self, message: str) -> None:
        """
        Send a warning (level) message to the broker.

        :param message: message to send
        """
        self.send_log(LogLevel.WARNING, message)

    def error(self, message: str) -> None:
        """
        Send an error (level) message to the broker.

        :param message: message to send
        """
        self.send_log(LogLevel.ERROR, message)

    def critical(self, message: str) -> None:
        """
        Send a critical (level) message to the broker.

        :param message: message to send
        """
        self.send_log(LogLevel.CRITICAL, message)

    def send_telemetry(self,
                       state: State = None,
                       exec_per_sec: int = None,
                       total_exec: int = None,
                       cycle: int = None,
                       timeout: int = None,
                       coverage_block: int = None,
                       coverage_edge: int = None,
                       coverage_path: int = None,
                       last_cov_update: int = None) -> None:
        """
        Send a telemetry message to the broker. These data could be used on the
        broker side to plot statistics.

        :param state: current state of the fuzzer
        :param exec_per_sec: number of execution per seconds
        :param total_exec: total number of executions
        :param cycle: number of cycles
        :param timeout: timeout numbers
        :param coverage_block: coverage count in blocks
        :param coverage_edge: coverage count in edges
        :param coverage_path: coverage count in paths
        :param last_cov_update: last coverage update
        """
        msg = TelemetryMsg()
        msg.cpu_usage = psutil.cpu_percent()
        msg.mem_usage = psutil.virtual_memory().percent
        if state:
            msg.state = state.value
        if exec_per_sec:
            msg.exec_per_sec = exec_per_sec
        if total_exec:
            msg.total_exec = total_exec
        if cycle:
            msg.cycle = cycle
        if timeout:
            msg.timeout = timeout
        if coverage_block:
            msg.coverage_block = coverage_block
        if coverage_edge:
            msg.coverage_edge = coverage_edge
        if coverage_path:
            msg.coverage_path = coverage_path
        if last_cov_update:
            msg.last_cov_update = last_cov_update
        self.send(msg, msg_type=MessageType.TELEMETRY)

    def send_stop_coverage_criteria(self) -> None:
        """
        Send a message to the broker indicating, the program has been fully
        covered in accordance to the coverage criteria (metric).
        """
        self.send(StopCoverageCriteria(), MessageType.STOP_COVERAGE_DONE)

    def send_seed(self, typ: SeedType, seed: bytes) -> None:
        """
        Send an input seed to the broker. The ``typ`` indicates
        the type of the seed, namely, input, crash or hang.

        :param typ: type of the input
        :param seed: bytes of the input
        """
        msg = InputSeedMsg()
        msg.type = typ.value
        msg.seed = seed
        self.send(msg, msg_type=MessageType.INPUT_SEED)

    def send_alert_data(self, alert_data: AlertData) -> None:
        """
        Send information related to the coverage or validation of a specific SAST
        alert.

        :param alert_data: alert object
        """
        msg = DataMsg()
        msg.data = alert_data.to_json()
        self.send(msg, msg_type=MessageType.DATA)

    def register_start_callback(self, cb: Callable) -> None:
        """
        Register a callback that will be called when a start message will
        be received. The callback should take 11 parameters.

        :param cb: callback function.
        """
        self.register_callback(MessageType.START, cb)

    def register_stop_callback(self, cb: Callable) -> None:
        """
        Register a callback called when the broker send a STOP
        message. The fuzzing has to stop running and sending data.

        :param cb: callback function
        """
        self.register_callback(MessageType.STOP, cb)

    def register_seed_callback(self, cb: Callable) -> None:
        """
        Register a callback called when an input seed is received from the
        broker. The callback function take 2 parameters seed type and content.

        :param cb: callback function
        """
        self.register_callback(MessageType.INPUT_SEED, cb)

    def register_data_callback(self, cb: Callable) -> None:
        """
        Register callback called when data is received. At the moment
        data are necessarily AlertData messages.

        :param cb: callback function
        """
        self.register_callback(MessageType.DATA, cb)



class FileAgent(ClientAgent):
    """
    Mock agent that will mimick all APIs function of a network agent
    but which will never receive any incoming messages. All messages
    sent are logged to a file
    """

    def __init__(self, level=logging.INFO, log_file: str = None):
        super(FileAgent, self).__init__()
        del self.ctx    # Remove network related attributes
        del self.socket
        self.logger = logging.getLogger('FileAgent')
        self.logger.parent = None  # Remove root handler to make sur it is not printed on output

        # create file handler
        if log_file is not None:
            ch = logging.FileHandler(log_file)
            ch.setLevel(level)
            ch.setFormatter(logging.Formatter('%(asctime)s - [%(name)s] [%(levelname)s]: %(message)s'))
            self.logger.addHandler(ch)

    def bind(self, port: int = 5555, ip: str = "*"):
        raise RuntimeError("FileAgent is not meant to be used as broker")

    def connect(self, remote: str = "localhost", port: int = 5555) -> bool:
        return True  # Do nothing

    def _recv_loop(self):
        while 1:
            if self._stop:
                return
            time.sleep(0.05)

    def send_to(self, id: bytes, msg: Message, msg_type: MessageType = None):
        raise RuntimeError("FileAgent is not meant to be used as broker")

    def send(self, msg: Message, msg_type: MessageType = None):
        if self.mode == AgentMode.BROKER:
            logging.error(f"cannot use sento() as {AgentMode.BROKER.name}")
            return
        if msg_type is None:
            msg_type = self.msg_to_type(msg)

        if isinstance(msg, InputSeedMsg):
            msg = f"{SeedType(msg.type).name}: {msg.seed[:20]}.."
        elif isinstance(msg, HelloMsg):
            msg = f"{msg.hostname}: {Platform(msg.platform)}({Arch(msg.architecture)}) CPU:{msg.cpus} engines:{[x.name for x in msg.engines]}"
        elif isinstance(msg, TelemetryMsg):
            msg = f"{State(msg.state).name} exec/s: {msg.exec_per_sec} total:{msg.total_exec}"
        elif isinstance(msg, LogMsg):
            msg = f"{LogLevel(msg.level).name}: {msg.message}"
        elif isinstance(msg, DataMsg):
            msg = f"Data: {msg.data}"
        elif isinstance(msg, StopCoverageCriteria):
            msg = ""
        else:
            logging.error(f"invalid message type: {type(msg)} as client")
            return

        self.logger.info(f"send {msg_type.name} {msg}")
