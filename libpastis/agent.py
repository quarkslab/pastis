# built-ins
import time
from typing import Callable, Optional, Tuple, List, Union, Dict
from enum import Enum
import logging
import threading
from pathlib import Path
import socket
import platform

# third-party libs
import zmq
import psutil

# local imports
from libpastis.proto import InputSeedMsg, StartMsg, StopMsg, HelloMsg, LogMsg, \
                            TelemetryMsg, StopCoverageCriteria, DataMsg, EnvelopeMsg
from libpastis.types import SeedType, Arch, FuzzingEngine, PathLike, ExecMode, CheckMode, CoverageMode, SeedInjectLoc, \
                            LogLevel, State, AlertData, Platform
from libpastis.utils import get_local_architecture, get_local_platform

Message = Union[InputSeedMsg, StartMsg, StopMsg, HelloMsg, LogMsg, TelemetryMsg, StopCoverageCriteria, DataMsg]


class MessageType(Enum):  # Topics in the ZMQ terminology
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
    def __init__(self):
        self.mode = None
        self.ctx = zmq.Context()
        self.socket = None
        self._stop = False
        self._th = None
        self._cbs = {x: [] for x in MessageType}

    def register_callback(self, typ: MessageType, callback: Callable) -> None:
        self._cbs[typ].append(callback)

    def bind(self, port: int = 5555):
        self.socket = self.ctx.socket(zmq.ROUTER)
        self.socket.RCVTIMEO = 500  # 500 milliseconds
        self.socket.bind(f"tcp://*:{port}")
        self.mode = AgentMode.BROKER

    def connect(self, remote: str = "localhost", port: int = 5555) -> bool:
        self.socket = self.ctx.socket(zmq.DEALER)
        self.socket.RCVTIMEO = 500  # 500 milliseconds
        self.socket.connect(f"tcp://{remote}:{port}")
        self.mode = AgentMode.CLIENT
        return True

    def start(self):
        self._th = threading.Thread(target=self._recv_loop, daemon=True)
        self._th.start()

    def run(self):
        self._recv_loop()

    def stop(self):
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

    def send_to(self, id: bytes, msg: Message, msg_type: MessageType=None):
        if self.mode == AgentMode.CLIENT:
            logging.error(f"cannot use sento_to() as {AgentMode.CLIENT.name}")
            return
        if msg_type is None:
            msg_type = self.msg_to_type(msg)
        final_msg = EnvelopeMsg()
        getattr(final_msg, msg_type.value).MergeFrom(msg)
        self.socket.send_multipart([id, final_msg.SerializeToString()])

    def send(self, msg: Message, msg_type: MessageType=None):
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
        msg = EnvelopeMsg()
        msg.ParseFromString(message)
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
            engs = [(FuzzingEngine(x), y) for x, y in zip(msg.engines, msg.versions)]
            return [engs, Arch(msg.architecture), msg.cpus, msg.memory, msg.hostname, Platform(msg.platform)]
        elif topic == MessageType.START:
            return [msg.binary_filename, msg.binary, FuzzingEngine(msg.engine), ExecMode(msg.exec_mode),
                    CheckMode(msg.check_mode), CoverageMode(msg.coverage_mode), SeedInjectLoc(msg.seed_location),
                    msg.engine_args, [x for x in msg.program_argv], msg.klocwork_report]
        elif topic == MessageType.DATA:
            return [msg.data]
        else:  # for stop and store_coverage_done nothing to unpack
            return []


class BrokerAgent(NetworkAgent):

    def send_seed(self, id: bytes, typ: SeedType, seed: bytes):
        msg = InputSeedMsg()
        msg.type = typ.value
        msg.seed = seed
        self.send_to(id, msg, msg_type=MessageType.INPUT_SEED)

    def send_start(self, id: bytes, program: PathLike, argv: List[str], exmode: ExecMode, ckmode: CheckMode,
                   covmode: CoverageMode, engine: FuzzingEngine, engine_args: str,
                   seed_loc: SeedInjectLoc, kl_report: str=None):
        msg = StartMsg()
        if isinstance(program, str):
            program = Path(program)
        msg.binary_filename = program.name
        msg.binary = program.read_bytes()
        msg.engine = engine.value
        msg.exec_mode = exmode.value
        msg.check_mode = ckmode.value
        msg.coverage_mode = covmode.value
        msg.seed_location = seed_loc.value
        msg.engine_args = engine_args
        if kl_report is not None:
            msg.klocwork_report = kl_report
        for arg in argv:
            msg.program_argv.append(arg)
        self.send_to(id, msg, msg_type=MessageType.START)

    def send_stop(self, id: bytes):
        msg = StopMsg()
        self.send_to(id, msg, msg_type=MessageType.STOP)

    def register_seed_callback(self, cb: Callable):
        self.register_callback(MessageType.INPUT_SEED, cb)

    def register_hello_callback(self, cb: Callable):
        self.register_callback(MessageType.HELLO, cb)

    def register_log_callback(self, cb: Callable):
        self.register_callback(MessageType.LOG, cb)

    def register_telemetry_callback(self, cb: Callable):
        self.register_callback(MessageType.TELEMETRY, cb)

    def register_stop_coverage_callback(self, cb: Callable):
        self.register_callback(MessageType.STOP_COVERAGE_DONE, cb)

    def register_data_callback(self, cb: Callable):
        self.register_callback(MessageType.DATA, cb)


class ClientAgent(NetworkAgent):

    def send_hello(self, engines: List[Tuple[FuzzingEngine, str]], arch: Arch = None, platform: Platform = None) -> bool:
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
        for eng, version in engines:
            msg.engines.append(eng.value)
            msg.versions.append(version)
        self.send(msg, msg_type=MessageType.HELLO)

    def send_log(self, level: LogLevel, message: str):
        self.send(LogMsg(level=level.value, message=message), MessageType.LOG)

    def debug(self, message: str):
        self.send_log(LogLevel.DEBUG, message)

    def info(self, message: str):
        self.send_log(LogLevel.INFO, message)

    def warning(self, message: str):
        self.send_log(LogLevel.WARNING, message)

    def error(self, message: str):
        self.send_log(LogLevel.ERROR, message)

    def critical(self, message: str):
        self.send_log(LogLevel.CRITICAL, message)

    def send_telemetry(self, state: State = None, exec_per_sec: int = None, total_exec: int = None, cycle: int = None,
                       timeout: int = None, coverage_block: int = None, coverage_edge: int = None,
                       coverage_path: int = None, last_cov_update: int = None):
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

    def send_stop_coverage_criteria(self):
        self.send(StopCoverageCriteria(), MessageType.STOP_COVERAGE_DONE)

    def send_seed(self, typ: SeedType, seed: bytes):
        msg = InputSeedMsg()
        msg.type = typ.value
        msg.seed = seed
        self.send(msg, msg_type=MessageType.INPUT_SEED)

    def send_alert_data(self, alert_data: AlertData):
        msg = DataMsg()
        msg.data = alert_data.to_json()
        self.send(msg, msg_type=MessageType.DATA)

    def register_start_callback(self, cb: Callable):
        self.register_callback(MessageType.START, cb)

    def register_stop_callback(self, cb: Callable):
        self.register_callback(MessageType.STOP, cb)

    def register_seed_callback(self, cb: Callable):
        self.register_callback(MessageType.INPUT_SEED, cb)

    def register_data_callback(self, cb: Callable):
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

    def bind(self, port: int = 5555):
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
            msg = f"{msg.hostname}: {Platform(msg.platform)}({Arch(msg.architecture)}) CPU:{msg.cpus} engines:{[FuzzingEngine(x).name for x in msg.engines]}"
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
