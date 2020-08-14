from typing import Callable, Optional, Tuple, List, Union, Dict
from enum import Enum
import logging
import threading
import abc
from pathlib import Path
import inspect

import zmq
import psutil

from libpastis.proto import InputSeedMsg, StartMsg, StopMsg, HelloMsg, LogMsg, \
                            TelemetryMsg, StopCoverageCriteria
from libpastis.types import SeedType, Arch, FuzzingEngine, PathLike, ExecMode, CheckMode, CoverageMode, SeedInjectLoc, \
                            LogLevel, State

Message = Union[InputSeedMsg, StartMsg, StopMsg, HelloMsg, LogMsg, TelemetryMsg, StopCoverageCriteria]


class MessageType(Enum):  # Topics in the ZMQ terminology
    HELLO = b'H'
    # STATE = 1
    START = b'S'
    INPUT_SEED = b'I'
    TELEMETRY = b'T'
    LOG = b'L'
    STOP_COVERAGE_DONE = b'C'
    STOP = b"P"


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
                    uid, topic, data = self.socket.recv_multipart()
                    self.__broker_transfer_to_callback(uid, MessageType(topic), data)
                else:
                    topic, data = self.socket.recv_multipart()
                    self.__client_transfer_to_callback(MessageType(topic), data)
            except zmq.error.Again:
                pass
            except ValueError:
                logging.error(f"Invalid topic: {topic}")

    def send_to(self, id: bytes, msg: Message, msg_type: MessageType=None):
        if self.mode == AgentMode.CLIENT:
            logging.error(f"cannot use sento_to() as {AgentMode.CLIENT.name}")
            return
        if msg_type is None:
            msg_type = self.msg_to_type(msg)
        self.socket.send_multipart([id, msg_type.value, msg.SerializeToString()])

    def send(self, msg: Message, msg_type: MessageType=None):
        if self.mode == AgentMode.BROKER:
            logging.error(f"cannot use sento() as {AgentMode.BROKER.name}")
            return
        if msg_type is None:
            msg_type = self.msg_to_type(msg)
        self.socket.send_multipart([msg_type.value, msg.SerializeToString()])

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
        else:
            logging.error(f"invalid message type: {type(msg)} (cannot find associated topic)")

    def __broker_transfer_to_callback(self, id: bytes, topic: MessageType, message: bytes):
        if topic in [MessageType.START]:
            logging.error(f"Invalid message of type {topic.name} received")
        if not self._cbs[topic]:
            logging.warning(f"[broker] message of type {topic.name} (but no callback)")
        args = self._unpack_message(topic, message)
        for cb in self._cbs[topic]:
            cb(id, *args)

    def __client_transfer_to_callback(self, topic: MessageType, message: bytes):
        if topic in [MessageType.HELLO, MessageType.TELEMETRY, MessageType.LOG, MessageType.STOP_COVERAGE_DONE]:
            logging.error(f"Invalid message of type {topic.name} received")
        if not self._cbs[topic]:
            logging.warning(f"[agent] message of type {topic.name} (but no callback)")
        args = self._unpack_message(topic, message)
        for cb in self._cbs[topic]:
            cb(*args)

    def _unpack_message(self, topic: MessageType, message: bytes):
        if topic == MessageType.INPUT_SEED:
            msg = InputSeedMsg.FromString(message)
            return [SeedType(msg.type), msg.seed, FuzzingEngine(msg.origin)]
        elif topic == MessageType.LOG:
            msg = LogMsg.FromString(message)
            return [LogLevel(msg.level), msg.message]
        elif topic == MessageType.TELEMETRY:
            msg = TelemetryMsg.FromString(message)
            return [msg.state, msg.exec_per_sec, msg.total_exec, msg.cycle, msg.timeout, msg.coverage_block,
                    msg.coverage_edge, msg.coverage_path, msg.last_cov_update]
        elif topic == MessageType.HELLO:
            msg = HelloMsg.FromString(message)
            engs = [(FuzzingEngine(x), y) for x, y in zip(msg.engines, msg.versions)]
            return [engs, Arch(msg.architecture), msg.cpus, msg.memory]
        elif topic == MessageType.START:
            msg = StartMsg.FromString(message)
            return [msg.binary_filename, msg.binary, FuzzingEngine(msg.engine), ExecMode(msg.exec_mode),
                    CheckMode(msg.check_mode), CoverageMode(msg.coverage_mode), SeedInjectLoc(msg.seed_location),
                    msg.engine_args, [x for x in msg.program_argv], msg.klocwork_report]
        else:  # for stop and store_coverage_done nothing to unpack
            return []


class BrokerAgent(NetworkAgent):

    def send_seed(self, id: bytes, typ: SeedType, seed: bytes, origin: FuzzingEngine):
        msg = InputSeedMsg()
        msg.type = typ.value
        msg.seed = seed
        msg.origin = origin.value
        self.send_to(id, msg, msg_type=MessageType.INPUT_SEED)

    def send_start(self, id: bytes, program: PathLike, argv: List[str], exmode: ExecMode, ckmode: CheckMode,
                   covmode: CoverageMode, engine: FuzzingEngine, engine_args: str,
                   seed_type: SeedInjectLoc, kl_report: str=None):
        msg = StartMsg()
        if isinstance(program, str):
            program = Path(program)
        msg.binary_filename = program.name
        msg.binary = program.read_bytes()
        msg.engine = engine.value
        msg.exec_mode = exmode.value
        msg.check_mode = ckmode.value
        msg.coverage_mode = covmode.value
        msg.seed_location = seed_type.value
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


class ClientAgent(NetworkAgent):

    def send_hello(self, engines: List[Tuple[FuzzingEngine, str]], arch: Arch = None):
        msg = HelloMsg()
        msg.cpus = psutil.cpu_count()
        msg.memory = psutil.virtual_memory().total
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

    def send_seed(self, typ: SeedType, seed: bytes, origin: FuzzingEngine):
        msg = InputSeedMsg()
        msg.type = typ.value
        msg.seed = seed
        msg.origin = origin.value
        self.send(msg, msg_type=MessageType.INPUT_SEED)

    def register_start_callback(self, cb: Callable):
        self.register_callback(MessageType.START, cb)

    def register_stop_callback(self, cb: Callable):
        self.register_callback(MessageType.STOP, cb)

    def register_seed_callback(self, cb: Callable):
        self.register_callback(MessageType.INPUT_SEED, cb)
