from typing import Callable, Optional, Tuple, List, Union
from enum import Enum
import logging
import threading
import abc
from pathlib import Path

import zmq

from libpastis.proto import InputSeedMsg, StartMsg, StopMsg, HelloMsg, LogMsg, \
                            TelemetryMsg, StopCoverageCriteria
from libpastis.types import SeedType, Arch, FuzzingEngine, PathLike, ExecMode, CheckMode, CoverageMode, SeedInjectLoc

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
        self._cbs[typ] = callback

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
        for cb in self._cbs[topic]:
            cb(id, message)

    def __client_transfer_to_callback(self, topic: MessageType, message: bytes):
        if topic in [MessageType.HELLO, MessageType.TELEMETRY, MessageType.LOG, MessageType.STOP_COVERAGE_DONE]:
            logging.error(f"Invalid message of type {topic.name} received")
        if not self._cbs[topic]:
            logging.warning(f"[agent] message of type {topic.name} (but no callback)")
        for cb in self._cbs[topic]:
            cb(message)


class BrokerAgent(NetworkAgent):

    def send_start(self, id: bytes, message: StartMsg):
        # TODO: to implement
        pass

    def send_seed(self, id: bytes, typ: SeedType, seed: bytes, origin: FuzzingEngine):
        msg = InputSeedMsg()
        msg.type = typ.value
        msg.seed = seed
        msg.origin = origin.value
        self.send_to(id, msg)

    def send_start(self, id: bytes, binary: PathLike, exmode):
        pass

class ClientAgent(NetworkAgent):

    def send_hello(self, engine: Tuple[FuzzingEngine, str], archs: List[Arch] = []):
        # TODO: retrieving threads, memory, and architecture if empty
        pass

    def send_log(self, msg: LogMsg):
        # TODO: to implement
        pass

    def send_telemetry(self, msg: TelemetryMsg):
        # TODO: to implement
        pass

    def send_stop_coverage_criteria(self, msg: StopCoverageCriteria):
        # TODO: to implement
        pass

    def send_seed(self, typ: SeedType, seed: bytes, origin: FuzzingEngine):
        msg = InputSeedMsg()
        msg.type = typ.value
        msg.seed = seed
        msg.origin = origin.value
        self.send(msg)

