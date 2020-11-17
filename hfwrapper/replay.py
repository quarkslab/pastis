import subprocess
from io import BytesIO
from typing import Optional, List, Tuple
import re


class Replay(object):

    INTRINSIC_REGEX = rb".*REACHED ID (\d+)"
    ASAN_REGEX = rb"^==\d+==ERROR:"
    ASAN_END_LINE = rb"^==\d+==ERROR: AddressSanitizer: (.+)"
    ASAN_PARAM = rb"^==\d+==ERROR: AddressSanitizer: (\S+)"

    def __init__(self):
        self._process = None
        self._alert_covered = []
        self._alert_crash = None
        self._is_hang = False
        self._asan_line = ""
        self._asan_bugtype = ""

        # For debugging
        self.stdout, self.stderr = None, None

    @staticmethod
    def run(binary_path: str, args: List[str], stdin_file=None, timeout=None, cwd=None):
        replay = Replay()
        replay._process = subprocess.Popen([binary_path]+args, stdin=open(stdin_file, 'rb'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
        try:
            replay.stdout, replay.stderr = replay._process.communicate(timeout=timeout)
            replay.__parse_output(replay.stdout)  # In case intrinsic are on output
            replay.__parse_output(replay.stderr)
        except TimeoutError:
            replay._is_hang = True

        return replay

    @property
    def returncode(self) -> int:
        return self._process.returncode

    @property
    def alert_covered(self) -> List[int]:
        """ Alert covered """
        return self._alert_covered

    def has_hanged(self) -> bool:
        """ Return true if the target hanged during its replay """
        return self._is_hang

    def has_crashed(self) -> bool:
        """ Return whether the execution has crashed or not """
        if self._process.returncode:
            return self._process.returncode != 0
        else:
            return False

    @property
    def crashing_id(self) -> Optional[int]:
        """ Return the alert identifier that made the program to crash (last one seen) """
        return self._alert_crash

    def asan_info(self) -> Tuple[str, str]:
        """ In case of crash return ASAN info gather by parsing """
        return self._asan_bugtype, self._asan_line


    def __parse_output(self, raw_output: bytes):
        for line in BytesIO(raw_output).readlines():
            # Check if its a line of intrinsic output
            m = re.match(self.INTRINSIC_REGEX, line)
            if m:
                id = int(m.groups()[0])
                self._alert_covered.append(id)

            # Check if its a line of ASAN
            m = re.match(self.ASAN_REGEX, line)
            if m:
                if self._alert_covered: # Try getting last alert (and consider it to be the origin)
                    self._alert_crash = self._alert_covered[-1]
                # Else cannot link the crash to an ID

                # Extract end of line and parameter
                m = re.match(self.ASAN_END_LINE, line)
                if m:
                    self._asan_line = m.groups()[0].decode()
                m = re.match(self.ASAN_PARAM, line)
                if m:
                    self._asan_bugtype = m.groups()[0].decode()
