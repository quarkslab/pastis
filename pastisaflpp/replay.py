import subprocess
from io import BytesIO
from typing import Optional, List, Tuple
import re
import logging


EXAMPLES = '''
REGEX_1:
==373876==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffecfb907a4 at pc 0x00000043e9e7 bp 0x7ffecfb90660 sp 0x7ffecfb8fdf8

REGEX_2:
==372317==AddressSanitizer: WARNING: unexpected format specifier in printf interceptor: %� (reported once per process)
==372317==AddressSanitizer CHECK failed: /build/llvm-toolchain-9-NoMHhU/llvm-toolchain-9-9.0.1/compiler-rt/lib/asan/../sanitizer_common/sani
'''


class Replay(object):

    INTRINSIC_REGEX = rb".*REACHED ID (\d+)"
    ASAN_REGEX_1 = rb"^==\d+==ERROR: AddressSanitizer: (\S+) (.*)"
    ASAN_REGEX_2 = rb"^==\d+==AddressSanitizer:? ([^:]+): (.*)"

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
    def run(binary_path: str, args: List[str] = [], stdin_file=None, timeout=None, cwd=None):
        replay = Replay()
        replay._process = subprocess.Popen([binary_path]+args, stdin=open(stdin_file, 'rb'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
        try:
            replay.stdout, replay.stderr = replay._process.communicate(timeout=timeout)
            found = replay.__parse_output(replay.stdout)  # In case intrinsic are on output
            found |= replay.__parse_output(replay.stderr)

            if not found and replay.has_crashed():  # Crash that we were not able to link to an ASAN error
                if replay._alert_covered: # Thus take the latest alert and consider it is the origin
                    replay._alert_crash = replay._alert_covered[-1]
        except subprocess.TimeoutExpired:
            replay._is_hang = True

        return replay

    def is_asan_without_crash(self) -> bool:
        """ Return True if an ASAN WARNING was shown without errors """
        return self._asan_bugtype and not self.has_crashed()

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

    def __parse_output(self, raw_output: bytes) -> bool:
        """ Return True if a vuln was matched """
        matched_vuln = False
        for line in BytesIO(raw_output).readlines():
            # Check if its a line of intrinsic output
            m = re.match(self.INTRINSIC_REGEX, line)
            if m:
                id = int(m.groups()[0])
                self._alert_covered.append(id)

            # Check if its a line of ASAN
            m1 = re.match(self.ASAN_REGEX_1, line)
            m2 = re.match(self.ASAN_REGEX_2, line)
            if m1 or m2:
                if matched_vuln:
                    logging.warning(f"already matched ASAN with {self._asan_bugtype} now {m1.groups() if m1 else m2.groups()}")
                    continue
                matched_vuln = True
                if self._alert_covered: # Try getting last alert (and consider it to be the origin)
                    self._alert_crash = self._alert_covered[-1]
                # Else cannot link the crash to an ID

                # Extract end of line and parameter
                topic, details = m1.groups() if m1 else m2.groups()
                self._asan_bugtype = topic.decode(errors="replace")
                self._asan_line = details.decode(errors="replace")

        return matched_vuln
