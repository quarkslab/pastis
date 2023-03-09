# built-in imports
import json
import logging
import csv
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Union



class SASTAlert:
    def __init__(self):
        # Static alert data
        self.id = None         # ID
        self.type = None       # Alert type SV.UNBOUND.COPY, UFM.DEREF ..
        self.params = None     # Parameters of the alert (values between parentheses in the report)
        self.taxonomy = None   # Taxonomy used in the report 'C, C++', 'MISRA Checker Package'..
        self.severity = None   # Severity of the report: Review, Error, Critical ..
        self.file = None       # Source file impacted
        self.line = None       # line of code (in the file
        self.function = None   # Function impacted
        self.raw_line = None   # Raw line as shown in report

        # Analysis results
        self.covered = False
        self.validated = False
        self.uncoverable = False

    @staticmethod
    def from_json(data: dict) -> 'SASTAlert':
        """
        Create a SASTAlert object from the JSON data provided.

        :param data: JSON data of the alert
        :return: SASTkAlert instance, initialized with the JSON
        """
        alert = SASTAlert()
        for name in ["id", "type", "params", "taxonomy", "severity", "file", "line", "function", "raw_line",
                     "covered", "validated", "uncoverable"]:
            val = data.get(name)
            if val:
                setattr(alert, name, val)
        return alert


    def to_dict(self) -> dict:
        """
        Export the alert attribute to a valid JSON dictionnary
        that can be written to file.

        :return: JSON dict of the alert serialized
        """
        return {x: getattr(self, x) for x in ["id", "type", "params", "taxonomy", "severity", "file", "line", "function",
                                              "raw_line", "covered", "validated", "uncoverable"]}

    def __repr__(self):
        return f"<Alert id:{self.id}: {self.type} {self.function}:{self.line} ({Path(self.file).name})>"



class SASTReport:
    """
    Class that manages a set of SAST alerts taken from a report
    """

    def __init__(self):
        """
        Class constructor. Optionally takes the report JSON file
        and the pastis binding JSON file.

        :param file: Report file path
        """
        self.alerts: Dict[int, SASTAlert] = {}  # id -> SASTAlert


    def iter_alerts(self) -> List[SASTAlert]:
        return list(self.alerts.values())


    def all_alerts_validated(self) -> bool:
        """
        Checks whether or not all alerts considered, are covered and validated

        :return: True if all alerts are covered and vulns validated
        """
        for alert in self.iter_alerts():
            if not alert.covered:
                return False
        return True


    def add_alert(self, alert: SASTAlert) -> None:
        """
        Add an alert in the report. This function is solely
        used by the report parser

        :param alert: Alert object to add in the report
        :return: None
        """
        self.alerts[alert.id] = alert


    @staticmethod
    def from_file(file: Union[str, Path]) -> 'SASTReport':
        """
        Parse the given string into a SAST report object.

        :param file: path to report
        :return: SASTReport object
        """
        data = Path(file).read_bytes()
        return SASTReport.from_json(data)


    @staticmethod
    def from_json(data: Union[str, bytes]) -> 'SASTReport':
        """
        Parse the given string into a SAST report object.

        :param data: serialized report in JSON
        :return: SASTReport object
        """
        data = json.loads(data)
        report = SASTReport()
        for it in data:
            a = SASTAlert.from_json(it)
            report.add_alert(a)
        return report


    def to_json(self) -> str:
        """
        Export the current state of the alerts within a JSON dictionnary.

        :return: JSON serialized report
        """
        return json.dumps([x.to_dict() for x in self.alerts.values()], indent=2)


    def write(self, out_file) -> None:
        """
        Export the current state of the alerts within a JSON dictionnary.

        :param out_file: Output file path
        """
        with open(out_file, "w") as f:
            f.write(self.to_json())


    def get_stats(self) -> Tuple[int, int, int]:
        covered = 0
        validated = 0
        total = 0
        for alert in self.alerts.values():
            covered += int(alert.covered)
            validated += int(alert.validated)
            total += 1
        return covered, validated, total

    def write_csv(self, file: Path) -> None:
        with open(file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=['id', 'type', 'covered', 'validated'])
            writer.writeheader()
            for a in self.iter_alerts():
                writer.writerow({'id': a.id,
                                 'type': a.type.name,
                                 'covered': a.covered,
                                 'validated': a.validated})
