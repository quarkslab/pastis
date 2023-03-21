# built-in imports
import json
import csv
from pathlib import Path
from typing import List, Dict, Tuple, Union


class SASTAlert:
    """
    Class representing an alert in a somewhat abstract SAST tool. Its
    used to perform alert driven testing.
    """
    def __init__(self):
        # Static alert data
        self.id: int = -1
        #: Unique ID of the alert
        self.type: str = ""
        #: Type of the alert BoF, UaF (in the convention of the SAST)
        self.params: list = []
        #: Additional parameters of the alert (list)
        self.taxonomy: str = ""
        #: Taxonomy of the alert (e.g: CWE, CVE, MISRA checker, ..)
        self.severity: str = ""
        #: Severity of the alert (e.g: Review, Error, Critical ..)
        self.file: str = ""
        #: Source file impacted
        self.line: int = -1
        #: line of code (in the file)
        self.function: str = ""
        #: Function impacted
        self.raw_line: str = ""
        #: Raw alert extract taken from the report (in its own format)

        # Analysis results
        self.covered = False
        #: Coverage: True if the alert has been covered (path leading there)
        self.validated = False
        #: Validation: True if the alert has been validated (as a true positive by a checker)
        self.uncoverable = False
        #: Reachability: True if the alert cannot be reached by any paths

    @staticmethod
    def from_json(data: dict) -> 'SASTAlert':
        """
        Create a SASTAlert object from the JSON data provided.

        :param data: JSON data of the alert
        :return: SASTAlert instance, initialized with the JSON
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
    SAST report. Manages a list of SAST alerts taken from a report.
    """

    def __init__(self):
        self.alerts: Dict[int, SASTAlert] = {}
        #: Dictionnary of alerts indexed by their ID


    def iter_alerts(self) -> List[SASTAlert]:
        """
        Iterate all the alerts of the report.
        :return: list of alerts
        """
        return list(self.alerts.values())


    def all_alerts_validated(self) -> bool:
        """
        Checks if all alerts have been validated (and thus covered)

        :return: True if all alerts are covered and vulns validated
        """
        for alert in self.iter_alerts():
            if not alert.covered:
                return False
        return True


    def add_alert(self, alert: SASTAlert) -> None:
        """
        Add an alert in the report. This function is solely
        meant to be used by the report parser

        :param alert: Alert object to add in the report
        """
        self.alerts[alert.id] = alert


    @staticmethod
    def from_file(file: Union[str, Path]) -> 'SASTReport':
        """
        Parse the given file into a SAST report object.

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
        Export the current state of the alerts within a JSON dictionary.

        :param out_file: Output file path
        """
        with open(out_file, "w") as f:
            f.write(self.to_json())


    def get_stats(self) -> Tuple[int, int, int]:
        """
        Get stats about the report. The results is a triple
        with the number of alerts covered, validated and total.

        :return: triple of covered, validated, totoal number of alerts
        """
        covered = 0
        validated = 0
        total = 0
        for alert in self.alerts.values():
            covered += int(alert.covered)
            validated += int(alert.validated)
            total += 1
        return covered, validated, total

    def write_csv(self, file: Path) -> None:
        """
        Write the report as a csv into the given file.

        :param file: CSV file to write
        """
        with open(file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=['id', 'type', 'covered', 'validated'])
            writer.writeheader()
            for a in self.iter_alerts():
                writer.writerow({'id': a.id,
                                 'type': a.type,
                                 'covered': a.covered,
                                 'validated': a.validated})
