"""Log parser module for parsing various log formats."""

import re
from datetime import datetime
from typing import Optional


class LogEntry:
    """Represents a single parsed log entry."""

    def __init__(
        self,
        timestamp: Optional[datetime],
        severity: str,
        message: str,
        source: str = "",
        ip: Optional[str] = None,
        status_code: Optional[int] = None,
        endpoint: Optional[str] = None,
        raw_line: str = "",
        line_number: int = 0,
        file_name: str = "",
    ):
        self.timestamp = timestamp
        self.severity = severity.upper() if severity else "INFO"
        self.message = message
        self.source = source
        self.ip = ip
        self.status_code = status_code
        self.endpoint = endpoint
        self.raw_line = raw_line
        self.line_number = line_number
        self.file_name = file_name

    def to_dict(self) -> dict:
        """Convert log entry to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "severity": self.severity,
            "message": self.message,
            "source": self.source,
            "ip": self.ip,
            "status_code": self.status_code,
            "endpoint": self.endpoint,
            "line_number": self.line_number,
            "file_name": self.file_name,
        }


class LogParser:
    """Parser for various log formats."""

    # Common log patterns
    PATTERNS = {
        # Syslog format: Jan 19 10:15:30 hostname service[pid]: message
        "syslog": re.compile(
            r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
            r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
            r"(?P<host>\S+)\s+"
            r"(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
            r"(?P<message>.*)$"
        ),
        # Apache/Nginx combined log format
        "apache_combined": re.compile(
            r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
            r'\[(?P<datetime>[^\]]+)\]\s+'
            r'"(?P<method>\w+)\s+(?P<endpoint>\S+)\s+\S+"\s+'
            r'(?P<status>\d{3})\s+(?P<size>\S+)'
        ),
        # Generic timestamp with severity
        "generic": re.compile(
            r"^(?P<datetime>\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
            r"(?:\[?(?P<severity>DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL)\]?\s+)?"
            r"(?P<message>.*)$",
            re.IGNORECASE,
        ),
        # Simple severity pattern
        "simple_severity": re.compile(
            r"^(?:\[?(?P<severity>DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL)\]?\s+)"
            r"(?P<message>.*)$",
            re.IGNORECASE,
        ),
    }

    # IP address pattern
    IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

    # Status code pattern
    STATUS_PATTERN = re.compile(r"\b([1-5]\d{2})\b")

    # Endpoint/URL pattern
    ENDPOINT_PATTERN = re.compile(r'(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/\S*)')

    def __init__(self):
        self.current_year = datetime.now().year

    def parse_line(self, line: str, line_number: int = 0, file_name: str = "") -> Optional[LogEntry]:
        """Parse a single log line."""
        line = line.strip()
        if not line:
            return None

        # Try each pattern
        for pattern_name, pattern in self.PATTERNS.items():
            match = pattern.match(line)
            if match:
                return self._create_entry_from_match(
                    match, pattern_name, line, line_number, file_name
                )

        # Fallback: treat as INFO message
        return LogEntry(
            timestamp=None,
            severity="INFO",
            message=line,
            raw_line=line,
            line_number=line_number,
            file_name=file_name,
            ip=self._extract_ip(line),
            status_code=self._extract_status_code(line),
            endpoint=self._extract_endpoint(line),
        )

    def _create_entry_from_match(
        self, match, pattern_name: str, line: str, line_number: int, file_name: str
    ) -> LogEntry:
        """Create a LogEntry from a regex match."""
        groups = match.groupdict()

        timestamp = self._parse_timestamp(groups, pattern_name)
        severity = self._extract_severity(groups, line)
        message = groups.get("message", line)
        source = groups.get("service", "") or groups.get("host", "")

        ip = groups.get("ip") or self._extract_ip(line)
        status_code = None
        if "status" in groups and groups["status"]:
            try:
                status_code = int(groups["status"])
            except (ValueError, TypeError):
                status_code = self._extract_status_code(line)
        else:
            status_code = self._extract_status_code(line)

        endpoint = groups.get("endpoint") or self._extract_endpoint(line)

        return LogEntry(
            timestamp=timestamp,
            severity=severity,
            message=message,
            source=source,
            ip=ip,
            status_code=status_code,
            endpoint=endpoint,
            raw_line=line,
            line_number=line_number,
            file_name=file_name,
        )

    def _parse_timestamp(self, groups: dict, pattern_name: str) -> Optional[datetime]:
        """Parse timestamp from regex groups."""
        try:
            if pattern_name == "syslog":
                month = groups.get("month", "")
                day = groups.get("day", "")
                time_str = groups.get("time", "")
                if month and day and time_str:
                    date_str = f"{month} {day} {self.current_year} {time_str}"
                    return datetime.strptime(date_str, "%b %d %Y %H:%M:%S")

            elif pattern_name == "apache_combined":
                dt_str = groups.get("datetime", "")
                if dt_str:
                    # Format: 19/Jan/2026:10:15:30 +0000
                    return datetime.strptime(dt_str.split()[0], "%d/%b/%Y:%H:%M:%S")

            elif "datetime" in groups and groups["datetime"]:
                dt_str = groups["datetime"]
                # Try common formats
                for fmt in [
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S.%f",
                    "%Y-%m-%dT%H:%M:%S.%f",
                    "%Y/%m/%d %H:%M:%S",
                ]:
                    try:
                        return datetime.strptime(dt_str[:19], fmt[:len(dt_str) + fmt.count("%")])
                    except ValueError:
                        continue
                # Try ISO format
                try:
                    return datetime.fromisoformat(dt_str.replace("Z", "+00:00")[:26])
                except ValueError:
                    pass

        except (ValueError, TypeError):
            pass
        return None

    def _extract_severity(self, groups: dict, line: str) -> str:
        """Extract severity level."""
        severity = groups.get("severity", "")
        if severity:
            severity = severity.upper()
            if severity == "WARNING":
                severity = "WARN"
            return severity

        # Check for severity keywords in the line
        line_upper = line.upper()
        for level in ["CRITICAL", "FATAL", "ERROR", "WARN", "WARNING", "INFO", "DEBUG"]:
            if level in line_upper:
                return "WARN" if level == "WARNING" else level
        return "INFO"

    def _extract_ip(self, line: str) -> Optional[str]:
        """Extract IP address from line."""
        match = self.IP_PATTERN.search(line)
        return match.group(1) if match else None

    def _extract_status_code(self, line: str) -> Optional[int]:
        """Extract HTTP status code from line."""
        match = self.STATUS_PATTERN.search(line)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                pass
        return None

    def _extract_endpoint(self, line: str) -> Optional[str]:
        """Extract endpoint/URL from line."""
        match = self.ENDPOINT_PATTERN.search(line)
        return match.group(1) if match else None

    def parse_file(self, file_path: str) -> list[LogEntry]:
        """Parse an entire log file."""
        entries = []
        file_name = file_path.split("/")[-1]

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line_number, line in enumerate(f, 1):
                    entry = self.parse_line(line, line_number, file_name)
                    if entry:
                        entries.append(entry)
        except IOError as e:
            print(f"Error reading file {file_path}: {e}")

        return entries
