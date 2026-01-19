"""Log analyzer module for analyzing parsed log entries."""

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Optional

from .parser import LogEntry


class LogAnalyzer:
    """Analyzes parsed log entries and generates statistics."""

    SEVERITY_ORDER = ["CRITICAL", "FATAL", "ERROR", "WARN", "INFO", "DEBUG"]

    def __init__(self, entries: list[LogEntry]):
        self.entries = entries
        self.analysis = {}

    def analyze(self) -> dict:
        """Perform full analysis of log entries."""
        self.analysis = {
            "summary": self._get_summary(),
            "severity_breakdown": self._get_severity_breakdown(),
            "timeline": self._get_timeline(),
            "top_ips": self._get_top_ips(),
            "status_codes": self._get_status_codes(),
            "top_endpoints": self._get_top_endpoints(),
            "notable_findings": self._get_notable_findings(),
            "messages": self._get_messages(),
            "files_analyzed": self._get_files_analyzed(),
        }
        return self.analysis

    def _get_summary(self) -> dict:
        """Get summary statistics."""
        total = len(self.entries)
        with_timestamp = sum(1 for e in self.entries if e.timestamp)
        parse_rate = (with_timestamp / total * 100) if total > 0 else 0

        timestamps = [e.timestamp for e in self.entries if e.timestamp]
        time_range = {
            "start": min(timestamps).isoformat() if timestamps else None,
            "end": max(timestamps).isoformat() if timestamps else None,
        }

        severity_counts = Counter(e.severity for e in self.entries)

        return {
            "total_entries": total,
            "parsed_entries": with_timestamp,
            "parse_rate": round(parse_rate, 1),
            "time_range": time_range,
            "error_count": severity_counts.get("ERROR", 0) + severity_counts.get("CRITICAL", 0) + severity_counts.get("FATAL", 0),
            "warning_count": severity_counts.get("WARN", 0),
            "unique_ips": len(set(e.ip for e in self.entries if e.ip)),
            "unique_endpoints": len(set(e.endpoint for e in self.entries if e.endpoint)),
        }

    def _get_severity_breakdown(self) -> dict:
        """Get severity level breakdown."""
        counts = Counter(e.severity for e in self.entries)
        total = len(self.entries)

        breakdown = {}
        for severity in self.SEVERITY_ORDER:
            count = counts.get(severity, 0)
            breakdown[severity] = {
                "count": count,
                "percentage": round((count / total * 100) if total > 0 else 0, 1),
            }

        return breakdown

    def _get_timeline(self) -> list[dict]:
        """Get timeline data grouped by hour."""
        entries_with_time = [e for e in self.entries if e.timestamp]
        if not entries_with_time:
            return []

        # Group by hour
        hourly = defaultdict(lambda: {"total": 0, "errors": 0, "warnings": 0})

        for entry in entries_with_time:
            hour_key = entry.timestamp.replace(minute=0, second=0, microsecond=0)
            hourly[hour_key]["total"] += 1
            if entry.severity in ("ERROR", "CRITICAL", "FATAL"):
                hourly[hour_key]["errors"] += 1
            elif entry.severity == "WARN":
                hourly[hour_key]["warnings"] += 1

        # Sort by time and format
        timeline = []
        for hour in sorted(hourly.keys()):
            timeline.append({
                "timestamp": hour.isoformat(),
                "hour": hour.strftime("%Y-%m-%d %H:00"),
                "total": hourly[hour]["total"],
                "errors": hourly[hour]["errors"],
                "warnings": hourly[hour]["warnings"],
            })

        return timeline

    def _get_top_ips(self, limit: int = 20) -> list[dict]:
        """Get top IP addresses by frequency."""
        ips = [e.ip for e in self.entries if e.ip]
        ip_counts = Counter(ips)

        # Also track severity per IP
        ip_severity = defaultdict(lambda: {"errors": 0, "warnings": 0})
        for entry in self.entries:
            if entry.ip:
                if entry.severity in ("ERROR", "CRITICAL", "FATAL"):
                    ip_severity[entry.ip]["errors"] += 1
                elif entry.severity == "WARN":
                    ip_severity[entry.ip]["warnings"] += 1

        return [
            {
                "ip": ip,
                "count": count,
                "errors": ip_severity[ip]["errors"],
                "warnings": ip_severity[ip]["warnings"],
            }
            for ip, count in ip_counts.most_common(limit)
        ]

    def _get_status_codes(self) -> list[dict]:
        """Get HTTP status code breakdown."""
        codes = [e.status_code for e in self.entries if e.status_code]
        code_counts = Counter(codes)

        # Categorize by class
        categories = {
            "1xx": {"name": "Informational", "count": 0},
            "2xx": {"name": "Success", "count": 0},
            "3xx": {"name": "Redirection", "count": 0},
            "4xx": {"name": "Client Error", "count": 0},
            "5xx": {"name": "Server Error", "count": 0},
        }

        result = []
        for code, count in sorted(code_counts.items()):
            category = f"{code // 100}xx"
            if category in categories:
                categories[category]["count"] += count
            result.append({
                "code": code,
                "count": count,
                "category": category,
            })

        return result

    def _get_top_endpoints(self, limit: int = 20) -> list[dict]:
        """Get top endpoints by frequency."""
        endpoints = [e.endpoint for e in self.entries if e.endpoint]
        endpoint_counts = Counter(endpoints)

        # Track status codes per endpoint
        endpoint_stats = defaultdict(lambda: {"errors": 0, "total": 0})
        for entry in self.entries:
            if entry.endpoint:
                endpoint_stats[entry.endpoint]["total"] += 1
                if entry.status_code and entry.status_code >= 400:
                    endpoint_stats[entry.endpoint]["errors"] += 1

        return [
            {
                "endpoint": endpoint,
                "count": count,
                "error_count": endpoint_stats[endpoint]["errors"],
                "error_rate": round(
                    endpoint_stats[endpoint]["errors"] / count * 100 if count > 0 else 0, 1
                ),
            }
            for endpoint, count in endpoint_counts.most_common(limit)
        ]

    def _get_notable_findings(self) -> list[dict]:
        """Identify notable findings and potential issues."""
        findings = []

        summary = self._get_summary()

        # High error rate
        total = summary["total_entries"]
        error_count = summary["error_count"]
        if total > 0:
            error_rate = error_count / total * 100
            if error_rate > 10:
                findings.append({
                    "severity": "high",
                    "title": "High Error Rate Detected",
                    "description": f"Error rate is {error_rate:.1f}% ({error_count} errors out of {total} entries).",
                    "recommendation": "Review error logs to identify root causes. High error rates may indicate system instability or configuration issues.",
                })
            elif error_rate > 5:
                findings.append({
                    "severity": "medium",
                    "title": "Elevated Error Rate",
                    "description": f"Error rate is {error_rate:.1f}% ({error_count} errors out of {total} entries).",
                    "recommendation": "Monitor error trends and investigate recurring error patterns.",
                })

        # Check for error spikes in timeline
        timeline = self._get_timeline()
        if len(timeline) > 1:
            avg_errors = sum(t["errors"] for t in timeline) / len(timeline)
            for entry in timeline:
                if entry["errors"] > avg_errors * 3 and entry["errors"] > 5:
                    findings.append({
                        "severity": "medium",
                        "title": f"Error Spike at {entry['hour']}",
                        "description": f"Detected {entry['errors']} errors during this hour, which is significantly above average ({avg_errors:.1f}).",
                        "recommendation": "Investigate logs during this time period to identify the cause of the spike.",
                    })
                    break  # Only report first major spike

        # Suspicious IPs (high error rate)
        top_ips = self._get_top_ips()
        for ip_data in top_ips[:5]:
            if ip_data["count"] > 10 and ip_data["errors"] / ip_data["count"] > 0.5:
                findings.append({
                    "severity": "medium",
                    "title": f"Suspicious Activity from {ip_data['ip']}",
                    "description": f"IP {ip_data['ip']} has {ip_data['errors']} errors out of {ip_data['count']} requests ({ip_data['errors']/ip_data['count']*100:.1f}% error rate).",
                    "recommendation": "Review requests from this IP for potential malicious activity or misconfigured clients.",
                })

        # 5xx status codes
        status_codes = self._get_status_codes()
        server_errors = sum(s["count"] for s in status_codes if s["code"] >= 500)
        if server_errors > 0:
            findings.append({
                "severity": "high" if server_errors > 50 else "medium",
                "title": "Server Errors Detected (5xx)",
                "description": f"Found {server_errors} requests resulting in server errors.",
                "recommendation": "Server errors indicate issues with the application or backend services. Review application logs and server health.",
            })

        # Low parse rate
        if summary["parse_rate"] < 70:
            findings.append({
                "severity": "low",
                "title": "Low Log Parse Rate",
                "description": f"Only {summary['parse_rate']}% of log entries have parseable timestamps.",
                "recommendation": "Consider standardizing log formats for better analysis capabilities.",
            })

        # No findings
        if not findings:
            findings.append({
                "severity": "info",
                "title": "No Significant Issues Detected",
                "description": "Log analysis did not detect any notable issues or anomalies.",
                "recommendation": "Continue monitoring logs regularly to catch issues early.",
            })

        return findings

    def _get_messages(self, limit: int = 100) -> list[dict]:
        """Get recent log messages with details."""
        # Get a mix of recent entries, prioritizing errors
        error_entries = [e for e in self.entries if e.severity in ("ERROR", "CRITICAL", "FATAL")]
        warn_entries = [e for e in self.entries if e.severity == "WARN"]
        other_entries = [e for e in self.entries if e.severity not in ("ERROR", "CRITICAL", "FATAL", "WARN")]

        # Take proportionally more errors and warnings
        selected = []
        selected.extend(error_entries[:limit // 2])
        selected.extend(warn_entries[:limit // 4])
        remaining = limit - len(selected)
        selected.extend(other_entries[:remaining])

        # Sort by line number
        selected.sort(key=lambda e: (e.file_name, e.line_number))

        return [e.to_dict() for e in selected[:limit]]

    def _get_files_analyzed(self) -> list[dict]:
        """Get list of files analyzed with stats."""
        file_stats = defaultdict(lambda: {"entries": 0, "errors": 0, "warnings": 0})

        for entry in self.entries:
            file_stats[entry.file_name]["entries"] += 1
            if entry.severity in ("ERROR", "CRITICAL", "FATAL"):
                file_stats[entry.file_name]["errors"] += 1
            elif entry.severity == "WARN":
                file_stats[entry.file_name]["warnings"] += 1

        return [
            {
                "name": name,
                "entries": stats["entries"],
                "errors": stats["errors"],
                "warnings": stats["warnings"],
            }
            for name, stats in sorted(file_stats.items())
        ]

    def to_csv_rows(self) -> list[dict]:
        """Convert entries to CSV-compatible rows."""
        return [e.to_dict() for e in self.entries]
