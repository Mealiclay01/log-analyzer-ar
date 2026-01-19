"""Reporter module for generating HTML, JSON, and CSV reports."""

import csv
import html
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any


class Reporter:
    """Generates analysis reports in various formats."""

    def __init__(self, analysis: dict, output_dir: str = "output"):
        self.analysis = analysis
        self.output_dir = output_dir
        self.template_dir = Path(__file__).parent / "templates"

    def generate_all(self) -> dict[str, str]:
        """Generate all report formats."""
        os.makedirs(self.output_dir, exist_ok=True)

        paths = {
            "json": self.generate_json(),
            "csv": self.generate_csv(),
            "html": self.generate_html(),
        }

        return paths

    def generate_json(self) -> str:
        """Generate JSON report."""
        path = os.path.join(self.output_dir, "analysis.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.analysis, f, indent=2, ensure_ascii=False)
        return path

    def generate_csv(self) -> str:
        """Generate CSV report of log messages."""
        path = os.path.join(self.output_dir, "messages.csv")
        messages = self.analysis.get("messages", [])

        if messages:
            fieldnames = ["timestamp", "severity", "message", "source", "ip", "status_code", "endpoint", "file_name", "line_number"]
            with open(path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(messages)

        return path

    def generate_html(self) -> str:
        """Generate HTML report."""
        path = os.path.join(self.output_dir, "report.html")

        # Load template
        template_path = self.template_dir / "report.html"
        with open(template_path, "r", encoding="utf-8") as f:
            template = f.read()

        # Prepare data for injection (with XSS protection)
        report_data = self._prepare_report_data()

        # Replace placeholder with escaped JSON data
        html_content = template.replace(
            "/* __REPORT_DATA_PLACEHOLDER__ */",
            f"const REPORT_DATA = {json.dumps(report_data, ensure_ascii=False)};"
        )

        # Set generation timestamp
        html_content = html_content.replace(
            "__GENERATION_TIME__",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return path

    def _prepare_report_data(self) -> dict:
        """Prepare report data with XSS-safe escaping."""
        # Deep copy and escape string values
        return self._escape_dict(self.analysis)

    def _escape_dict(self, obj: Any) -> Any:
        """Recursively escape string values in nested data structures."""
        if isinstance(obj, dict):
            return {k: self._escape_dict(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._escape_dict(item) for item in obj]
        elif isinstance(obj, str):
            return html.escape(obj)
        else:
            return obj
