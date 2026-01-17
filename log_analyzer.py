#!/usr/bin/env python3
"""
Linux Log Analyzer CLI Tool
Analyzes syslog, nginx, and application logs with severity detection,
message counting, IP/status analysis, and timeline generation.
"""

import argparse
import csv
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Any


class LogAnalyzer:
    """Main log analyzer class"""
    
    def __init__(self, log_files: List[str]):
        self.log_files = log_files
        self.results = {
            'summary': {},
            'severity_counts': Counter(),
            'top_messages': [],
            'top_ips': [],
            'top_status_codes': [],
            'timeline_by_hour': defaultdict(int),
            'log_files_analyzed': log_files
        }
        
        # Regex patterns for different log formats
        self.patterns = {
            'syslog': re.compile(
                r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
                r'(?P<host>\S+)\s+(?P<process>\S+?)(\[(?P<pid>\d+)\])?\s*:\s*'
                r'(?P<message>.+)'
            ),
            'nginx_access': re.compile(
                r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
                r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>\S+)"\s+'
                r'(?P<status>\d+)\s+(?P<bytes>\S+)\s+'
                r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
            ),
            'nginx_error': re.compile(
                r'(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
                r'\[(?P<severity>\w+)\]\s+(?P<pid>\d+)#(?P<tid>\d+):\s+'
                r'(\*(?P<cid>\d+)\s+)?(?P<message>.+)'
            ),
            'generic_app': re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
                r'(\.\d+)?\s+(?P<severity>ERROR|WARN|WARNING|INFO|DEBUG)'
                r'(\s+\[(?P<logger>[^\]]+)\])?\s*[-:]?\s*(?P<message>.+)',
                re.IGNORECASE
            )
        }
        
        # IP address pattern
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
    def detect_severity(self, message: str, explicit_severity: str = None) -> str:
        """Detect severity level from message or explicit field"""
        if explicit_severity:
            return explicit_severity.upper()
        
        message_upper = message.upper()
        if any(word in message_upper for word in ['ERROR', 'FATAL', 'CRITICAL', 'FAIL']):
            return 'ERROR'
        elif any(word in message_upper for word in ['WARN', 'WARNING']):
            return 'WARN'
        elif any(word in message_upper for word in ['INFO', 'INFORMATION']):
            return 'INFO'
        elif 'DEBUG' in message_upper:
            return 'DEBUG'
        return 'INFO'
    
    def extract_hour_from_timestamp(self, timestamp_str: str) -> str:
        """Extract hour from various timestamp formats"""
        try:
            # Try different timestamp formats
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y/%m/%d %H:%M:%S',
                '%d/%b/%Y:%H:%M:%S',
                '%H:%M:%S',
                '%b %d %H:%M:%S'
            ]
            
            for fmt in formats:
                try:
                    dt = datetime.strptime(timestamp_str.split('.')[0].split()[0:2] 
                                         if ' ' in timestamp_str 
                                         else timestamp_str.split('.')[0], 
                                         fmt)
                    return f"{dt.hour:02d}:00"
                except ValueError:
                    continue
            
            # Extract hour directly if possible
            hour_match = re.search(r'(\d{2}):\d{2}:\d{2}', timestamp_str)
            if hour_match:
                return f"{hour_match.group(1)}:00"
                
        except Exception:
            pass
        
        return "00:00"
    
    def parse_log_line(self, line: str) -> Tuple[str, Dict[str, Any]]:
        """Parse a single log line and return format type and extracted data"""
        line = line.strip()
        if not line:
            return None, None
        
        # Try nginx access log
        match = self.patterns['nginx_access'].match(line)
        if match:
            data = match.groupdict()
            return 'nginx_access', data
        
        # Try nginx error log
        match = self.patterns['nginx_error'].match(line)
        if match:
            data = match.groupdict()
            return 'nginx_error', data
        
        # Try syslog
        match = self.patterns['syslog'].match(line)
        if match:
            data = match.groupdict()
            return 'syslog', data
        
        # Try generic application log
        match = self.patterns['generic_app'].match(line)
        if match:
            data = match.groupdict()
            return 'generic_app', data
        
        # Unmatched line
        return 'unknown', {'message': line}
    
    def analyze(self):
        """Analyze all log files"""
        message_counter = Counter()
        ip_counter = Counter()
        status_counter = Counter()
        
        total_lines = 0
        parsed_lines = 0
        
        for log_file in self.log_files:
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        total_lines += 1
                        log_type, data = self.parse_log_line(line)
                        
                        if not data:
                            continue
                        
                        parsed_lines += 1
                        
                        # Extract severity
                        severity = None
                        message = data.get('message', '')
                        
                        if log_type == 'nginx_error':
                            severity = data.get('severity', '')
                        elif log_type == 'generic_app':
                            severity = data.get('severity', '')
                        
                        severity = self.detect_severity(message, severity)
                        self.results['severity_counts'][severity] += 1
                        
                        # Count messages (normalize for better grouping)
                        normalized_msg = re.sub(r'\d+', 'N', message[:100])
                        message_counter[normalized_msg] += 1
                        
                        # Extract IPs
                        if log_type == 'nginx_access':
                            ip = data.get('ip')
                            if ip:
                                ip_counter[ip] += 1
                        else:
                            # Look for IPs in message
                            ips = self.ip_pattern.findall(message)
                            for ip in ips:
                                ip_counter[ip] += 1
                        
                        # Extract status codes
                        if log_type == 'nginx_access':
                            status = data.get('status')
                            if status:
                                status_counter[status] += 1
                        
                        # Build timeline
                        timestamp = data.get('timestamp') or data.get('time', '')
                        if timestamp:
                            hour = self.extract_hour_from_timestamp(timestamp)
                            self.results['timeline_by_hour'][hour] += 1
                        
            except Exception as e:
                print(f"Error processing {log_file}: {e}")
        
        # Compile top results
        self.results['top_messages'] = [
            {'message': msg, 'count': count} 
            for msg, count in message_counter.most_common(10)
        ]
        
        self.results['top_ips'] = [
            {'ip': ip, 'count': count} 
            for ip, count in ip_counter.most_common(10)
        ]
        
        self.results['top_status_codes'] = [
            {'status_code': code, 'count': count} 
            for code, count in status_counter.most_common(10)
        ]
        
        # Convert timeline to sorted list
        timeline = sorted(
            [{'hour': hour, 'count': count} 
             for hour, count in self.results['timeline_by_hour'].items()],
            key=lambda x: x['hour']
        )
        self.results['timeline_by_hour'] = timeline
        
        # Summary
        self.results['summary'] = {
            'total_lines': total_lines,
            'parsed_lines': parsed_lines,
            'total_errors': self.results['severity_counts'].get('ERROR', 0),
            'total_warnings': self.results['severity_counts'].get('WARN', 0),
            'total_info': self.results['severity_counts'].get('INFO', 0),
            'unique_ips': len(ip_counter),
            'unique_status_codes': len(status_counter)
        }
        
        return self.results


class OutputGenerator:
    """Generate various output formats"""
    
    def __init__(self, results: Dict, output_dir: str):
        self.results = results
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_json(self) -> str:
        """Generate JSON output"""
        json_file = self.output_dir / 'analysis.json'
        
        # Convert Counter to dict for JSON serialization
        output_data = dict(self.results)
        output_data['severity_counts'] = dict(output_data['severity_counts'])
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        return str(json_file)
    
    def generate_csv(self) -> List[str]:
        """Generate CSV outputs"""
        csv_files = []
        
        # Summary CSV
        summary_file = self.output_dir / 'summary.csv'
        with open(summary_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Metric', 'Value'])
            for key, value in self.results['summary'].items():
                writer.writerow([key, value])
        csv_files.append(str(summary_file))
        
        # Top messages CSV
        if self.results['top_messages']:
            messages_file = self.output_dir / 'top_messages.csv'
            with open(messages_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['message', 'count'])
                writer.writeheader()
                writer.writerows(self.results['top_messages'])
            csv_files.append(str(messages_file))
        
        # Top IPs CSV
        if self.results['top_ips']:
            ips_file = self.output_dir / 'top_ips.csv'
            with open(ips_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['ip', 'count'])
                writer.writeheader()
                writer.writerows(self.results['top_ips'])
            csv_files.append(str(ips_file))
        
        # Top status codes CSV
        if self.results['top_status_codes']:
            status_file = self.output_dir / 'top_status_codes.csv'
            with open(status_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['status_code', 'count'])
                writer.writeheader()
                writer.writerows(self.results['top_status_codes'])
            csv_files.append(str(status_file))
        
        # Timeline CSV
        if self.results['timeline_by_hour']:
            timeline_file = self.output_dir / 'timeline.csv'
            with open(timeline_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['hour', 'count'])
                writer.writeheader()
                writer.writerows(self.results['timeline_by_hour'])
            csv_files.append(str(timeline_file))
        
        return csv_files
    
    def generate_html(self) -> str:
        """Generate HTML report"""
        html_file = self.output_dir / 'report.html'
        
        summary = self.results['summary']
        severity_counts = dict(self.results['severity_counts'])
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log Analysis Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
            border-bottom: 2px solid #ddd;
            padding-bottom: 5px;
        }}
        .summary {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .summary-item {{
            background: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #4CAF50;
        }}
        .summary-item label {{
            display: block;
            font-size: 0.9em;
            color: #666;
            margin-bottom: 5px;
        }}
        .summary-item value {{
            font-size: 1.5em;
            font-weight: bold;
            color: #333;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #4CAF50;
            color: white;
            font-weight: bold;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .severity-error {{ color: #d32f2f; font-weight: bold; }}
        .severity-warn {{ color: #f57c00; font-weight: bold; }}
        .severity-info {{ color: #1976d2; }}
        .chart-container {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .bar {{
            background: #4CAF50;
            height: 25px;
            margin: 5px 0;
            border-radius: 3px;
            position: relative;
        }}
        .bar-label {{
            position: absolute;
            right: 10px;
            line-height: 25px;
            color: white;
            font-weight: bold;
        }}
        footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <h1>📊 Log Analysis Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-item">
                <label>Total Lines</label>
                <value>{summary.get('total_lines', 0)}</value>
            </div>
            <div class="summary-item">
                <label>Parsed Lines</label>
                <value>{summary.get('parsed_lines', 0)}</value>
            </div>
            <div class="summary-item">
                <label>Errors</label>
                <value class="severity-error">{summary.get('total_errors', 0)}</value>
            </div>
            <div class="summary-item">
                <label>Warnings</label>
                <value class="severity-warn">{summary.get('total_warnings', 0)}</value>
            </div>
            <div class="summary-item">
                <label>Info Messages</label>
                <value class="severity-info">{summary.get('total_info', 0)}</value>
            </div>
            <div class="summary-item">
                <label>Unique IPs</label>
                <value>{summary.get('unique_ips', 0)}</value>
            </div>
        </div>
    </div>
    
    <div class="summary">
        <h2>Severity Distribution</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for severity, count in sorted(severity_counts.items(), key=lambda x: x[1], reverse=True):
            severity_class = f"severity-{severity.lower()}" if severity.lower() in ['error', 'warn', 'info'] else ''
            html_content += f"""
                <tr>
                    <td class="{severity_class}">{severity}</td>
                    <td>{count}</td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
    </div>
"""
        
        # Top messages
        if self.results['top_messages']:
            html_content += """
    <div class="summary">
        <h2>Top Messages</h2>
        <table>
            <thead>
                <tr>
                    <th>Message</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
"""
            for item in self.results['top_messages']:
                html_content += f"""
                <tr>
                    <td>{item['message'][:150]}</td>
                    <td>{item['count']}</td>
                </tr>
"""
            html_content += """
            </tbody>
        </table>
    </div>
"""
        
        # Top IPs
        if self.results['top_ips']:
            html_content += """
    <div class="summary">
        <h2>Top IP Addresses</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
"""
            for item in self.results['top_ips']:
                html_content += f"""
                <tr>
                    <td>{item['ip']}</td>
                    <td>{item['count']}</td>
                </tr>
"""
            html_content += """
            </tbody>
        </table>
    </div>
"""
        
        # Top status codes
        if self.results['top_status_codes']:
            html_content += """
    <div class="summary">
        <h2>Top HTTP Status Codes</h2>
        <table>
            <thead>
                <tr>
                    <th>Status Code</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
"""
            for item in self.results['top_status_codes']:
                html_content += f"""
                <tr>
                    <td>{item['status_code']}</td>
                    <td>{item['count']}</td>
                </tr>
"""
            html_content += """
            </tbody>
        </table>
    </div>
"""
        
        # Timeline
        if self.results['timeline_by_hour']:
            max_count = max(item['count'] for item in self.results['timeline_by_hour'])
            html_content += """
    <div class="chart-container">
        <h2>Timeline by Hour</h2>
"""
            for item in self.results['timeline_by_hour']:
                width = (item['count'] / max_count * 100) if max_count > 0 else 0
                html_content += f"""
        <div>
            <small>{item['hour']}</small>
            <div class="bar" style="width: {width}%">
                <span class="bar-label">{item['count']}</span>
            </div>
        </div>
"""
            html_content += """
    </div>
"""
        
        # Footer
        html_content += f"""
    <footer>
        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Analyzed files: {', '.join(self.results['log_files_analyzed'])}</p>
    </footer>
</body>
</html>
"""
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(html_file)


class ArabicSummaryGenerator:
    """Generate Arabic summary using AI providers"""
    
    def __init__(self, results: Dict, output_dir: str):
        self.results = results
        self.output_dir = Path(output_dir)
        self.ai_provider = os.getenv('AI_PROVIDER', '').lower()
        self.ai_api_key = os.getenv('AI_API_KEY', '')
    
    def generate_summary(self) -> str:
        """Generate Arabic summary if AI credentials are available"""
        if not self.ai_provider or not self.ai_api_key:
            print("Skipping Arabic summary: AI_PROVIDER and AI_API_KEY not set")
            return None
        
        summary_text = self._create_summary_text()
        
        try:
            if self.ai_provider == 'openai':
                return self._generate_with_openai(summary_text)
            elif self.ai_provider == 'anthropic':
                return self._generate_with_anthropic(summary_text)
            else:
                print(f"Unsupported AI provider: {self.ai_provider}")
                return None
        except Exception as e:
            print(f"Error generating Arabic summary: {e}")
            return None
    
    def _create_summary_text(self) -> str:
        """Create summary text for AI"""
        summary = self.results['summary']
        return f"""Log Analysis Summary:
- Total lines: {summary.get('total_lines', 0)}
- Errors: {summary.get('total_errors', 0)}
- Warnings: {summary.get('total_warnings', 0)}
- Info: {summary.get('total_info', 0)}
- Unique IPs: {summary.get('unique_ips', 0)}
- Unique Status Codes: {summary.get('unique_status_codes', 0)}

Top Messages: {len(self.results['top_messages'])} unique patterns
Top IPs: {len(self.results['top_ips'])} unique addresses
Top Status Codes: {len(self.results['top_status_codes'])} unique codes
"""
    
    def _generate_with_openai(self, summary_text: str) -> str:
        """Generate summary using OpenAI"""
        import openai
        
        client = openai.OpenAI(api_key=self.ai_api_key)
        
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant that creates concise Arabic summaries of log analysis reports."},
                {"role": "user", "content": f"Create a brief Arabic summary (3-5 sentences) of this log analysis:\n\n{summary_text}"}
            ],
            max_tokens=500
        )
        
        arabic_summary = response.choices[0].message.content
        return self._save_summary(arabic_summary)
    
    def _generate_with_anthropic(self, summary_text: str) -> str:
        """Generate summary using Anthropic"""
        import anthropic
        
        client = anthropic.Anthropic(api_key=self.ai_api_key)
        
        response = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=500,
            messages=[
                {
                    "role": "user",
                    "content": f"Create a brief Arabic summary (3-5 sentences) of this log analysis:\n\n{summary_text}"
                }
            ]
        )
        
        arabic_summary = response.content[0].text
        return self._save_summary(arabic_summary)
    
    def _save_summary(self, arabic_summary: str) -> str:
        """Save Arabic summary to file"""
        summary_file = self.output_dir / 'summary.md'
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("# ملخص تحليل السجلات\n\n")
            f.write(arabic_summary)
            f.write("\n")
        
        return str(summary_file)


def main():
    parser = argparse.ArgumentParser(
        description='Linux Log Analyzer - Analyze syslog, nginx, and application logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s access.log
  %(prog)s /var/log/syslog /var/log/nginx/access.log
  %(prog)s app.log -o results/
  AI_PROVIDER=openai AI_API_KEY=sk-xxx %(prog)s app.log
        """
    )
    
    parser.add_argument(
        'log_files',
        nargs='+',
        help='One or more log files to analyze'
    )
    
    parser.add_argument(
        '-o', '--output-dir',
        default='output',
        help='Output directory for results (default: output/)'
    )
    
    args = parser.parse_args()
    
    # Validate input files
    for log_file in args.log_files:
        if not os.path.exists(log_file):
            print(f"Error: Log file not found: {log_file}")
            return 1
    
    print(f"🔍 Analyzing {len(args.log_files)} log file(s)...")
    
    # Analyze logs
    analyzer = LogAnalyzer(args.log_files)
    results = analyzer.analyze()
    
    print(f"✅ Analysis complete!")
    print(f"   - Total lines: {results['summary']['total_lines']}")
    print(f"   - Parsed lines: {results['summary']['parsed_lines']}")
    print(f"   - Errors: {results['summary']['total_errors']}")
    print(f"   - Warnings: {results['summary']['total_warnings']}")
    
    # Generate outputs
    print(f"\n📝 Generating outputs in {args.output_dir}/...")
    generator = OutputGenerator(results, args.output_dir)
    
    json_file = generator.generate_json()
    print(f"   ✓ JSON: {json_file}")
    
    csv_files = generator.generate_csv()
    for csv_file in csv_files:
        print(f"   ✓ CSV: {csv_file}")
    
    html_file = generator.generate_html()
    print(f"   ✓ HTML: {html_file}")
    
    # Generate Arabic summary if configured
    arabic_gen = ArabicSummaryGenerator(results, args.output_dir)
    summary_file = arabic_gen.generate_summary()
    if summary_file:
        print(f"   ✓ Arabic Summary: {summary_file}")
    
    print(f"\n✨ All done! Open {html_file} to view the report.")
    return 0


if __name__ == '__main__':
    exit(main())
