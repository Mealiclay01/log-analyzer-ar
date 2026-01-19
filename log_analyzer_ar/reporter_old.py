"""
Output generators for JSON, CSV, and HTML reports
"""

import csv
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import html


class OutputGenerator:
    """Generate various output formats"""
    
    def __init__(self, results: Dict, output_dir: str, 
                 generate_json: bool = True,
                 generate_csv: bool = True,
                 generate_html: bool = True):
        self.results = results
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generate_json_flag = generate_json
        self.generate_csv_flag = generate_csv
        self.generate_html_flag = generate_html
        self.generated_files = []
    
    def generate_all(self) -> List[str]:
        """Generate all enabled outputs"""
        if self.generate_json_flag:
            self.generated_files.append(self.generate_json())
        
        if self.generate_csv_flag:
            self.generated_files.extend(self.generate_csv())
        
        if self.generate_html_flag:
            self.generated_files.append(self.generate_html())
        
        return self.generated_files
    
    def generate_json(self) -> str:
        """Generate JSON output with safe serialization"""
        json_file = self.output_dir / 'analysis.json'
        
        # Ensure all data is JSON-serializable
        output_data = self._prepare_json_data(self.results)
        
        try:
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            # Fallback with str conversion
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=True, default=str)
        
        return str(json_file)
    
    def _prepare_json_data(self, data: Any) -> Any:
        """Recursively prepare data for JSON serialization"""
        if isinstance(data, dict):
            return {k: self._prepare_json_data(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._prepare_json_data(item) for item in data]
        elif isinstance(data, (str, int, float, bool, type(None))):
            return data
        else:
            return str(data)
    
    def generate_csv(self) -> List[str]:
        """Generate CSV outputs"""
        csv_files = []
        
        # Summary CSV
        summary_file = self.output_dir / 'summary.csv'
        with open(summary_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Metric', 'Value'])
            for key, value in self.results['summary'].items():
                if isinstance(value, dict):
                    # Handle nested dicts (like time_range)
                    for sub_key, sub_value in value.items():
                        writer.writerow([f"{key}_{sub_key}", sub_value])
                else:
                    writer.writerow([key, value])
        csv_files.append(str(summary_file))
        
        # Top messages CSV
        if self.results.get('top_messages'):
            messages_file = self.output_dir / 'top_messages.csv'
            with open(messages_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['message', 'count'])
                writer.writeheader()
                writer.writerows(self.results['top_messages'])
            csv_files.append(str(messages_file))
        
        # Top IPs CSV
        if self.results.get('top_ips'):
            ips_file = self.output_dir / 'top_ips.csv'
            with open(ips_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['ip', 'count'])
                writer.writeheader()
                writer.writerows(self.results['top_ips'])
            csv_files.append(str(ips_file))
        
        # Top status codes CSV
        if self.results.get('top_status_codes'):
            status_file = self.output_dir / 'top_status_codes.csv'
            with open(status_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['status_code', 'count'])
                writer.writeheader()
                writer.writerows(self.results['top_status_codes'])
            csv_files.append(str(status_file))
        
        # Top endpoints CSV (new)
        if self.results.get('top_endpoints'):
            endpoints_file = self.output_dir / 'top_endpoints.csv'
            with open(endpoints_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['endpoint', 'count'])
                writer.writeheader()
                writer.writerows(self.results['top_endpoints'])
            csv_files.append(str(endpoints_file))
        
        # Hourly timeline CSV
        if self.results.get('timeline_by_hour'):
            timeline_file = self.output_dir / 'timeline_hourly.csv'
            with open(timeline_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['hour', 'count'])
                writer.writeheader()
                writer.writerows(self.results['timeline_by_hour'])
            csv_files.append(str(timeline_file))
        
        # Daily timeline CSV (new)
        if self.results.get('timeline_by_day'):
            daily_file = self.output_dir / 'timeline_daily.csv'
            with open(daily_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['day', 'count'])
                writer.writeheader()
                writer.writerows(self.results['timeline_by_day'])
            csv_files.append(str(daily_file))
        
        return csv_files
    
    def generate_html(self) -> str:
        """Generate portfolio-grade HTML report with Chart.js and dark mode"""
        html_file = self.output_dir / 'report.html'
        
        summary = self.results.get('summary', {})
        severity_counts = self.results.get('severity_counts', {})
        notable_findings = self.results.get('notable_findings', {})
        
        # Prepare data for Chart.js
        timeline_data = self._prepare_timeline_data()
        severity_data = self._prepare_severity_data()
        status_data = self._prepare_status_data()
        
        html_content = self._generate_html_template(
            summary, severity_counts, notable_findings,
            timeline_data, severity_data, status_data
        )
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(html_file)
    
    def _prepare_timeline_data(self) -> Dict:
        """Prepare timeline data for Chart.js"""
        hourly = self.results.get('timeline_by_hour', [])
        return {
            'labels': [item['hour'] for item in hourly],
            'data': [item['count'] for item in hourly]
        }
    
    def _prepare_severity_data(self) -> Dict:
        """Prepare severity data for Chart.js"""
        severity = self.results.get('severity_counts', {})
        return {
            'labels': list(severity.keys()),
            'data': list(severity.values())
        }
    
    def _prepare_status_data(self) -> Dict:
        """Prepare status code data for Chart.js"""
        status = self.results.get('top_status_codes', [])[:10]
        return {
            'labels': [str(item['status_code']) for item in status],
            'data': [item['count'] for item in status]
        }
    
    def _escape_html(self, text: str) -> str:
        """Safely escape HTML to prevent XSS"""
        return html.escape(str(text))
    
    def _generate_html_template(self, summary: Dict, severity_counts: Dict,
                                notable_findings: Dict, timeline_data: Dict,
                                severity_data: Dict, status_data: Dict) -> str:
        """Generate complete HTML template"""
        
        # Format time range
        time_range = summary.get('time_range', {})
        time_range_str = ""
        if time_range.get('start') and time_range.get('end'):
            time_range_str = f"{time_range['start']} to {time_range['end']}"
        
        return f'''<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>📊 Log Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        :root {{
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --bg-card: #ffffff;
            --text-primary: #212529;
            --text-secondary: #6c757d;
            --border-color: #dee2e6;
            --accent-color: #4CAF50;
            --error-color: #dc3545;
            --warning-color: #ffc107;
            --info-color: #17a2b8;
            --shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        [data-theme="dark"] {{
            --bg-primary: #1a1a1a;
            --bg-secondary: #2d2d2d;
            --bg-card: #2d2d2d;
            --text-primary: #ffffff;
            --text-secondary: #b0b0b0;
            --border-color: #404040;
            --shadow: 0 2px 8px rgba(0,0,0,0.3);
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg-secondary);
            color: var(--text-primary);
            line-height: 1.6;
            transition: background 0.3s, color 0.3s;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        /* Header */
        .header {{
            background: var(--accent-color);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: var(--shadow);
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
        }}
        
        .header p {{
            opacity: 0.9;
            font-size: 1.1rem;
        }}
        
        .header .time-range {{
            margin-top: 10px;
            font-size: 0.9rem;
            opacity: 0.8;
        }}
        
        /* Controls */
        .controls {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            flex-wrap: wrap;
            gap: 15px;
        }}
        
        .theme-toggle {{
            background: var(--bg-card);
            border: 2px solid var(--border-color);
            color: var(--text-primary);
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1rem;
            transition: all 0.3s;
        }}
        
        .theme-toggle:hover {{
            background: var(--accent-color);
            color: white;
            border-color: var(--accent-color);
        }}
        
        .search-box {{
            padding: 10px 15px;
            border: 2px solid var(--border-color);
            border-radius: 8px;
            background: var(--bg-card);
            color: var(--text-primary);
            font-size: 1rem;
            width: 300px;
        }}
        
        /* Tabs */
        .tabs {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid var(--border-color);
            flex-wrap: wrap;
        }}
        
        .tab {{
            padding: 12px 24px;
            cursor: pointer;
            border: none;
            background: transparent;
            color: var(--text-secondary);
            font-size: 1rem;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
        }}
        
        .tab:hover {{
            color: var(--accent-color);
        }}
        
        .tab.active {{
            color: var(--accent-color);
            border-bottom-color: var(--accent-color);
        }}
        
        .tab-content {{
            display: none;
        }}
        
        .tab-content.active {{
            display: block;
            animation: fadeIn 0.3s;
        }}
        
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        
        /* Hero Stats */
        .hero-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: var(--bg-card);
            padding: 25px;
            border-radius: 12px;
            box-shadow: var(--shadow);
            border-left: 4px solid var(--accent-color);
            transition: transform 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-bottom: 8px;
        }}
        
        .stat-value {{
            font-size: 2rem;
            font-weight: bold;
            color: var(--text-primary);
        }}
        
        .stat-value.error {{ color: var(--error-color); }}
        .stat-value.warning {{ color: var(--warning-color); }}
        .stat-value.info {{ color: var(--info-color); }}
        
        /* Alerts */
        .alert {{
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid;
        }}
        
        .alert-warning {{
            background: rgba(255, 193, 7, 0.1);
            border-color: var(--warning-color);
            color: var(--text-primary);
        }}
        
        .alert-error {{
            background: rgba(220, 53, 69, 0.1);
            border-color: var(--error-color);
            color: var(--text-primary);
        }}
        
        /* Cards */
        .card {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: var(--shadow);
        }}
        
        .card h2 {{
            color: var(--text-primary);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border-color);
        }}
        
        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        
        th {{
            background: var(--accent-color);
            color: white;
            font-weight: 600;
            position: sticky;
            top: 0;
        }}
        
        tr:hover {{
            background: var(--bg-secondary);
        }}
        
        tbody tr {{
            transition: background 0.2s;
        }}
        
        /* Charts */
        .chart-container {{
            position: relative;
            height: 300px;
            margin: 20px 0;
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{ font-size: 1.8rem; }}
            .hero-stats {{ grid-template-columns: repeat(2, 1fr); }}
            .controls {{ flex-direction: column; align-items: stretch; }}
            .search-box {{ width: 100%; }}
        }}
        
        @media (max-width: 480px) {{
            .hero-stats {{ grid-template-columns: 1fr; }}
        }}
        
        /* RTL Support */
        [dir="rtl"] {{
            direction: rtl;
        }}
        
        [dir="rtl"] .stat-card {{
            border-left: none;
            border-right: 4px solid var(--accent-color);
        }}
        
        [dir="rtl"] .alert {{
            border-left: none;
            border-right: 4px solid;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>📊 Log Analysis Report</h1>
            <p>Comprehensive analysis of system logs</p>
            {f'<div class="time-range">📅 {self._escape_html(time_range_str)}</div>' if time_range_str else ''}
        </div>
        
        <!-- Controls -->
        <div class="controls">
            <button class="theme-toggle" onclick="toggleTheme()">🌓 Toggle Dark Mode</button>
            <input type="text" class="search-box" id="searchBox" placeholder="🔍 Search in tables..." onkeyup="searchTables()">
        </div>
        
        <!-- Tabs -->
        <div class="tabs">
            <button class="tab active" onclick="showTab('overview')">Overview</button>
            <button class="tab" onclick="showTab('timeline')">Timeline</button>
            <button class="tab" onclick="showTab('ips')">IP Analysis</button>
            <button class="tab" onclick="showTab('status')">Status Codes</button>
            <button class="tab" onclick="showTab('messages')">Top Messages</button>
        </div>
        
        <!-- Tab: Overview -->
        <div id="overview" class="tab-content active">
            <!-- Hero Stats -->
            <div class="hero-stats">
                <div class="stat-card">
                    <div class="stat-label">Total Lines</div>
                    <div class="stat-value">{summary.get('total_lines', 0):,}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Parsed</div>
                    <div class="stat-value info">{summary.get('parsed_lines', 0):,}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Parse Rate</div>
                    <div class="stat-value info">{summary.get('parse_rate', 0)}%</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Errors</div>
                    <div class="stat-value error">{summary.get('total_errors', 0):,}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Warnings</div>
                    <div class="stat-value warning">{summary.get('total_warnings', 0):,}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Unique IPs</div>
                    <div class="stat-value">{summary.get('unique_ips', 0):,}</div>
                </div>
            </div>
            
            <!-- Notable Findings -->
            {self._generate_notable_findings_html(notable_findings)}
            
            <!-- Severity Distribution -->
            <div class="card">
                <h2>Severity Distribution</h2>
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>
                <table id="severityTable">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Count</th>
                            <th>Percentage</th>
                        </tr>
                    </thead>
                    <tbody>
                        {self._generate_severity_table_rows(severity_counts, summary.get('parsed_lines', 1))}
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Tab: Timeline -->
        <div id="timeline" class="tab-content">
            <div class="card">
                <h2>Events Timeline (Hourly)</h2>
                <div class="chart-container" style="height: 400px;">
                    <canvas id="timelineChart"></canvas>
                </div>
            </div>
        </div>
        
        <!-- Tab: IPs -->
        <div id="ips" class="tab-content">
            <div class="card">
                <h2>Top IP Addresses</h2>
                <table id="ipsTable" class="searchable">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Request Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {self._generate_table_rows(self.results.get('top_ips', []), ['ip', 'count'])}
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Tab: Status Codes -->
        <div id="status" class="tab-content">
            <div class="card">
                <h2>HTTP Status Code Distribution</h2>
                <div class="chart-container">
                    <canvas id="statusChart"></canvas>
                </div>
                <table id="statusTable" class="searchable">
                    <thead>
                        <tr>
                            <th>Status Code</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {self._generate_table_rows(self.results.get('top_status_codes', []), ['status_code', 'count'])}
                    </tbody>
                </table>
            </div>
            
            <!-- Endpoints -->
            {self._generate_endpoints_section()}
        </div>
        
        <!-- Tab: Messages -->
        <div id="messages" class="tab-content">
            <div class="card">
                <h2>Top Log Messages</h2>
                <table id="messagesTable" class="searchable">
                    <thead>
                        <tr>
                            <th>Message Pattern</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {self._generate_table_rows(self.results.get('top_messages', []), ['message', 'count'])}
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="card" style="margin-top: 40px; text-align: center;">
            <p style="color: var(--text-secondary);">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p style="color: var(--text-secondary); margin-top: 10px;">Log Analyzer AR v1.0.0</p>
        </div>
    </div>
    
    <script>
        // Theme toggle
        function toggleTheme() {{
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            
            // Update charts for theme
            updateChartsForTheme(newTheme);
        }}
        
        // Load saved theme
        window.addEventListener('DOMContentLoaded', () => {{
            const savedTheme = localStorage.getItem('theme') || 'light';
            document.documentElement.setAttribute('data-theme', savedTheme);
        }});
        
        // Tab switching
        function showTab(tabName) {{
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {{
                tab.classList.remove('active');
            }});
            document.querySelectorAll('.tab').forEach(tab => {{
                tab.classList.remove('active');
            }});
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }}
        
        // Search functionality
        function searchTables() {{
            const searchTerm = document.getElementById('searchBox').value.toLowerCase();
            document.querySelectorAll('.searchable tbody tr').forEach(row => {{
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchTerm) ? '' : 'none';
            }});
        }}
        
        // Chart.js setup
        const chartColors = {{
            error: '#dc3545',
            warn: '#ffc107',
            info: '#17a2b8',
            debug: '#6c757d',
            primary: '#4CAF50'
        }};
        
        // Severity Chart
        new Chart(document.getElementById('severityChart'), {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(severity_data['labels'])},
                datasets: [{{
                    data: {json.dumps(severity_data['data'])},
                    backgroundColor: ['#17a2b8', '#dc3545', '#ffc107', '#6c757d']
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
        
        // Timeline Chart
        new Chart(document.getElementById('timelineChart'), {{
            type: 'line',
            data: {{
                labels: {json.dumps(timeline_data['labels'])},
                datasets: [{{
                    label: 'Events',
                    data: {json.dumps(timeline_data['data'])},
                    borderColor: chartColors.primary,
                    backgroundColor: chartColors.primary + '20',
                    fill: true,
                    tension: 0.4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{ beginAtZero: true }}
                }},
                plugins: {{
                    legend: {{ display: false }}
                }}
            }}
        }});
        
        // Status Code Chart
        new Chart(document.getElementById('statusChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(status_data['labels'])},
                datasets: [{{
                    label: 'Requests',
                    data: {json.dumps(status_data['data'])},
                    backgroundColor: chartColors.primary
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{ beginAtZero: true }}
                }},
                plugins: {{
                    legend: {{ display: false }}
                }}
            }}
        }});
        
        function updateChartsForTheme(theme) {{
            // Charts update automatically with CSS variables
        }}
    </script>
</body>
</html>'''
    
    def _generate_notable_findings_html(self, findings: Dict) -> str:
        """Generate HTML for notable findings alerts"""
        if not findings.get('has_findings'):
            return ''
        
        html_parts = []
        
        if findings.get('high_error_rate'):
            html_parts.append('''
                <div class="alert alert-error">
                    <strong>⚠️ High Error Rate Detected!</strong> More than 10% of log entries are errors.
                </div>
            ''')
        
        if findings.get('error_spike'):
            html_parts.append('''
                <div class="alert alert-warning">
                    <strong>📈 Traffic Spike Detected!</strong> Unusual spike in log volume detected.
                </div>
            ''')
        
        if findings.get('suspicious_ips'):
            ips = ', '.join([f"{ip['ip']} ({ip['count']} requests)" 
                            for ip in findings['suspicious_ips'][:3]])
            html_parts.append(f'''
                <div class="alert alert-warning">
                    <strong>🔍 Suspicious IP Activity!</strong> High request volumes from: {self._escape_html(ips)}
                </div>
            ''')
        
        if findings.get('repeated_500s'):
            html_parts.append('''
                <div class="alert alert-error">
                    <strong>💥 Server Errors Detected!</strong> Multiple 5xx status codes found.
                </div>
            ''')
        
        return ''.join(html_parts)
    
    def _generate_severity_table_rows(self, severity_counts: Dict, total: int) -> str:
        """Generate table rows for severity distribution"""
        rows = []
        for severity, count in sorted(severity_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            severity_class = severity.lower() if severity.lower() in ['error', 'warn', 'info'] else ''
            rows.append(f'''
                <tr>
                    <td class="{severity_class}">{self._escape_html(severity.upper())}</td>
                    <td>{count:,}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
            ''')
        return ''.join(rows)
    
    def _generate_table_rows(self, items: List[Dict], fields: List[str]) -> str:
        """Generate table rows from list of dicts"""
        rows = []
        for item in items:
            cells = [f'<td>{self._escape_html(str(item.get(field, "")))}</td>' for field in fields]
            rows.append(f"<tr>{''.join(cells)}</tr>")
        return ''.join(rows)
    
    def _generate_endpoints_section(self) -> str:
        """Generate endpoints section if data exists"""
        endpoints = self.results.get('top_endpoints', [])
        if not endpoints:
            return ''
        
        return f'''
            <div class="card">
                <h2>Top Endpoints</h2>
                <table id="endpointsTable" class="searchable">
                    <thead>
                        <tr>
                            <th>Endpoint</th>
                            <th>Requests</th>
                        </tr>
                    </thead>
                    <tbody>
                        {self._generate_table_rows(endpoints, ['endpoint', 'count'])}
                    </tbody>
                </table>
            </div>
        '''
