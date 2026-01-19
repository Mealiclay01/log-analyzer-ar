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
        ips_data = self._prepare_ips_data()
        endpoints_data = self._prepare_endpoints_data()
        
        html_content = self._generate_html_template(
            summary, severity_counts, notable_findings,
            timeline_data, severity_data, status_data,
            ips_data, endpoints_data
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
    
    def _prepare_ips_data(self) -> Dict:
        """Prepare top IPs data for Chart.js"""
        ips = self.results.get('top_ips', [])[:10]
        return {
            'labels': [item['ip'] for item in ips],
            'data': [item['count'] for item in ips]
        }
    
    def _prepare_endpoints_data(self) -> Dict:
        """Prepare top endpoints data for Chart.js"""
        endpoints = self.results.get('top_endpoints', [])[:10]
        return {
            'labels': [item['endpoint'] for item in endpoints],
            'data': [item['count'] for item in endpoints]
        }
    
    def _escape_html(self, text: str) -> str:
        """Safely escape HTML to prevent XSS"""
        return html.escape(str(text))
    
    def _generate_html_template(self, summary: Dict, severity_counts: Dict,
                                notable_findings: Dict, timeline_data: Dict,
                                severity_data: Dict, status_data: Dict,
                                ips_data: Dict, endpoints_data: Dict) -> str:
        """Generate complete HTML template with sidebar navigation"""
        
        # Format time range
        time_range = summary.get('time_range', {})
        time_range_str = ""
        if time_range.get('start') and time_range.get('end'):
            time_range_str = f"{time_range['start']} to {time_range['end']}"
        
        # Get file list
        files_analyzed = summary.get('files_analyzed', [])
        files_str = ', '.join([str(Path(f).name) for f in files_analyzed[:3]])
        if len(files_analyzed) > 3:
            files_str += f' (+{len(files_analyzed) - 3} more)'
        
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>📊 Log Analysis Report</title>
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css">
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        :root {{
            --sidebar-width: 260px;
            --header-height: 70px;
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --bg-card: #ffffff;
            --bg-sidebar: #2c3e50;
            --text-primary: #212529;
            --text-secondary: #6c757d;
            --text-sidebar: #ecf0f1;
            --border-color: #dee2e6;
            --accent-color: #3498db;
            --accent-hover: #2980b9;
            --error-color: #e74c3c;
            --warning-color: #f39c12;
            --info-color: #3498db;
            --success-color: #27ae60;
            --shadow-sm: 0 1px 3px rgba(0,0,0,0.08);
            --shadow: 0 2px 8px rgba(0,0,0,0.1);
            --shadow-lg: 0 4px 16px rgba(0,0,0,0.15);
        }}
        
        [data-theme="dark"] {{
            --bg-primary: #1a1a1a;
            --bg-secondary: #0d0d0d;
            --bg-card: #252525;
            --bg-sidebar: #1a1a1a;
            --text-primary: #ffffff;
            --text-secondary: #b0b0b0;
            --text-sidebar: #ecf0f1;
            --border-color: #333333;
            --shadow-sm: 0 1px 3px rgba(0,0,0,0.3);
            --shadow: 0 2px 8px rgba(0,0,0,0.4);
            --shadow-lg: 0 4px 16px rgba(0,0,0,0.5);
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg-secondary);
            color: var(--text-primary);
            line-height: 1.6;
            transition: background 0.3s, color 0.3s;
            overflow-x: hidden;
        }}
        
        /* Sidebar */
        .sidebar {{
            position: fixed;
            left: 0;
            top: 0;
            bottom: 0;
            width: var(--sidebar-width);
            background: var(--bg-sidebar);
            color: var(--text-sidebar);
            padding: 20px 0;
            overflow-y: auto;
            box-shadow: var(--shadow-lg);
            z-index: 1000;
            transition: transform 0.3s ease;
        }}
        
        .sidebar-header {{
            padding: 0 20px 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            margin-bottom: 20px;
        }}
        
        .sidebar-header h3 {{
            font-size: 1.3rem;
            font-weight: 600;
            margin-bottom: 5px;
        }}
        
        .sidebar-header .subtitle {{
            font-size: 0.85rem;
            opacity: 0.7;
        }}
        
        .nav-item {{
            display: flex;
            align-items: center;
            padding: 12px 20px;
            color: var(--text-sidebar);
            text-decoration: none;
            transition: all 0.2s;
            cursor: pointer;
            border-left: 3px solid transparent;
        }}
        
        .nav-item:hover {{
            background: rgba(255, 255, 255, 0.1);
            border-left-color: var(--accent-color);
        }}
        
        .nav-item.active {{
            background: rgba(52, 152, 219, 0.2);
            border-left-color: var(--accent-color);
            font-weight: 600;
        }}
        
        .nav-icon {{
            margin-right: 12px;
            font-size: 1.1rem;
            width: 20px;
            text-align: center;
        }}
        
        .mobile-toggle {{
            display: none;
            position: fixed;
            top: 15px;
            left: 15px;
            z-index: 1100;
            background: var(--accent-color);
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1.2rem;
        }}
        
        /* Main Layout */
        .layout {{
            margin-left: var(--sidebar-width);
            min-height: 100vh;
        }}
        
        /* Header */
        .header {{
            background: var(--bg-card);
            padding: 20px 30px;
            box-shadow: var(--shadow-sm);
            position: sticky;
            top: 0;
            z-index: 100;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .header-content {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }}
        
        .header-left h1 {{
            font-size: 1.8rem;
            color: var(--text-primary);
            margin-bottom: 5px;
        }}
        
        .header-meta {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}
        
        .meta-item {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 600;
            background: var(--success-color);
            color: white;
        }}
        
        .header-right {{
            display: flex;
            gap: 10px;
            align-items: center;
        }}
        
        .btn {{
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }}
        
        .btn-primary {{
            background: var(--accent-color);
            color: white;
        }}
        
        .btn-primary:hover {{
            background: var(--accent-hover);
        }}
        
        .btn-secondary {{
            background: var(--bg-secondary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }}
        
        .btn-secondary:hover {{
            background: var(--bg-primary);
        }}
        
        .search-box {{
            padding: 8px 14px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            background: var(--bg-primary);
            color: var(--text-primary);
            font-size: 0.9rem;
            min-width: 250px;
        }}
        
        /* Content */
        .content {{
            padding: 30px;
        }}
        
        .section {{
            display: none;
            animation: fadeIn 0.3s;
        }}
        
        .section.active {{
            display: block;
        }}
        
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        
        /* KPI Cards */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .kpi-card {{
            background: var(--bg-card);
            padding: 20px;
            border-radius: 12px;
            box-shadow: var(--shadow-sm);
            border-left: 4px solid var(--accent-color);
            transition: all 0.2s;
        }}
        
        .kpi-card:hover {{
            transform: translateY(-3px);
            box-shadow: var(--shadow);
        }}
        
        .kpi-card.error {{ border-left-color: var(--error-color); }}
        .kpi-card.warning {{ border-left-color: var(--warning-color); }}
        .kpi-card.info {{ border-left-color: var(--info-color); }}
        .kpi-card.success {{ border-left-color: var(--success-color); }}
        
        .kpi-label {{
            font-size: 0.85rem;
            color: var(--text-secondary);
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        
        .kpi-value {{
            font-size: 2rem;
            font-weight: 700;
            color: var(--text-primary);
        }}
        
        .kpi-value.error {{ color: var(--error-color); }}
        .kpi-value.warning {{ color: var(--warning-color); }}
        .kpi-value.info {{ color: var(--info-color); }}
        .kpi-value.success {{ color: var(--success-color); }}
        
        /* Alerts */
        .alert {{
            padding: 16px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid;
            position: relative;
            display: flex;
            justify-content: space-between;
            align-items: start;
        }}
        
        .alert-error {{
            background: rgba(231, 76, 60, 0.1);
            border-color: var(--error-color);
        }}
        
        .alert-warning {{
            background: rgba(243, 156, 18, 0.1);
            border-color: var(--warning-color);
        }}
        
        .alert-content {{
            flex: 1;
        }}
        
        .alert-title {{
            font-weight: 600;
            margin-bottom: 4px;
        }}
        
        .alert-desc {{
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}
        
        .alert-dismiss {{
            background: none;
            border: none;
            font-size: 1.3rem;
            cursor: pointer;
            color: var(--text-secondary);
            padding: 0;
            margin-left: 10px;
            opacity: 0.6;
            transition: opacity 0.2s;
        }}
        
        .alert-dismiss:hover {{
            opacity: 1;
        }}
        
        /* Cards */
        .card {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: var(--shadow-sm);
        }}
        
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid var(--border-color);
        }}
        
        .card-title {{
            font-size: 1.3rem;
            font-weight: 600;
            color: var(--text-primary);
        }}
        
        .card-actions {{
            display: flex;
            gap: 8px;
        }}
        
        /* Tables */
        .table-wrapper {{
            overflow-x: auto;
        }}
        
        table.dataTable {{
            width: 100% !important;
            border-collapse: collapse;
        }}
        
        table.dataTable thead th {{
            background: var(--accent-color);
            color: white;
            font-weight: 600;
            padding: 12px;
            text-align: left;
        }}
        
        table.dataTable tbody td {{
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-primary);
        }}
        
        table.dataTable tbody tr:hover {{
            background: var(--bg-secondary);
        }}
        
        [data-theme="dark"] table.dataTable {{
            background: var(--bg-card);
        }}
        
        [data-theme="dark"] .dataTables_wrapper .dataTables_filter input,
        [data-theme="dark"] .dataTables_wrapper .dataTables_length select {{
            background: var(--bg-primary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }}
        
        [data-theme="dark"] .dataTables_wrapper {{
            color: var(--text-primary);
        }}
        
        /* Charts */
        .chart-container {{
            position: relative;
            height: 350px;
            margin: 20px 0;
        }}
        
        .chart-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 25px;
            margin-bottom: 25px;
        }}
        
        /* Export Grid */
        .export-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 20px;
        }}
        
        .export-item {{
            background: var(--bg-card);
            padding: 20px;
            border-radius: 10px;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--border-color);
            transition: all 0.2s;
        }}
        
        .export-item:hover {{
            box-shadow: var(--shadow);
            transform: translateY(-2px);
        }}
        
        .export-icon {{
            font-size: 2rem;
            margin-bottom: 10px;
        }}
        
        .export-title {{
            font-weight: 600;
            margin-bottom: 5px;
        }}
        
        .export-desc {{
            font-size: 0.85rem;
            color: var(--text-secondary);
            margin-bottom: 15px;
        }}
        
        .export-actions {{
            display: flex;
            gap: 8px;
        }}
        
        .btn-sm {{
            padding: 6px 12px;
            font-size: 0.85rem;
        }}
        
        /* Filter Controls */
        .filter-bar {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            margin-bottom: 20px;
            padding: 15px;
            background: var(--bg-secondary);
            border-radius: 8px;
        }}
        
        .filter-group {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        
        .filter-label {{
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-secondary);
        }}
        
        .filter-options {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}
        
        .checkbox-label {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85rem;
            transition: all 0.2s;
        }}
        
        .checkbox-label:hover {{
            background: var(--accent-color);
            color: white;
            border-color: var(--accent-color);
        }}
        
        .checkbox-label input {{
            cursor: pointer;
        }}
        
        /* Compact mode */
        body.compact-mode .kpi-card {{
            padding: 15px;
        }}
        
        body.compact-mode .kpi-value {{
            font-size: 1.5rem;
        }}
        
        body.compact-mode .card {{
            padding: 18px;
        }}
        
        body.compact-mode table.dataTable tbody td {{
            padding: 8px;
            font-size: 0.9rem;
        }}
        
        /* Mobile */
        @media (max-width: 768px) {{
            .sidebar {{
                transform: translateX(-100%);
            }}
            
            .sidebar.open {{
                transform: translateX(0);
            }}
            
            .mobile-toggle {{
                display: block;
            }}
            
            .layout {{
                margin-left: 0;
            }}
            
            .header-content {{
                flex-direction: column;
                align-items: flex-start;
            }}
            
            .search-box {{
                width: 100%;
            }}
            
            .kpi-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            
            .chart-grid {{
                grid-template-columns: 1fr;
            }}
        }}
        
        @media (max-width: 480px) {{
            .kpi-grid {{
                grid-template-columns: 1fr;
            }}
        }}
        
        /* Print */
        @media print {{
            .sidebar, .header-right, .mobile-toggle, .alert-dismiss, .btn {{
                display: none !important;
            }}
            
            .layout {{
                margin-left: 0;
            }}
            
            .card {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <!-- Mobile Toggle -->
    <button class="mobile-toggle" onclick="toggleSidebar()">☰</button>
    
    <!-- Sidebar -->
    <nav class="sidebar" id="sidebar">
        <div class="sidebar-header">
            <h3>📊 Log Analyzer</h3>
            <div class="subtitle">Analysis Report</div>
        </div>
        <a class="nav-item active" href="#overview" onclick="navigateTo('overview', event)">
            <span class="nav-icon">📈</span> Overview
        </a>
        <a class="nav-item" href="#timeline" onclick="navigateTo('timeline', event)">
            <span class="nav-icon">📅</span> Timeline
        </a>
        <a class="nav-item" href="#severity" onclick="navigateTo('severity', event)">
            <span class="nav-icon">⚠️</span> Severity
        </a>
        <a class="nav-item" href="#ips" onclick="navigateTo('ips', event)">
            <span class="nav-icon">🌐</span> IP Addresses
        </a>
        <a class="nav-item" href="#status" onclick="navigateTo('status', event)">
            <span class="nav-icon">📡</span> Status Codes
        </a>
        <a class="nav-item" href="#endpoints" onclick="navigateTo('endpoints', event)">
            <span class="nav-icon">🔗</span> Endpoints
        </a>
        <a class="nav-item" href="#messages" onclick="navigateTo('messages', event)">
            <span class="nav-icon">💬</span> Messages
        </a>
        <a class="nav-item" href="#export" onclick="navigateTo('export', event)">
            <span class="nav-icon">📥</span> Export
        </a>
    </nav>
    
    <!-- Main Layout -->
    <div class="layout">
        <!-- Header -->
        <header class="header">
            <div class="header-content">
                <div class="header-left">
                    <h1>📊 Log Analysis Report</h1>
                    <div class="header-meta">
                        {f'<div class="meta-item"><span>📅</span> {self._escape_html(time_range_str)}</div>' if time_range_str else ''}
                        {f'<div class="meta-item"><span>📁</span> {self._escape_html(files_str)}</div>' if files_str else ''}
                        <div class="meta-item">
                            <span class="badge">{summary.get('parse_rate', 0)}% parsed</span>
                        </div>
                    </div>
                </div>
                <div class="header-right">
                    <input type="text" class="search-box" id="globalSearch" placeholder="🔍 Search..." onkeyup="globalSearch()">
                    <button class="btn btn-secondary" onclick="toggleCompact()">⚡ Compact</button>
                    <button class="btn btn-primary" onclick="toggleTheme()">🌓 Theme</button>
                </div>
            </div>
        </header>
        
        <!-- Content -->
        <main class="content">
            <!-- Overview Section -->
            <section id="overview" class="section active">
                <div class="kpi-grid">
                    <div class="kpi-card">
                        <div class="kpi-label">📊 Total Lines</div>
                        <div class="kpi-value">{summary.get('total_lines', 0):,}</div>
                    </div>
                    <div class="kpi-card success">
                        <div class="kpi-label">✅ Parsed</div>
                        <div class="kpi-value success">{summary.get('parsed_lines', 0):,}</div>
                    </div>
                    <div class="kpi-card info">
                        <div class="kpi-label">📈 Parse Rate</div>
                        <div class="kpi-value info">{summary.get('parse_rate', 0)}%</div>
                    </div>
                    <div class="kpi-card error">
                        <div class="kpi-label">❌ Errors</div>
                        <div class="kpi-value error">{summary.get('total_errors', 0):,}</div>
                    </div>
                    <div class="kpi-card warning">
                        <div class="kpi-label">⚠️ Warnings</div>
                        <div class="kpi-value warning">{summary.get('total_warnings', 0):,}</div>
                    </div>
                    <div class="kpi-card info">
                        <div class="kpi-label">🌐 Unique IPs</div>
                        <div class="kpi-value">{summary.get('unique_ips', 0):,}</div>
                    </div>
                </div>
                
                <!-- Notable Findings -->
                {self._generate_notable_findings_html(notable_findings)}
                
                <!-- Charts Grid -->
                <div class="chart-grid">
                    <div class="card">
                        <div class="card-header">
                            <h2 class="card-title">Severity Distribution</h2>
                        </div>
                        <div class="chart-container">
                            <canvas id="severityChart"></canvas>
                        </div>
                    </div>
                    
                    <div class="card">
                        <div class="card-header">
                            <h2 class="card-title">Timeline Overview</h2>
                        </div>
                        <div class="chart-container">
                            <canvas id="timelinePreviewChart"></canvas>
                        </div>
                    </div>
                </div>
            </section>
            
            <!-- Timeline Section -->
            <section id="timeline" class="section">
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Events Timeline</h2>
                        <div class="card-actions">
                            <button class="btn btn-sm btn-secondary" onclick="filterTimeline('1h', event)">1h</button>
                            <button class="btn btn-sm btn-secondary" onclick="filterTimeline('6h', event)">6h</button>
                            <button class="btn btn-sm btn-secondary" onclick="filterTimeline('24h', event)">24h</button>
                            <button class="btn btn-sm btn-primary" onclick="filterTimeline('all', event)">All</button>
                        </div>
                    </div>
                    <div class="chart-container" style="height: 400px;">
                        <canvas id="timelineChart"></canvas>
                    </div>
                </div>
            </section>
            
            <!-- Severity Section -->
            <section id="severity" class="section">
                <div class="filter-bar">
                    <div class="filter-group">
                        <div class="filter-label">Filter by Severity:</div>
                        <div class="filter-options">
                            <label class="checkbox-label">
                                <input type="checkbox" checked onchange="filterSeverity()"> ERROR
                            </label>
                            <label class="checkbox-label">
                                <input type="checkbox" checked onchange="filterSeverity()"> WARN
                            </label>
                            <label class="checkbox-label">
                                <input type="checkbox" checked onchange="filterSeverity()"> INFO
                            </label>
                            <label class="checkbox-label">
                                <input type="checkbox" checked onchange="filterSeverity()"> DEBUG
                            </label>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Severity Distribution</h2>
                    </div>
                    <div class="table-wrapper">
                        <table id="severityTable" class="display">
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
            </section>
            
            <!-- IPs Section -->
            <section id="ips" class="section">
                <div class="chart-grid">
                    <div class="card">
                        <div class="card-header">
                            <h2 class="card-title">Top IP Addresses</h2>
                        </div>
                        <div class="chart-container">
                            <canvas id="ipsChart"></canvas>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">IP Address Details</h2>
                    </div>
                    <div class="table-wrapper">
                        <table id="ipsTable" class="display">
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
            </section>
            
            <!-- Status Codes Section -->
            <section id="status" class="section">
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Status Code Distribution</h2>
                    </div>
                    <div class="chart-container">
                        <canvas id="statusChart"></canvas>
                    </div>
                    <div class="table-wrapper">
                        <table id="statusTable" class="display">
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
                </div>
            </section>
            
            <!-- Endpoints Section -->
            <section id="endpoints" class="section">
                {self._generate_endpoints_section_enhanced(endpoints_data)}
            </section>
            
            <!-- Messages Section -->
            <section id="messages" class="section">
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Top Log Messages</h2>
                    </div>
                    <div class="table-wrapper">
                        <table id="messagesTable" class="display">
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
            </section>
            
            <!-- Export Section -->
            <section id="export" class="section">
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Export Data</h2>
                    </div>
                    <div class="export-grid">
                        <div class="export-item">
                            <div class="export-icon">📄</div>
                            <div class="export-title">analysis.json</div>
                            <div class="export-desc">Complete analysis results in JSON format</div>
                            <div class="export-actions">
                                <button class="btn btn-sm btn-primary" onclick="window.open('analysis.json')">Open</button>
                            </div>
                        </div>
                        
                        <div class="export-item">
                            <div class="export-icon">📊</div>
                            <div class="export-title">CSV Files</div>
                            <div class="export-desc">Summary, IPs, status codes, messages, timeline</div>
                            <div class="export-actions">
                                <button class="btn btn-sm btn-primary" onclick="window.open('summary.csv')">Summary</button>
                                <button class="btn btn-sm btn-secondary" onclick="window.open('top_ips.csv')">IPs</button>
                            </div>
                        </div>
                        
                        <div class="export-item">
                            <div class="export-icon">🌐</div>
                            <div class="export-title">report.html</div>
                            <div class="export-desc">This interactive report (shareable)</div>
                            <div class="export-actions">
                                <button class="btn btn-sm btn-primary" onclick="copyReportPath()">Copy Path</button>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card" style="margin-top: 20px; background: var(--bg-secondary);">
                        <h3 style="margin-bottom: 10px;">💡 Viewing in Codespaces</h3>
                        <p style="margin-bottom: 8px;">To view this report in GitHub Codespaces:</p>
                        <ol style="margin-left: 20px; line-height: 1.8;">
                            <li>Navigate to the output directory: <code>cd output</code></li>
                            <li>Start a local server: <code>python3 -m http.server 8000</code></li>
                            <li>Click the "Open in Browser" notification or go to the Ports tab</li>
                            <li>Open <code>report.html</code> in your browser</li>
                        </ol>
                    </div>
                </div>
            </section>
            
            <!-- Footer -->
            <div class="card" style="text-align: center; margin-top: 40px;">
                <p style="color: var(--text-secondary);">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <p style="color: var(--text-secondary); margin-top: 8px;">Log Analyzer AR · Premium Report</p>
            </div>
        </main>
    </div>
    
    <script>
        // Initialize theme from system preference or saved
        window.addEventListener('DOMContentLoaded', () => {{
            const savedTheme = localStorage.getItem('theme');
            const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            const theme = savedTheme || (systemPrefersDark ? 'dark' : 'light');
            document.documentElement.setAttribute('data-theme', theme);
            
            // Initialize DataTables
            initDataTables();
            
            // Initialize Charts
            initCharts();
            
            // Handle hash navigation
            handleHashNavigation();
            window.addEventListener('hashchange', handleHashNavigation);
        }});
        
        // Theme toggle
        function toggleTheme() {{
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        }}
        
        // Compact mode toggle
        function toggleCompact() {{
            document.body.classList.toggle('compact-mode');
        }}
        
        // Sidebar toggle (mobile)
        function toggleSidebar() {{
            document.getElementById('sidebar').classList.toggle('open');
        }}
        
        // Navigation
        function navigateTo(section, evt) {{
            // Update active nav item
            document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
            if (evt && evt.target) {{
                evt.target.classList.add('active');
            }} else {{
                // For hash navigation, find and activate the nav item
                document.querySelectorAll('.nav-item').forEach(item => {{
                    if (item.getAttribute('href') === '#' + section) {{
                        item.classList.add('active');
                    }}
                }});
            }}
            
            // Show section
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.getElementById(section).classList.add('active');
            
            // Close sidebar on mobile
            if (window.innerWidth <= 768) {{
                document.getElementById('sidebar').classList.remove('open');
            }}
            
            // Scroll to top
            window.scrollTo(0, 0);
        }}
        
        // Handle hash navigation (deep linking)
        function handleHashNavigation() {{
            const hash = window.location.hash.substring(1);
            if (hash) {{
                const section = document.getElementById(hash);
                if (section) {{
                    navigateTo(hash, null);
                }}
            }}
        }}
        
        // Global search
        function globalSearch() {{
            const term = document.getElementById('globalSearch').value.toLowerCase();
            document.querySelectorAll('.dataTables_filter input').forEach(input => {{
                input.value = term;
                $(input).trigger('keyup');
            }});
        }}
        
        // Timeline filter
        function filterTimeline(period, evt) {{
            // Visual feedback
            if (evt && evt.target) {{
                evt.target.parentElement.querySelectorAll('.btn').forEach(b => {{
                    b.classList.remove('btn-primary');
                    b.classList.add('btn-secondary');
                }});
                evt.target.classList.remove('btn-secondary');
                evt.target.classList.add('btn-primary');
            }}
            
            // Note: Actual filtering would require re-rendering the chart with filtered data
            // For this implementation, we show all data (static report)
            console.log('Timeline filter:', period);
        }}
        
        // Severity filter
        function filterSeverity() {{
            // Get checked severities
            const checkboxes = document.querySelectorAll('.filter-options input[type="checkbox"]');
            const checked = Array.from(checkboxes).filter(cb => cb.checked).map(cb => cb.parentElement.textContent.trim());
            
            // Filter severity table if DataTable is initialized
            const table = $('#severityTable').DataTable();
            if (table && checked.length > 0) {{
                // Build regex for filtering
                const pattern = checked.join('|');
                table.column(0).search(pattern, true, false).draw();
            }}
        }}
        
        // Copy report path
        function copyReportPath() {{
            const path = window.location.href;
            navigator.clipboard.writeText(path).then(() => {{
                alert('Report path copied to clipboard!');
            }});
        }}
        
        // Initialize DataTables
        function initDataTables() {{
            const tables = ['severityTable', 'ipsTable', 'statusTable', 'messagesTable'];
            tables.forEach(tableId => {{
                const el = document.getElementById(tableId);
                if (el) {{
                    $(el).DataTable({{
                        pageLength: 25,
                        order: [[1, 'desc']],
                        language: {{
                            search: "Search:",
                            lengthMenu: "Show _MENU_ entries",
                            info: "Showing _START_ to _END_ of _TOTAL_ entries"
                        }}
                    }});
                }}
            }});
            
            // Endpoints table if exists
            const endpointsTable = document.getElementById('endpointsTable');
            if (endpointsTable) {{
                $(endpointsTable).DataTable({{
                    pageLength: 25,
                    order: [[1, 'desc']]
                }});
            }}
        }}
        
        // Initialize Charts
        function initCharts() {{
            const chartColors = {{
                primary: '#3498db',
                error: '#e74c3c',
                warning: '#f39c12',
                info: '#3498db',
                success: '#27ae60',
                purple: '#9b59b6',
                gray: '#95a5a6'
            }};
            
            // Severity Chart (Doughnut)
            new Chart(document.getElementById('severityChart'), {{
                type: 'doughnut',
                data: {{
                    labels: {json.dumps(severity_data['labels'])},
                    datasets: [{{
                        data: {json.dumps(severity_data['data'])},
                        backgroundColor: [chartColors.info, chartColors.error, chartColors.warning, chartColors.gray],
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{
                                padding: 15,
                                font: {{ size: 12 }}
                            }}
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    const label = context.label || '';
                                    const value = context.parsed || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = ((value / total) * 100).toFixed(1);
                                    return `${{label}}: ${{value.toLocaleString()}} (${{percentage}}%)`;
                                }}
                            }}
                        }}
                    }}
                }}
            }});
            
            // Timeline Preview Chart
            new Chart(document.getElementById('timelinePreviewChart'), {{
                type: 'line',
                data: {{
                    labels: {json.dumps(timeline_data['labels'])},
                    datasets: [{{
                        label: 'Events',
                        data: {json.dumps(timeline_data['data'])},
                        borderColor: chartColors.primary,
                        backgroundColor: chartColors.primary + '30',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2,
                        pointRadius: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        y: {{ 
                            beginAtZero: true,
                            grid: {{ color: 'rgba(0,0,0,0.05)' }}
                        }},
                        x: {{
                            grid: {{ display: false }}
                        }}
                    }},
                    plugins: {{
                        legend: {{ display: false }}
                    }}
                }}
            }});
            
            // Timeline Full Chart
            new Chart(document.getElementById('timelineChart'), {{
                type: 'line',
                data: {{
                    labels: {json.dumps(timeline_data['labels'])},
                    datasets: [{{
                        label: 'Events Over Time',
                        data: {json.dumps(timeline_data['data'])},
                        borderColor: chartColors.primary,
                        backgroundColor: chartColors.primary + '20',
                        fill: true,
                        tension: 0.3,
                        borderWidth: 3,
                        pointRadius: 3,
                        pointHoverRadius: 6
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        y: {{ 
                            beginAtZero: true,
                            title: {{
                                display: true,
                                text: 'Event Count'
                            }}
                        }},
                        x: {{
                            title: {{
                                display: true,
                                text: 'Time'
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{ 
                            position: 'top',
                            labels: {{ font: {{ size: 13 }} }}
                        }},
                        tooltip: {{
                            mode: 'index',
                            intersect: false
                        }}
                    }}
                }}
            }});
            
            // Status Code Chart (Bar)
            new Chart(document.getElementById('statusChart'), {{
                type: 'bar',
                data: {{
                    labels: {json.dumps(status_data['labels'])},
                    datasets: [{{
                        label: 'Requests',
                        data: {json.dumps(status_data['data'])},
                        backgroundColor: chartColors.primary,
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        y: {{ 
                            beginAtZero: true,
                            title: {{
                                display: true,
                                text: 'Count'
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{ display: false }},
                        tooltip: {{
                            callbacks: {{
                                title: function(context) {{
                                    return 'Status Code: ' + context[0].label;
                                }}
                            }}
                        }}
                    }}
                }}
            }});
            
            // IPs Chart (Horizontal Bar)
            const ipsChartEl = document.getElementById('ipsChart');
            if (ipsChartEl) {{
                new Chart(ipsChartEl, {{
                    type: 'bar',
                    data: {{
                        labels: {json.dumps(ips_data['labels'])},
                        datasets: [{{
                            label: 'Requests',
                            data: {json.dumps(ips_data['data'])},
                            backgroundColor: chartColors.success,
                            borderWidth: 0
                        }}]
                    }},
                    options: {{
                        indexAxis: 'y',
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {{
                            x: {{ 
                                beginAtZero: true,
                                title: {{
                                    display: true,
                                    text: 'Request Count'
                                }}
                            }}
                        }},
                        plugins: {{
                            legend: {{ display: false }}
                        }}
                    }}
                }});
            }}
            
            // Endpoints Chart (Horizontal Bar) - if data exists
            const endpointsChartEl = document.getElementById('endpointsChart');
            if (endpointsChartEl && {json.dumps(endpoints_data['labels'])}.length > 0) {{
                new Chart(endpointsChartEl, {{
                    type: 'bar',
                    data: {{
                        labels: {json.dumps(endpoints_data['labels'])},
                        datasets: [{{
                            label: 'Requests',
                            data: {json.dumps(endpoints_data['data'])},
                            backgroundColor: chartColors.purple,
                            borderWidth: 0
                        }}]
                    }},
                    options: {{
                        indexAxis: 'y',
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {{
                            x: {{ 
                                beginAtZero: true,
                                title: {{
                                    display: true,
                                    text: 'Request Count'
                                }}
                            }}
                        }},
                        plugins: {{
                            legend: {{ display: false }}
                        }}
                    }}
                }});
            }}
        }}
    </script>
</body>
</html>'''
    
    def _generate_notable_findings_html(self, findings: Dict) -> str:
        """Generate HTML for notable findings alerts with dismiss buttons"""
        if not findings.get('has_findings'):
            return ''
        
        html_parts = []
        
        if findings.get('high_error_rate'):
            html_parts.append('''
                <div class="alert alert-error">
                    <div class="alert-content">
                        <div class="alert-title">⚠️ High Error Rate Detected!</div>
                        <div class="alert-desc">More than 10% of log entries are errors. This may indicate system instability or configuration issues.</div>
                    </div>
                    <button class="alert-dismiss" onclick="this.parentElement.remove()">×</button>
                </div>
            ''')
        
        if findings.get('error_spike'):
            html_parts.append('''
                <div class="alert alert-warning">
                    <div class="alert-content">
                        <div class="alert-title">📈 Traffic Spike Detected!</div>
                        <div class="alert-desc">Unusual spike in log volume detected. Monitor system resources and investigate potential causes.</div>
                    </div>
                    <button class="alert-dismiss" onclick="this.parentElement.remove()">×</button>
                </div>
            ''')
        
        if findings.get('suspicious_ips'):
            ips = ', '.join([f"{ip['ip']} ({ip['count']} requests)" 
                            for ip in findings['suspicious_ips'][:3]])
            html_parts.append(f'''
                <div class="alert alert-warning">
                    <div class="alert-content">
                        <div class="alert-title">🔍 Suspicious IP Activity!</div>
                        <div class="alert-desc">High request volumes from: {self._escape_html(ips)}. Review access logs and consider rate limiting.</div>
                    </div>
                    <button class="alert-dismiss" onclick="this.parentElement.remove()">×</button>
                </div>
            ''')
        
        if findings.get('repeated_500s'):
            html_parts.append('''
                <div class="alert alert-error">
                    <div class="alert-content">
                        <div class="alert-title">💥 Server Errors Detected!</div>
                        <div class="alert-desc">Multiple 5xx status codes found. Check application logs and server health immediately.</div>
                    </div>
                    <button class="alert-dismiss" onclick="this.parentElement.remove()">×</button>
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
    
    def _generate_endpoints_section_enhanced(self, endpoints_data: Dict) -> str:
        """Generate enhanced endpoints section with chart"""
        endpoints = self.results.get('top_endpoints', [])
        if not endpoints:
            return '<div class="card"><p style="text-align: center; color: var(--text-secondary);">No endpoint data available</p></div>'
        
        return f'''
            <div class="chart-grid">
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Top Endpoints</h2>
                    </div>
                    <div class="chart-container">
                        <canvas id="endpointsChart"></canvas>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Endpoint Details</h2>
                </div>
                <div class="table-wrapper">
                    <table id="endpointsTable" class="display">
                        <thead>
                            <tr>
                                <th>Endpoint</th>
                                <th>Request Count</th>
                            </tr>
                        </thead>
                        <tbody>
                            {self._generate_table_rows(endpoints, ['endpoint', 'count'])}
                        </tbody>
                    </table>
                </div>
            </div>
        '''
