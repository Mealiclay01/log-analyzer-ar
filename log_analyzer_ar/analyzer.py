"""
Log analyzer with advanced analytics and notable findings detection
"""

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from .parser import LogParser


class LogAnalyzer:
    """Advanced log analyzer with notable findings"""
    
    def __init__(self, format_hint: str = "auto", timezone: str = "UTC",
                 from_time: Optional[str] = None, to_time: Optional[str] = None,
                 top_n: int = 10, max_lines: Optional[int] = None):
        self.parser = LogParser(format_hint)
        self.timezone = timezone
        self.from_time = self._parse_time_filter(from_time) if from_time else None
        self.to_time = self._parse_time_filter(to_time) if to_time else None
        self.top_n = top_n
        self.max_lines = max_lines
        
        # Statistics
        self.total_lines = 0
        self.parsed_lines = 0
        self.skipped_lines = 0
        
        # Collected data
        self.entries = []
        self.severity_counts = Counter()
        self.message_counter = Counter()
        self.ip_counter = Counter()
        self.status_counter = Counter()
        self.endpoint_counter = Counter()
        self.hourly_timeline = defaultdict(int)
        self.daily_timeline = defaultdict(int)
        
        # For notable findings
        self.error_bursts = []
        self.suspicious_ips = []
    
    def _parse_time_filter(self, time_str: str) -> datetime:
        """Parse time filter from ISO format or relative"""
        try:
            return datetime.fromisoformat(time_str.replace('Z', '+00:00'))
        except:
            # Try relative time (e.g., "1h", "24h", "7d")
            match = re.match(r'(\d+)([hd])', time_str)
            if match:
                value, unit = int(match.group(1)), match.group(2)
                if unit == 'h':
                    return datetime.now() - timedelta(hours=value)
                elif unit == 'd':
                    return datetime.now() - timedelta(days=value)
            return datetime.now()
    
    def analyze_file(self, filepath: str, verbose: bool = False) -> None:
        """Analyze a single log file with streaming"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    self.total_lines += 1
                    
                    # Check max_lines limit
                    if self.max_lines and self.total_lines > self.max_lines:
                        if verbose:
                            print(f"  Reached max_lines limit: {self.max_lines}")
                        break
                    
                    # Parse line
                    entry = self.parser.parse_line(line, filepath, line_num)
                    
                    if not entry:
                        self.skipped_lines += 1
                        continue
                    
                    # Apply time filters
                    if self.from_time or self.to_time:
                        try:
                            entry_time = datetime.fromisoformat(entry['timestamp'])
                            if self.from_time and entry_time < self.from_time:
                                self.skipped_lines += 1
                                continue
                            if self.to_time and entry_time > self.to_time:
                                self.skipped_lines += 1
                                continue
                        except:
                            pass
                    
                    self.parsed_lines += 1
                    self.entries.append(entry)
                    
                    # Update counters
                    self._update_counters(entry)
                    
                    if verbose and self.total_lines % 1000 == 0:
                        print(f"  Processed {self.total_lines} lines...")
        
        except Exception as e:
            if verbose:
                print(f"  Error reading {filepath}: {e}")
    
    def _update_counters(self, entry: Dict) -> None:
        """Update all counters with entry data"""
        # Severity
        self.severity_counts[entry['severity']] += 1
        
        # Message (normalize for better grouping)
        message = entry['message']
        normalized_msg = self._normalize_message(message)
        self.message_counter[normalized_msg] += 1
        
        # IP addresses
        if entry.get('ip'):
            self.ip_counter[entry['ip']] += 1
        
        # Status codes
        if entry.get('status_code'):
            self.status_counter[entry['status_code']] += 1
        
        # Endpoints
        if entry.get('endpoint'):
            self.endpoint_counter[entry['endpoint']] += 1
        
        # Timeline
        try:
            dt = datetime.fromisoformat(entry['timestamp'])
            hour_key = dt.strftime('%Y-%m-%d %H:00')
            day_key = dt.strftime('%Y-%m-%d')
            self.hourly_timeline[hour_key] += 1
            self.daily_timeline[day_key] += 1
        except:
            pass
    
    def _normalize_message(self, message: str) -> str:
        """Normalize message for pattern grouping"""
        # Replace numbers with 'N'
        normalized = re.sub(r'\d+', 'N', message)
        # Replace IPs with 'IP'
        normalized = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'IP', normalized)
        # Replace UUIDs
        normalized = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID', normalized, flags=re.IGNORECASE)
        # Truncate to 150 chars
        return normalized[:150]
    
    def detect_notable_findings(self) -> Dict[str, Any]:
        """Detect anomalies and notable patterns"""
        findings = {
            'has_findings': False,
            'error_spike': False,
            'high_error_rate': False,
            'suspicious_ips': [],
            'repeated_404s': [],
            'repeated_500s': [],
            'ip_bursts': []
        }
        
        # Check error rate
        if self.parsed_lines > 0:
            error_rate = self.severity_counts.get('error', 0) / self.parsed_lines
            if error_rate > 0.1:  # More than 10% errors
                findings['high_error_rate'] = True
                findings['has_findings'] = True
        
        # Check for error spikes in timeline
        if len(self.hourly_timeline) > 2:
            values = list(self.hourly_timeline.values())
            avg = sum(values) / len(values)
            max_val = max(values)
            if max_val > avg * 3:  # 3x average
                findings['error_spike'] = True
                findings['has_findings'] = True
        
        # Check for suspicious IPs (high request count)
        if self.ip_counter:
            avg_requests = sum(self.ip_counter.values()) / len(self.ip_counter)
            for ip, count in self.ip_counter.most_common(5):
                if count > avg_requests * 5:  # 5x average
                    findings['suspicious_ips'].append({'ip': ip, 'count': count})
                    findings['has_findings'] = True
        
        # Check for repeated 404s
        for status, count in self.status_counter.items():
            if status == '404' and count > 10:
                findings['repeated_404s'].append({'count': count})
                findings['has_findings'] = True
            elif status and int(status) >= 500 and count > 5:
                findings['repeated_500s'].append({'status': status, 'count': count})
                findings['has_findings'] = True
        
        return findings
    
    def get_results(self) -> Dict[str, Any]:
        """Get complete analysis results"""
        # Sort timelines
        hourly_timeline = sorted(
            [{'hour': hour, 'count': count} for hour, count in self.hourly_timeline.items()],
            key=lambda x: x['hour']
        )
        
        daily_timeline = sorted(
            [{'day': day, 'count': count} for day, count in self.daily_timeline.items()],
            key=lambda x: x['day']
        )
        
        # Get top items
        top_messages = [
            {'message': msg, 'count': count}
            for msg, count in self.message_counter.most_common(self.top_n)
        ]
        
        top_ips = [
            {'ip': ip, 'count': count}
            for ip, count in self.ip_counter.most_common(self.top_n)
        ]
        
        top_status_codes = [
            {'status_code': code, 'count': count}
            for code, count in self.status_counter.most_common(self.top_n)
        ]
        
        top_endpoints = [
            {'endpoint': ep, 'count': count}
            for ep, count in self.endpoint_counter.most_common(self.top_n)
        ]
        
        # Detect notable findings
        notable_findings = self.detect_notable_findings()
        
        return {
            'summary': {
                'total_lines': self.total_lines,
                'parsed_lines': self.parsed_lines,
                'skipped_lines': self.skipped_lines,
                'parse_rate': round(self.parsed_lines / self.total_lines * 100, 2) if self.total_lines > 0 else 0,
                'total_errors': self.severity_counts.get('error', 0),
                'total_warnings': self.severity_counts.get('warn', 0),
                'total_info': self.severity_counts.get('info', 0),
                'total_debug': self.severity_counts.get('debug', 0),
                'unique_ips': len(self.ip_counter),
                'unique_status_codes': len(self.status_counter),
                'unique_endpoints': len(self.endpoint_counter),
                'time_range': self._get_time_range(),
            },
            'severity_counts': dict(self.severity_counts),
            'top_messages': top_messages,
            'top_ips': top_ips,
            'top_status_codes': top_status_codes,
            'top_endpoints': top_endpoints,
            'timeline_by_hour': hourly_timeline,
            'timeline_by_day': daily_timeline,
            'notable_findings': notable_findings,
        }
    
    def _get_time_range(self) -> Dict[str, str]:
        """Get time range of analyzed logs"""
        if not self.entries:
            return {'start': '', 'end': ''}
        
        timestamps = [e['timestamp'] for e in self.entries if e.get('timestamp')]
        if not timestamps:
            return {'start': '', 'end': ''}
        
        return {
            'start': min(timestamps),
            'end': max(timestamps)
        }
