"""
Log parsers for different formats with auto-detection
"""

import re
from datetime import datetime
from typing import Dict, Optional, Tuple
from enum import Enum


class LogFormat(Enum):
    """Supported log formats"""
    SYSLOG = "syslog"
    NGINX_ACCESS = "nginx_access"
    NGINX_ERROR = "nginx_error"
    APP = "app"
    UNKNOWN = "unknown"


class LogParser:
    """Main log parser with auto-detection"""
    
    def __init__(self, format_hint: str = "auto"):
        self.format_hint = format_hint
        
        # Regex patterns for different log formats
        self.patterns = {
            LogFormat.SYSLOG: re.compile(
                r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
                r'(?P<host>\S+)\s+(?P<process>\S+?)(\[(?P<pid>\d+)\])?\s*:\s*'
                r'(?P<message>.+)'
            ),
            LogFormat.NGINX_ACCESS: re.compile(
                r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
                r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>\S+)"\s+'
                r'(?P<status>\d+)\s+(?P<bytes>\S+)\s+'
                r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
            ),
            LogFormat.NGINX_ERROR: re.compile(
                r'(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
                r'\[(?P<severity>\w+)\]\s+(?P<pid>\d+)#(?P<tid>\d+):\s+'
                r'(\*(?P<cid>\d+)\s+)?(?P<message>.+)'
            ),
            LogFormat.APP: re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
                r'(\.\d+)?\s+(?P<severity>ERROR|WARN|WARNING|INFO|DEBUG)'
                r'(\s+\[(?P<logger>[^\]]+)\])?\s*[-:]?\s*(?P<message>.+)',
                re.IGNORECASE
            )
        }
        
        # IP address pattern
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    def detect_format(self, line: str) -> LogFormat:
        """Auto-detect log format from line"""
        if self.format_hint != "auto":
            # Use hint if provided
            try:
                return LogFormat(self.format_hint)
            except ValueError:
                pass
        
        # Try each pattern
        for fmt, pattern in self.patterns.items():
            if pattern.match(line.strip()):
                return fmt
        
        return LogFormat.UNKNOWN
    
    def parse_line(self, line: str, source_file: str = "", line_number: int = 0) -> Optional[Dict]:
        """
        Parse a log line and return normalized data
        
        Returns normalized schema:
        - timestamp: ISO8601 string
        - source_file: filename
        - format: log format type
        - severity: error/warn/info/debug/unknown
        - message: normalized message
        - ip: IP address if found
        - status_code: HTTP status if found
        - endpoint: URL path if found
        - raw_line: original line (optional)
        """
        line = line.strip()
        if not line:
            return None
        
        log_format = self.detect_format(line)
        
        if log_format == LogFormat.UNKNOWN:
            # Still try to extract some info
            return {
                'timestamp': datetime.now().isoformat(),
                'source_file': source_file,
                'format': log_format.value,
                'severity': 'unknown',
                'message': line[:200],  # Truncate long lines
                'ip': None,
                'status_code': None,
                'endpoint': None,
                'line_number': line_number
            }
        
        # Parse based on format
        pattern = self.patterns[log_format]
        match = pattern.match(line)
        
        if not match:
            return None
        
        data = match.groupdict()
        
        # Normalize based on format
        if log_format == LogFormat.NGINX_ACCESS:
            return self._normalize_nginx_access(data, source_file, line_number)
        elif log_format == LogFormat.NGINX_ERROR:
            return self._normalize_nginx_error(data, source_file, line_number)
        elif log_format == LogFormat.SYSLOG:
            return self._normalize_syslog(data, source_file, line_number)
        elif log_format == LogFormat.APP:
            return self._normalize_app(data, source_file, line_number)
        
        return None
    
    def _normalize_nginx_access(self, data: Dict, source_file: str, line_number: int) -> Dict:
        """Normalize nginx access log"""
        timestamp_str = data.get('timestamp', '')
        try:
            dt = datetime.strptime(timestamp_str.split()[0], '%d/%b/%Y:%H:%M:%S')
            iso_timestamp = dt.isoformat()
        except:
            iso_timestamp = datetime.now().isoformat()
        
        return {
            'timestamp': iso_timestamp,
            'source_file': source_file,
            'format': LogFormat.NGINX_ACCESS.value,
            'severity': self._status_to_severity(data.get('status', '200')),
            'message': f"{data.get('method', 'GET')} {data.get('path', '/')}",
            'ip': data.get('ip'),
            'status_code': data.get('status'),
            'endpoint': data.get('path'),
            'method': data.get('method'),
            'line_number': line_number
        }
    
    def _normalize_nginx_error(self, data: Dict, source_file: str, line_number: int) -> Dict:
        """Normalize nginx error log"""
        timestamp_str = data.get('timestamp', '')
        try:
            dt = datetime.strptime(timestamp_str, '%Y/%m/%d %H:%M:%S')
            iso_timestamp = dt.isoformat()
        except:
            iso_timestamp = datetime.now().isoformat()
        
        severity = data.get('severity', 'error').lower()
        if severity == 'warn':
            severity = 'warn'
        elif severity in ['error', 'crit', 'alert', 'emerg']:
            severity = 'error'
        else:
            severity = 'info'
        
        return {
            'timestamp': iso_timestamp,
            'source_file': source_file,
            'format': LogFormat.NGINX_ERROR.value,
            'severity': severity,
            'message': data.get('message', ''),
            'ip': None,
            'status_code': None,
            'endpoint': None,
            'line_number': line_number
        }
    
    def _normalize_syslog(self, data: Dict, source_file: str, line_number: int) -> Dict:
        """Normalize syslog"""
        # Syslog doesn't have year, use current year
        month = data.get('month', 'Jan')
        day = data.get('day', '1')
        time_str = data.get('time', '00:00:00')
        
        try:
            current_year = datetime.now().year
            dt_str = f"{current_year} {month} {day} {time_str}"
            dt = datetime.strptime(dt_str, '%Y %b %d %H:%M:%S')
            iso_timestamp = dt.isoformat()
        except:
            iso_timestamp = datetime.now().isoformat()
        
        message = data.get('message', '')
        severity = self._detect_severity(message)
        
        # Try to extract IP from message
        ip_match = self.ip_pattern.search(message)
        ip = ip_match.group(0) if ip_match else None
        
        return {
            'timestamp': iso_timestamp,
            'source_file': source_file,
            'format': LogFormat.SYSLOG.value,
            'severity': severity,
            'message': message,
            'ip': ip,
            'status_code': None,
            'endpoint': None,
            'host': data.get('host'),
            'process': data.get('process'),
            'line_number': line_number
        }
    
    def _normalize_app(self, data: Dict, source_file: str, line_number: int) -> Dict:
        """Normalize generic application log"""
        timestamp_str = data.get('timestamp', '')
        try:
            dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            iso_timestamp = dt.isoformat()
        except:
            iso_timestamp = datetime.now().isoformat()
        
        severity = data.get('severity', 'info').lower()
        if severity == 'warning':
            severity = 'warn'
        
        message = data.get('message', '')
        
        # Try to extract IP from message
        ip_match = self.ip_pattern.search(message)
        ip = ip_match.group(0) if ip_match else None
        
        return {
            'timestamp': iso_timestamp,
            'source_file': source_file,
            'format': LogFormat.APP.value,
            'severity': severity,
            'message': message,
            'ip': ip,
            'status_code': None,
            'endpoint': None,
            'logger': data.get('logger'),
            'line_number': line_number
        }
    
    def _status_to_severity(self, status: str) -> str:
        """Convert HTTP status code to severity"""
        try:
            code = int(status)
            if code >= 500:
                return 'error'
            elif code >= 400:
                return 'warn'
            else:
                return 'info'
        except:
            return 'info'
    
    def _detect_severity(self, message: str) -> str:
        """Detect severity from message content"""
        message_upper = message.upper()
        if any(word in message_upper for word in ['ERROR', 'FATAL', 'CRITICAL', 'FAIL']):
            return 'error'
        elif any(word in message_upper for word in ['WARN', 'WARNING']):
            return 'warn'
        elif any(word in message_upper for word in ['INFO', 'INFORMATION']):
            return 'info'
        elif 'DEBUG' in message_upper:
            return 'debug'
        return 'info'
