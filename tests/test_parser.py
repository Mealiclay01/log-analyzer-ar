"""
Unit tests for log parsers
"""

import unittest
from log_analyzer_ar.parser import LogParser, LogFormat


class TestSyslogParser(unittest.TestCase):
    """Test syslog parsing"""
    
    def setUp(self):
        self.parser = LogParser()
    
    def test_syslog_format_detection(self):
        """Test syslog format detection"""
        line = "Jan 17 10:15:32 webserver sshd[1234]: Failed password"
        fmt = self.parser.detect_format(line)
        self.assertEqual(fmt, LogFormat.SYSLOG)
    
    def test_syslog_parsing(self):
        """Test syslog parsing"""
        line = "Jan 17 10:15:32 webserver sshd[1234]: Failed password for user from 192.168.1.100"
        entry = self.parser.parse_line(line, "test.log", 1)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry['format'], LogFormat.SYSLOG.value)
        self.assertIn('timestamp', entry)
        self.assertEqual(entry['ip'], '192.168.1.100')


class TestNginxAccessParser(unittest.TestCase):
    """Test nginx access log parsing"""
    
    def setUp(self):
        self.parser = LogParser()
    
    def test_nginx_access_format_detection(self):
        """Test nginx access format detection"""
        line = '192.168.1.101 - - [17/Jan/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        fmt = self.parser.detect_format(line)
        self.assertEqual(fmt, LogFormat.NGINX_ACCESS)
    
    def test_nginx_access_parsing(self):
        """Test nginx access parsing"""
        line = '192.168.1.101 - - [17/Jan/2026:10:15:32 +0000] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        entry = self.parser.parse_line(line, "access.log", 1)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry['format'], LogFormat.NGINX_ACCESS.value)
        self.assertEqual(entry['ip'], '192.168.1.101')
        self.assertEqual(entry['status_code'], '200')
        self.assertEqual(entry['endpoint'], '/api/users')
        self.assertEqual(entry['severity'], 'info')


class TestNginxErrorParser(unittest.TestCase):
    """Test nginx error log parsing"""
    
    def setUp(self):
        self.parser = LogParser()
    
    def test_nginx_error_format_detection(self):
        """Test nginx error format detection"""
        line = "2026/01/17 10:15:32 [error] 1234#0: *1 connect() failed"
        fmt = self.parser.detect_format(line)
        self.assertEqual(fmt, LogFormat.NGINX_ERROR)
    
    def test_nginx_error_parsing(self):
        """Test nginx error parsing"""
        line = "2026/01/17 10:15:32 [error] 1234#0: *1 connect() failed (111: Connection refused)"
        entry = self.parser.parse_line(line, "error.log", 1)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry['format'], LogFormat.NGINX_ERROR.value)
        self.assertEqual(entry['severity'], 'error')


class TestAppLogParser(unittest.TestCase):
    """Test application log parsing"""
    
    def setUp(self):
        self.parser = LogParser()
    
    def test_app_log_format_detection(self):
        """Test app log format detection"""
        line = "2026-01-17 10:15:32.123 ERROR [database] Connection failed"
        fmt = self.parser.detect_format(line)
        self.assertEqual(fmt, LogFormat.APP)
    
    def test_app_log_parsing(self):
        """Test app log parsing"""
        line = "2026-01-17 10:15:32.123 ERROR [database] Connection pool exhausted, retrying..."
        entry = self.parser.parse_line(line, "app.log", 1)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry['format'], LogFormat.APP.value)
        self.assertEqual(entry['severity'], 'error')
        self.assertEqual(entry['logger'], 'database')


class TestUnknownFormat(unittest.TestCase):
    """Test unknown format handling"""
    
    def setUp(self):
        self.parser = LogParser()
    
    def test_unknown_format(self):
        """Test that unknown formats don't crash"""
        line = "This is some random text that doesn't match any pattern"
        entry = self.parser.parse_line(line, "unknown.log", 1)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry['format'], LogFormat.UNKNOWN.value)
        self.assertEqual(entry['severity'], 'unknown')


if __name__ == '__main__':
    unittest.main()
