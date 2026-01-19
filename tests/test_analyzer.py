"""
Unit tests for analyzer
"""

import unittest
from log_analyzer_ar.analyzer import LogAnalyzer


class TestLogAnalyzer(unittest.TestCase):
    """Test log analyzer functionality"""
    
    def setUp(self):
        self.analyzer = LogAnalyzer()
    
    def test_message_normalization(self):
        """Test message normalization"""
        message = "Connection from 192.168.1.100 port 12345 failed"
        normalized = self.analyzer._normalize_message(message)
        
        # Numbers should be replaced with N
        self.assertNotIn('12345', normalized)
        self.assertIn('N', normalized)
        
        # IPs should be replaced (becomes N.N.N.N after digit replacement)
        self.assertNotIn('192.168.1.100', normalized)
    
    def test_analyze_results_structure(self):
        """Test that results have correct structure"""
        results = self.analyzer.get_results()
        
        self.assertIn('summary', results)
        self.assertIn('severity_counts', results)
        self.assertIn('top_messages', results)
        self.assertIn('top_ips', results)
        self.assertIn('top_endpoints', results)
        self.assertIn('notable_findings', results)


if __name__ == '__main__':
    unittest.main()
