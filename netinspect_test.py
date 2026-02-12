#!/usr/bin/env python3
"""
Test suite for netinspect network monitoring tool
Run with: python3 -m pytest test_netinspect.py
or: python3 test_netinspect.py
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
from collections import defaultdict

# Import the NetworkMonitor class
# Note: You may need to adjust the import based on your file name
try:
    from netmon import NetworkMonitor
except ImportError:
    # If running as standalone, try to import from current directory
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from netmon import NetworkMonitor


class TestNetworkMonitor(unittest.TestCase):
    """Test cases for NetworkMonitor class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.monitor = NetworkMonitor()
    
    def test_initialization(self):
        """Test that NetworkMonitor initializes correctly"""
        self.assertIsInstance(self.monitor.process_data, defaultdict)
        self.assertEqual(self.monitor.update_interval, 1.0)
        self.assertIsInstance(self.monitor.last_net_io, dict)
        self.assertIsInstance(self.monitor.interface_map, dict)
    
    def test_format_bytes(self):
        """Test byte formatting to human readable"""
        # Test bytes
        self.assertEqual(self.monitor.format_bytes(512), "512.00 B")
        
        # Test kilobytes
        self.assertEqual(self.monitor.format_bytes(1024), "1.00 KB")
        self.assertEqual(self.monitor.format_bytes(2048), "2.00 KB")
        
        # Test megabytes
        self.assertEqual(self.monitor.format_bytes(1024 * 1024), "1.00 MB")
        self.assertEqual(self.monitor.format_bytes(5 * 1024 * 1024), "5.00 MB")
        
        # Test gigabytes
        self.assertEqual(self.monitor.format_bytes(1024 * 1024 * 1024), "1.00 GB")
        
        # Test terabytes
        self.assertEqual(self.monitor.format_bytes(1024 * 1024 * 1024 * 1024), "1.00 TB")
    
    def test_format_rate(self):
        """Test rate formatting to human readable"""
        # Test bytes per second
        self.assertEqual(self.monitor.format_rate(512), "512.00 B/s")
        
        # Test kilobytes per second
        self.assertEqual(self.monitor.format_rate(1024), "1.00 KB/s")
        self.assertEqual(self.monitor.format_rate(2048), "2.00 KB/s")
        
        # Test megabytes per second
        self.assertEqual(self.monitor.format_rate(1024 * 1024), "1.00 MB/s")
        self.assertEqual(self.monitor.format_rate(5 * 1024 * 1024), "5.00 MB/s")
        
        # Test gigabytes per second
        self.assertEqual(self.monitor.format_rate(1024 * 1024 * 1024), "1.00 GB/s")
    
    def test_get_color_for_rate(self):
        """Test color assignment based on transfer rate"""
        max_rate = 1000
        
        # Test minimal rate (0-5%)
        self.assertEqual(self.monitor.get_color_for_rate(0, max_rate), 1)
        self.assertEqual(self.monitor.get_color_for_rate(30, max_rate), 1)
        
        # Test low rate (5-10%)
        self.assertEqual(self.monitor.get_color_for_rate(70, max_rate), 2)
        
        # Test moderate-low rate (10-20%)
        self.assertEqual(self.monitor.get_color_for_rate(150, max_rate), 3)
        
        # Test moderate rate (20-40%)
        self.assertEqual(self.monitor.get_color_for_rate(300, max_rate), 4)
        
        # Test moderate-high rate (40-60%)
        self.assertEqual(self.monitor.get_color_for_rate(500, max_rate), 5)
        
        # Test high rate (60-80%)
        self.assertEqual(self.monitor.get_color_for_rate(700, max_rate), 6)
        
        # Test maximum rate (80-100%)
        self.assertEqual(self.monitor.get_color_for_rate(900, max_rate), 7)
        self.assertEqual(self.monitor.get_color_for_rate(1000, max_rate), 7)
    
    def test_get_color_for_zero_max_rate(self):
        """Test color assignment when max rate is zero"""
        self.assertEqual(self.monitor.get_color_for_rate(0, 0), 1)
    
    def test_get_top_processes_empty(self):
        """Test getting top processes when no data exists"""
        top = self.monitor.get_top_processes(10)
        self.assertEqual(len(top), 0)
    
    def test_get_top_processes_with_data(self):
        """Test getting top processes with sample data"""
        # Add sample process data
        self.monitor.process_data[1] = {
            'rate': 1000,
            'total_bytes': 5000,
            'name': 'chrome',
            'path': '/usr/bin/chrome',
            'adapter': 'eth0',
            'last_seen': 1234567890
        }
        self.monitor.process_data[2] = {
            'rate': 2000,
            'total_bytes': 10000,
            'name': 'firefox',
            'path': '/usr/bin/firefox',
            'adapter': 'wlan0',
            'last_seen': 1234567890
        }
        self.monitor.process_data[3] = {
            'rate': 500,
            'total_bytes': 2000,
            'name': 'python',
            'path': '/usr/bin/python',
            'adapter': 'eth0',
            'last_seen': 1234567890
        }
        
        # Get top 2 processes
        top = self.monitor.get_top_processes(2)
        
        # Should be sorted by rate (descending)
        self.assertEqual(len(top), 2)
        self.assertEqual(top[0][0], 2)  # firefox (highest rate)
        self.assertEqual(top[0][1]['rate'], 2000)
        self.assertEqual(top[1][0], 1)  # chrome (second highest)
        self.assertEqual(top[1][1]['rate'], 1000)
    
    def test_get_top_processes_limit(self):
        """Test that get_top_processes respects the limit"""
        # Add 5 processes
        for i in range(1, 6):
            self.monitor.process_data[i] = {
                'rate': i * 100,
                'total_bytes': i * 1000,
                'name': f'proc{i}',
                'path': f'/usr/bin/proc{i}',
                'adapter': 'eth0',
                'last_seen': 1234567890
            }
        
        # Request only top 3
        top = self.monitor.get_top_processes(3)
        self.assertEqual(len(top), 3)
        
        # Should get the 3 with highest rates
        self.assertEqual(top[0][1]['rate'], 500)  # proc5
        self.assertEqual(top[1][1]['rate'], 400)  # proc4
        self.assertEqual(top[2][1]['rate'], 300)  # proc3
    
    @patch('netmon.psutil.net_if_addrs')
    def test_update_interface_map(self, mock_net_if_addrs):
        """Test interface map update"""
        # Mock network interface addresses
        mock_addr = Mock()
        mock_addr.family = 2  # AF_INET
        mock_addr.address = '192.168.1.100'
        
        mock_net_if_addrs.return_value = {
            'eth0': [mock_addr]
        }
        
        self.monitor.update_interface_map()
        
        # Check that interface map was updated
        self.assertEqual(self.monitor.interface_map['192.168.1.100'], 'eth0')
    
    def test_process_data_structure(self):
        """Test that process data has correct structure"""
        # Add a process
        pid = 1234
        self.monitor.process_data[pid] = {
            'rate': 1000,
            'total_bytes': 5000,
            'name': 'test_proc',
            'path': '/usr/bin/test',
            'adapter': 'eth0',
            'last_seen': 1234567890
        }
        
        # Verify structure
        self.assertIn('rate', self.monitor.process_data[pid])
        self.assertIn('total_bytes', self.monitor.process_data[pid])
        self.assertIn('name', self.monitor.process_data[pid])
        self.assertIn('path', self.monitor.process_data[pid])
        self.assertIn('adapter', self.monitor.process_data[pid])
        self.assertIn('last_seen', self.monitor.process_data[pid])


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.monitor = NetworkMonitor()
    
    def test_format_bytes_zero(self):
        """Test formatting zero bytes"""
        self.assertEqual(self.monitor.format_bytes(0), "0.00 B")
    
    def test_format_rate_zero(self):
        """Test formatting zero rate"""
        self.assertEqual(self.monitor.format_rate(0), "0.00 B/s")
    
    def test_format_bytes_negative(self):
        """Test formatting negative bytes (should not happen but test anyway)"""
        result = self.monitor.format_bytes(-1024)
        self.assertIn("-", result)
    
    def test_very_large_bytes(self):
        """Test formatting very large byte values"""
        petabyte = 1024 ** 5
        result = self.monitor.format_bytes(petabyte)
        self.assertIn("PB", result)
    
    def test_get_top_processes_more_than_available(self):
        """Test requesting more processes than available"""
        # Add only 2 processes
        self.monitor.process_data[1] = {
            'rate': 1000,
            'total_bytes': 5000,
            'name': 'proc1',
            'path': '/usr/bin/proc1',
            'adapter': 'eth0',
            'last_seen': 1234567890
        }
        self.monitor.process_data[2] = {
            'rate': 2000,
            'total_bytes': 10000,
            'name': 'proc2',
            'path': '/usr/bin/proc2',
            'adapter': 'eth0',
            'last_seen': 1234567890
        }
        
        # Request 10
        top = self.monitor.get_top_processes(10)
        
        # Should only return 2
        self.assertEqual(len(top), 2)


class TestIntegration(unittest.TestCase):
    """Integration tests for the network monitor"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.monitor = NetworkMonitor()
    
    def test_full_workflow(self):
        """Test a complete monitoring workflow"""
        # Simulate adding process data over time
        
        # First update
        self.monitor.process_data[1] = {
            'rate': 1000,
            'total_bytes': 1000,
            'name': 'chrome',
            'path': '/usr/bin/chrome',
            'adapter': 'eth0',
            'last_seen': 1234567890
        }
        
        # Second update - increase rate and total
        self.monitor.process_data[1]['rate'] = 2000
        self.monitor.process_data[1]['total_bytes'] = 3000
        
        # Verify data accumulated
        self.assertEqual(self.monitor.process_data[1]['total_bytes'], 3000)
        self.assertEqual(self.monitor.process_data[1]['rate'], 2000)
        
        # Get top processes
        top = self.monitor.get_top_processes(5)
        self.assertEqual(len(top), 1)
        self.assertEqual(top[0][1]['name'], 'chrome')


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestNetworkMonitor))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
