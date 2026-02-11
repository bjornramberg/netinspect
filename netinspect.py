#!/usr/bin/env python3
"""
Network Process Inspector
Inspects network traffic by process and displays top 10 with color coding
based on data sent (brighter = more data)
"""

import curses
import psutil
import time
from collections import defaultdict
from datetime import datetime

class NetworkMonitor:
    def __init__(self):
        self.process_data = defaultdict(lambda: {'bytes': 0, 'name': '', 'path': '', 'last_seen': time.time()})
        self.last_net_io = {}
        self.update_interval = 1.0  # seconds
        
    def get_process_connections(self):
        """Get all processes with network connections"""
        connections = {}
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                conns = proc.net_connections()
                if conns:
                    connections[proc.info['pid']] = {
                        'name': proc.info['name'],
                        'connections': len(conns)
                    }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return connections
    
    def get_network_stats(self):
        """Get network IO stats per process"""
        current_time = time.time()
        
        # Get current network IO counters
        current_net_io = {}
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                io = proc.io_counters()
                exe_path = ''
                try:
                    exe_path = proc.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    exe_path = '[access denied]'
                
                current_net_io[proc.info['pid']] = {
                    'name': proc.info['name'],
                    'path': exe_path,
                    'bytes_sent': io.write_bytes,  # Using write_bytes as proxy
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Calculate deltas
        for pid, data in current_net_io.items():
            if pid in self.last_net_io:
                bytes_delta = data['bytes_sent'] - self.last_net_io[pid]['bytes_sent']
                if bytes_delta > 0:
                    self.process_data[pid]['bytes'] += bytes_delta
                    self.process_data[pid]['name'] = data['name']
                    self.process_data[pid]['path'] = data['path']
                    self.process_data[pid]['last_seen'] = current_time
            else:
                self.process_data[pid]['name'] = data['name']
                self.process_data[pid]['path'] = data['path']
                self.process_data[pid]['last_seen'] = current_time
        
        self.last_net_io = current_net_io
        
        # Clean up old processes (not seen in last 30 seconds)
        pids_to_remove = [pid for pid, data in self.process_data.items() 
                         if current_time - data['last_seen'] > 30]
        for pid in pids_to_remove:
            del self.process_data[pid]
    
    def get_top_processes(self, n=10):
        """Get top N processes by bytes sent"""
        sorted_procs = sorted(
            [(pid, data) for pid, data in self.process_data.items()],
            key=lambda x: x[1]['bytes'],
            reverse=True
        )
        return sorted_procs[:n]
    
    def get_color_for_bytes(self, bytes_sent, max_bytes):
        """Get color pair number based on bytes sent"""
        if max_bytes == 0:
            return 1
        
        ratio = bytes_sent / max_bytes
        
        if ratio > 0.8:
            return 7  # Brightest
        elif ratio > 0.6:
            return 6
        elif ratio > 0.4:
            return 5
        elif ratio > 0.2:
            return 4
        elif ratio > 0.1:
            return 3
        elif ratio > 0.05:
            return 2
        else:
            return 1  # Dimmest
    
    def format_bytes(self, bytes_val):
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"

def main(stdscr):
    # Initialize colors
    curses.start_color()
    curses.use_default_colors()
    
    # Create color pairs (darker to brighter)
    curses.init_pair(1, curses.COLOR_BLUE, -1)
    curses.init_pair(2, curses.COLOR_CYAN, -1)
    curses.init_pair(3, curses.COLOR_GREEN, -1)
    curses.init_pair(4, curses.COLOR_YELLOW, -1)
    curses.init_pair(5, curses.COLOR_MAGENTA, -1)
    curses.init_pair(6, curses.COLOR_RED, -1)
    curses.init_pair(7, curses.COLOR_WHITE, -1)
    
    # Configure screen
    curses.curs_set(0)  # Hide cursor
    stdscr.nodelay(1)   # Non-blocking input
    stdscr.timeout(100) # Refresh timeout
    
    monitor = NetworkMonitor()
    
    while True:
        # Check for quit command
        try:
            key = stdscr.getch()
            if key == ord('q') or key == ord('Q'):
                break
        except:
            pass
        
        # Update network stats
        monitor.get_network_stats()
        
        # Calculate how many processes we can display based on terminal height
        # Layout: 7 lines for header + footer space (3-4 lines) = ~10 lines overhead
        height, width = stdscr.getmaxyx()
        max_processes = max(5, height - 10)  # At least 5, but scale with terminal size
        
        top_processes = monitor.get_top_processes(max_processes)
        
        # Clear screen
        stdscr.clear()
        
        # Draw header
        title = f"Network Process Monitor - Top {len(top_processes)} Processes by Data Sent"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            stdscr.addstr(0, 0, "=" * min(width - 1, 120), curses.A_BOLD)
            stdscr.addstr(1, 0, title[:width - 1], curses.A_BOLD | curses.A_UNDERLINE)
            stdscr.addstr(2, 0, f"Time: {timestamp}  |  Press 'q' to quit", curses.A_DIM)
            stdscr.addstr(3, 0, "=" * min(width - 1, 120), curses.A_BOLD)
            
            # Column headers
            header = f"{'Rank':<6} {'PID':<8} {'Process Name':<25} {'Path':<40} {'Data Sent':<15}"
            stdscr.addstr(5, 0, header[:width - 1], curses.A_BOLD)
            stdscr.addstr(6, 0, "-" * min(width - 1, 120))
            
            # Get max bytes for color scaling
            max_bytes = max([data['bytes'] for _, data in top_processes], default=1)
            
            # Display top processes
            for idx, (pid, data) in enumerate(top_processes):
                if 7 + idx >= height - 1:
                    break
                
                rank = f"#{idx + 1}"
                name = data['name'][:23]
                path = data['path'][:38] if data['path'] else '[unknown]'
                bytes_str = monitor.format_bytes(data['bytes'])
                
                # Get color based on traffic
                color = monitor.get_color_for_bytes(data['bytes'], max_bytes)
                
                # Display line with colored process name
                line = f"{rank:<6} {pid:<8} "
                stdscr.addstr(7 + idx, 0, line)
                stdscr.addstr(7 + idx, len(line), f"{name:<25}", curses.color_pair(color) | curses.A_BOLD)
                
                # Add path and data sent
                path_start = len(line) + 25
                if path_start + len(path) < width - 1:
                    stdscr.addstr(7 + idx, path_start, f"{path:<40}")
                    data_start = path_start + 40
                    if data_start < width - 1:
                        stdscr.addstr(7 + idx, data_start, f" {bytes_str}")
            
            # Draw footer
            if height > 20:
                footer_line = height - 3
                stdscr.addstr(footer_line, 0, "=" * min(width - 1, 120), curses.A_DIM)
                stdscr.addstr(footer_line + 1, 0, 
                            f"Color intensity indicates data volume (brighter = more data) | Showing {len(top_processes)} of {len(monitor.process_data)} active processes", 
                            curses.A_DIM)
            
        except curses.error:
            # Handle terminal size issues gracefully
            pass
        
        # Refresh screen
        stdscr.refresh()
        
        # Sleep for update interval
        time.sleep(monitor.update_interval)

if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
