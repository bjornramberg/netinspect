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
        self.process_data = defaultdict(lambda: {'rate': 0, 'total_bytes': 0, 'name': '', 'path': '', 'adapter': '', 'last_seen': time.time()})
        self.last_net_io = {}
        self.update_interval = 1.0  # seconds
        self.interface_map = {}  # Map IPs to interfaces
        
    def update_interface_map(self):
        """Build a map of IP addresses to network interfaces"""
        self.interface_map = {}
        try:
            addrs = psutil.net_if_addrs()
            for interface, addr_list in addrs.items():
                for addr in addr_list:
                    if addr.family == 2:  # AF_INET (IPv4)
                        self.interface_map[addr.address] = interface
        except Exception:
            pass
    
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
        
        # Update interface map periodically
        if not hasattr(self, '_last_interface_update') or current_time - self._last_interface_update > 5:
            self.update_interface_map()
            self._last_interface_update = current_time
        
        # Get current network IO counters and connections
        current_net_io = {}
        process_adapters = {}
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                io = proc.io_counters()
                exe_path = ''
                try:
                    exe_path = proc.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    exe_path = '[access denied]'
                
                # Get network connections to determine adapter
                adapter = ''
                try:
                    connections = proc.net_connections()
                    if connections:
                        # Use the first active connection's local address to determine interface
                        for conn in connections:
                            if conn.laddr:
                                local_ip = conn.laddr.ip
                                adapter = self.interface_map.get(local_ip, '')
                                if adapter:
                                    break
                        if not adapter and connections:
                            adapter = 'unknown'
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    adapter = '[denied]'
                
                current_net_io[proc.info['pid']] = {
                    'name': proc.info['name'],
                    'path': exe_path,
                    'adapter': adapter,
                    'bytes_sent': io.write_bytes,  # Using write_bytes as proxy
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Calculate deltas and rates
        for pid, data in current_net_io.items():
            if pid in self.last_net_io:
                bytes_delta = data['bytes_sent'] - self.last_net_io[pid]['bytes_sent']
                if bytes_delta > 0:
                    # Calculate rate in bytes per second
                    rate = bytes_delta / self.update_interval
                    self.process_data[pid]['rate'] = rate
                    self.process_data[pid]['total_bytes'] += bytes_delta
                    self.process_data[pid]['name'] = data['name']
                    self.process_data[pid]['path'] = data['path']
                    self.process_data[pid]['adapter'] = data['adapter']
                    self.process_data[pid]['last_seen'] = current_time
                else:
                    # No new data, decay the rate but keep cumulative
                    self.process_data[pid]['rate'] = 0
                    self.process_data[pid]['last_seen'] = current_time
            else:
                self.process_data[pid]['name'] = data['name']
                self.process_data[pid]['path'] = data['path']
                self.process_data[pid]['adapter'] = data['adapter']
                self.process_data[pid]['last_seen'] = current_time
        
        self.last_net_io = current_net_io
        
        # Clean up old processes (not seen in last 30 seconds and no activity)
        pids_to_remove = [pid for pid, data in self.process_data.items() 
                         if current_time - data['last_seen'] > 30 and data['rate'] == 0]
        for pid in pids_to_remove:
            del self.process_data[pid]
    
    def get_top_processes(self, n=10):
        """Get top N processes by current transfer rate"""
        sorted_procs = sorted(
            [(pid, data) for pid, data in self.process_data.items()],
            key=lambda x: x[1]['rate'],
            reverse=True
        )
        return sorted_procs[:n]
    
    def get_color_for_rate(self, rate, max_rate):
        """Get color pair number based on transfer rate"""
        if max_rate == 0:
            return 1
        
        ratio = rate / max_rate
        
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
    
    def format_rate(self, bytes_per_sec):
        """Format transfer rate to human readable format"""
        for unit in ['B/s', 'KB/s', 'MB/s', 'GB/s']:
            if bytes_per_sec < 1024.0:
                return f"{bytes_per_sec:.2f} {unit}"
            bytes_per_sec /= 1024.0
        return f"{bytes_per_sec:.2f} TB/s"

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
        title = f"Netinspect - Top {len(top_processes)} Processes by Current Transfer Rate"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            stdscr.addstr(0, 0, "=" * min(width - 1, 130), curses.A_BOLD)
            stdscr.addstr(1, 0, title[:width - 1], curses.A_BOLD | curses.A_UNDERLINE)
            stdscr.addstr(2, 0, f"Time: {timestamp}  |  Press 'q' to quit", curses.A_DIM)
            stdscr.addstr(3, 0, "=" * min(width - 1, 130), curses.A_BOLD)
            
            # Column headers
            header = f"{'Rank':<6} {'PID':<8} {'Process Name':<20} {'Adapter':<12} {'Path':<28} {'Current Rate':<14} {'Total Data':<12}"
            stdscr.addstr(5, 0, header[:width - 1], curses.A_BOLD)
            stdscr.addstr(6, 0, "-" * min(width - 1, 130))
            
            # Get max rate for color scaling
            max_rate = max([data['rate'] for _, data in top_processes], default=1)
            
            # Display top processes
            for idx, (pid, data) in enumerate(top_processes):
                if 7 + idx >= height - 1:
                    break
                
                rank = f"#{idx + 1}"
                name = data['name'][:20]
                adapter = data['adapter'][:12] if data['adapter'] else '[none]'
                path = data['path'][:28] if data['path'] else '[unknown]'
                rate_str = monitor.format_rate(data['rate'])[:14]
                total_str = monitor.format_bytes(data['total_bytes'])[:12]
                
                # Get color based on traffic
                color = monitor.get_color_for_rate(data['rate'], max_rate)
                
                # Build complete row as single formatted string
                full_line = f"{rank:<6} {pid:<8} {name:<20} {adapter:<12} {path:<28} {rate_str:<14} {total_str:<12}"
                
                # Write the line - we need to handle the colored name specially
                # Split into: prefix (rank+pid), name (colored), suffix (adapter+path+rate+total)
                prefix = f"{rank:<6} {pid:<8} "
                suffix = f" {adapter:<12} {path:<28} {rate_str:<14} {total_str:<12}"
                
                # Write prefix
                stdscr.addstr(7 + idx, 0, prefix)
                # Write colored name
                stdscr.addstr(7 + idx, len(prefix), f"{name:<20}", curses.color_pair(color) | curses.A_BOLD)
                # Write suffix
                stdscr.addstr(7 + idx, len(prefix) + 20, suffix[:width - len(prefix) - 20 - 1])
            
            # Draw footer
            if height > 20:
                footer_line = height - 3
                stdscr.addstr(footer_line, 0, "=" * min(width - 1, 130), curses.A_DIM)
                stdscr.addstr(footer_line + 1, 0, 
                            f"Color intensity indicates transfer rate (brighter = faster) | Showing {len(top_processes)} of {len(monitor.process_data)} active processes", 
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