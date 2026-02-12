# NetInspect 
A lightweight real-time network monitoring CLI tool for Linux. Tracks processes by current network transfer rate and cumulative data usage with color-coded displays.

## Features
- Real-Time Tracking: Monitors all network adapters with 1-second refresh.
- Dual Metrics: Shows both current transfer rate (KB/s, MB/s) and total cumulative data.
- Adapter Detection: Displays which network interface each process is using.
- Color-Coded: Process names highlighted by transfer rate (brighter = faster).
- Dynamic Layout: Automatically scales to fit your terminal height.

## Installation
Install the required dependency:
```bash
pip install psutil #(only use the flag "--break-system-packages" if needed and you know what you are doing)
```

## Usage
Run with sudo for full process monitoring:
```bash
sudo python3 netinspect.py
```
Press `q` to quit.

## Sample Output
```
==================================================================================================================================
Netinspect - Top 15 Processes by Current Transfer Rate
Time: 2026-02-12 20:41:37  |  Press 'q' to quit
==================================================================================================================================

Rank   PID      Process Name      Adapter      Path                         Current Rate   Total Data  
----------------------------------------------------------------------------------------------------------------------------------
#1     1234     chrome            wlan0        /usr/bin/google-chrome       2.45 MB/s      487.32 MB
#2     5678     firefox           eth0         /usr/bin/firefox             1.23 MB/s      156.78 MB
#3     9012     python3           wlan0        /usr/bin/python3             456.78 KB/s    23.45 MB
#4     3456     spotify           wlan0        /usr/bin/spotify             128.34 KB/s    89.12 MB
#5     7890     slack             eth0         /usr/bin/slack               64.12 KB/s     12.34 MB

==================================================================================================================================
Color intensity indicates transfer rate (brighter = faster) | Showing 15 of 89 active processes
```

## Display Columns
- **Rank** - Position sorted by current transfer rate
- **PID** - Process ID
- **Process Name** - Executable name (color-coded by current rate)
- **Adapter** - Network interface (eth0, wlan0, etc.)
- **Path** - Full path to process binary
- **Current Rate** - Live bandwidth usage per second
- **Total Data** - Cumulative data sent since monitoring started 

Colors scale relative to the current highest transfer rate.

## Requirements
- Python 3.6 or higher
- Linux
- Root/sudo access (can run without, but then won't be able to see all processes)
