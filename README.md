# NetInspect
A lightweight real-time network monitoring CLI tool for Linux. Tracks processes by network traffic with color-coded displays that adapt to your terminal size.

## Features
- Real-Time Tracking: Monitors all network adapters with 1-second refresh.
- Color-Coded: Process names highlighted by traffic volume (brighter = more data).
- Dynamic Layout: Automatically scales to fit your terminal height.
- Process Info: Shows PID, name, executable path, and data sent.

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
===============================================================================
Network Process Monitor - Top 15 Processes by Data Sent
Time: 2026-02-11 14:23:45  |  Press 'q' to quit
===============================================================================

Rank   PID      Process Name              Path                                     Data Sent      
--------------------------------------------------------------------------------------------------------
#1     1234     chrome                    /usr/bin/google-chrome                   145.23 MB
#2     5678     firefox                   /usr/bin/firefox                         89.47 MB
#3     9012     python3                   /usr/bin/python3                         12.34 MB
```

## Color Scale
- 🔵 Blue → Minimal (0-5%)
- 🔷 Cyan → Low (5-10%)
- 🟢 Green → Moderate-low (10-20%)
- 🟡 Yellow → Moderate (20-40%)
- 🟣 Magenta → Moderate-high (40-60%)
- 🔴 Red → High (60-80%)
- ⚪ White → Maximum (80-100%)

Colors scale relative to the highest traffic process.

## Requirements
- Python 3.6 or higher
- Linux
- Root/sudo access (can run without, but then wont be able to see all processes)
