# EDR Detection Tool

This Python script checks for potential **Endpoint Detection and Response (EDR)** products on a Windows machine. It scans running processes, system directories, and Windows services for any indication of EDR software based on a list of known EDR-related strings. Inspired by [EDRenum-BOF](https://github.com/mlcsec/EDRenum-BOF?tab=readme-ov-file) and [Invoke-EDRChecker](https://github.com/PwnDexter/Invoke-EDRChecker?tab=readme-ov-file).

## Features

- **Process Scanning**: Scans all running processes to identify potential EDR software by matching process names and executable paths against a predefined list of known EDR strings.
- **Directory Scanning**: Checks common system directories (e.g., `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`) for directories that match known EDR-related strings.
- **Service Scanning**: Enumerates Windows services to detect any that are associated with EDR products based on service names and display names.

## EDR Detection List

The script checks for over 100 EDR-related strings, including well-known security products such as:
- **CrowdStrike**
- **Carbon Black**
- **Cylance**
- **SentinelOne**
- **McAfee**
- **Sophos**
- **Symantec**
- **Trend Micro**
- **Cisco AMP**
- And many more...

You can find the full list of EDR strings in the code.

## How It Works

The script uses the following methods to detect EDR software:

1. **Processes**: It iterates through all running processes and checks if any process name or executable path contains known EDR strings.
2. **Directories**: It scans common system directories for folders that might be associated with EDR products.
3. **Services**: It enumerates all Windows services to identify any services related to EDR software.

## Usage

### Prerequisites

- **Python 3.x**
- Install the required dependencies:
  ```bash
  pip install psutil pywin32
