# Forensic Data Collection and Analysis Tool

This project consists of two main scripts: `forensics.py` for data collection and `analyze.py` for data analysis. These tools are designed to assist in cybersecurity incident response and forensic investigations.

## forensics.py

### Purpose
`forensics.py` is a remote forensic data collection tool that gathers system information, logs, and other relevant data from one or multiple remote hosts.

### Features
- Collects a wide range of system information and logs
- Supports both single-host and multi-host collection
- Handles different system configurations (e.g., iptables vs. nftables, journalctl vs. traditional syslog)
- Creates separate output files for different types of collected data
- Generates SHA256 hashes for all collected files
- Archives all collected data into a single compressed file

### How It Works
- **Host Selection**: Can target a single host or read multiple hosts from a file
- **Data Collection**: Executes a series of commands on the remote host(s) to gather forensic data
- **File Generation**: Creates separate output files for different types of data (e.g., system info, new files, firewall rules, logs)
- **Hashing**: Generates SHA256 hashes for all collected files to ensure integrity
- **Archiving**: Compresses all collected data into a single tar.gz file for easy transfer and storage

### Usage
1. **Single Host Without Password**:
   ```
   ./forensics.py <remote_ip_or_hostname>
   ```

2. **Single Host With Password**:
   ```
   ./forensics.py <remote_ip_or_hostname> <ssh_password>
   ```

3. **Multiple Hosts Without Password**:
   ```
   ./forensics.py -hosts <hosts_file>
   ```

4. **Multiple Hosts With Password**:
   ```
   ./forensics.py -hosts <hosts_file> <ssh_password>
   ```

## analyze.py

### Purpose
`analyze.py` is an AI-powered log analysis tool that processes the data collected by `forensics.py` to identify suspicious activities and potential security threats.

### Features
- Analyzes various types of log files and system data
- Uses OpenAI's GPT-4 model for intelligent analysis
- Supports filtering of time-based logs to focus on recent events
- Allows setting of minimum severity level for reported findings
- Provides detailed, context-aware analysis for different types of log files

### How It Works
- **File Discovery**: Automatically finds all relevant log files in the current directory and subdirectories
- **Content Chunking**: Splits large log files into manageable chunks for analysis
- **AI Analysis**: Utilizes OpenAI's GPT-4 to analyze each chunk of data
- **Contextual Analysis**: Applies specific analysis criteria based on the type of log file
- **Severity Filtering**: Reports only findings that meet or exceed the specified severity level

### Usage
```
analyze.py [-level {informational,warning,critical}] [-days DAYS]
```

- `-level`: Set the minimum severity level to report (default: informational)
- `-days`: Number of days to analyze for time-based logs (0 to analyze all data, default: all data)

### Example

```
analyze.py <recursively reads dir>
