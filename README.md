## How It Works:

- **Hosts File**: If the `-hosts` option is used, the script reads the list of IP addresses or hostnames from the specified file.
- **Directory Creation**: For each host, a directory with the hostname is created, and all forensic data for that host is stored in that directory.
- **Passwordless `sudo` Check**: The script attempts to run without a password, but if `sudo` requires a password, it prompts the user to rerun the script with the password.
- **Iterative Data Collection**: The script iteratively collects forensic data from each host listed in the file and stores the results in separate directories.


## Usage Examples:

1. **Single Host Without Password**:
   `./forensics_collector.py <remote_ip_or_hostname>`

2. **Single Host With Password**:
   `./forensics_collector.py <remote_ip_or_hostname> <ssh_password>`

3. **Multiple Hosts Without Password**:
   `./forensics_collector.py -hosts <hosts_file>`

4. **Multiple Hosts With Password**:
   `./forensics_collector.py -hosts <hosts_file> <ssh_password>`

5. **Analyze.py can use OpenAI to do forensics on collected data**:
   `analyze.py <recursively reads dir>`
