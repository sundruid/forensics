#!/usr/bin/env python3

import os
import glob
import argparse
from openai import OpenAI
from dotenv import load_dotenv
import datetime
import re
from collections import defaultdict
import sys
import io

# Load environment variables
load_dotenv(os.path.expanduser('~/.env'))

# Set up OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def read_file(filename):
    try:
        with open(filename, 'r') as file:
            return file.read()
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        return ""

def chunk_content(content, max_chunk_size=32000):
    return [content[i:i+max_chunk_size] for i in range(0, len(content), max_chunk_size)]

def analyze_with_openai(content, severity_level="informational", log_file=""):
    severity_levels = {"informational": 1, "warning": 2, "critical": 3}
    min_severity = severity_levels[severity_level.lower()]

    prompt = f"""
    You are an incident response investigator analyzing system logs for anomalous activity. 
    Please review the following log data and identify any suspicious activities. Keep in mind:

    1. Normal system activities:
       - Package updates and installations via apt-get or similar package managers are common and generally not suspicious.
       - System file changes due to updates are normal.
       - Regular cron jobs and scheduled tasks are expected.

    2. Focus on:
       - Files or activities that are out of place or in unexpected locations.
       - Errors when trying to run programs or scripts, especially if they involve sensitive system areas.
       - Signs of potential hacker behavior, such as:
         * Unusual network connections or data transfers.
         * Unexpected privilege escalations.
         * Modifications to critical system files not associated with updates.
         * Creation of new user accounts or changes to existing account permissions.
         * Unusual process executions, especially with elevated privileges.

    For each suspicious finding, provide only the following details:

    1. **Timestamp**: The exact time the activity occurred.
    2. **Log Source**: Specify where the suspicious activity was found (e.g., which log file).
    3. **Host**: Identify the host from which the log data was collected.
    4. **Suspicious Activity**: A brief description of the suspicious activity and why it's concerning.
    5. **Severity Level**: Assign a severity level (Informational, Warning, Critical) to each finding. Only include findings that match or exceed the severity level of "{severity_level}".

    Please provide a concise list of findings, including specific log entries. Only include findings with a severity level 
    of {severity_level} or higher. If no suspicious activity meeting this criteria is detected, 
    state "No suspicious activity detected at the {severity_level} level or above in this chunk."

    Log data:
    """

    if "new_files.out" in log_file:
        prompt += """
    For new_files.out:
    - Focus on files that appear suspicious or out of place.
    - Pay special attention to any unexpected files added to the /home directory and its subdirectories.
    - Be aware that new files in system directories may be due to package updates and are not necessarily suspicious.
    - Look for files with unusual names, unexpected locations, or suspicious file types.
    - Consider the context of when and where these files were added.
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in incident response and log analysis."},
                {"role": "user", "content": prompt + content}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error in OpenAI API call: {e}"

def filter_journalctl_by_days(content, days):
    if days is None:
        return content

    cutoff_date = datetime.datetime.now() - datetime.timedelta(days=days)
    filtered_lines = []
    current_date = None

    for line in content.split('\n'):
        try:
            # Attempt to parse the line as a date
            current_date = datetime.datetime.strptime(line.strip(), '%Y-%m-%d %H:%M:%S.%f')
            if current_date >= cutoff_date:
                filtered_lines.append(line)
        except ValueError:
            # If it's not a date, include the line if we're within the date range
            if current_date is None or current_date >= cutoff_date:
                filtered_lines.append(line)

    return '\n'.join(filtered_lines)

def extract_findings(full_analysis):
    findings = defaultdict(list)
    current_file = None
    severity_pattern = re.compile(r'Severity Level:\s*(Informational|Warning|Critical)', re.IGNORECASE)
    timestamp_pattern = re.compile(r'\b\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\b')

    for line in full_analysis.split('\n'):
        if line.startswith("Analyzing "):
            current_file = line.split("Analyzing ")[1].strip('...')
        elif "Severity Level:" in line:
            severity_match = severity_pattern.search(line)
            if severity_match:
                severity = severity_match.group(1)
                timestamp_match = timestamp_pattern.search(line)
                timestamp = timestamp_match.group(0) if timestamp_match else "N/A"
                finding = line.split("Severity Level:")[0].strip()
                findings[current_file].append((timestamp, severity, finding))

    return findings

class TeeStream:
    def __init__(self, stdout, file):
        self.stdout = stdout
        self.file = file

    def write(self, message):
        self.stdout.write(message)
        self.file.write(message)
        self.flush()

    def flush(self):
        self.stdout.flush()
        self.file.flush()

def main():
    parser = argparse.ArgumentParser(description="Analyze log files for suspicious activity.")
    parser.add_argument("-level", choices=["informational", "warning", "critical"],
                        default="informational", help="Minimum severity level to report")
    parser.add_argument("-days", type=int, help="Number of days to analyze for journalctl.out (0 to skip, default: all data)")
    args = parser.parse_args()

    log_files = glob.glob('**/forensics.out', recursive=True) + \
                glob.glob('**/new_files.out', recursive=True)

    if args.days != 0:
        log_files += glob.glob('**/journalctl.out', recursive=True)

    for log_file in log_files:
        print(f"Analyzing {log_file}...")
        content = read_file(log_file)
        if content:
            if 'journalctl.out' in log_file and args.days is not None and args.days > 0:
                content = filter_journalctl_by_days(content, args.days)
                print(f"Filtered journalctl.out to last {args.days} days")
            
            chunks = chunk_content(content)
            print(f"File split into {len(chunks)} chunks.")
            for i, chunk in enumerate(chunks):
                print(f"Analyzing chunk {i+1}/{len(chunks)}...")
                analysis = analyze_with_openai(chunk, args.level, log_file)
                if "No suspicious activity detected" not in analysis:
                    print(f"Findings in chunk {i+1}:")
                    print(analysis)
                    print("\n" + "="*50 + "\n")
                else:
                    print(f"No suspicious activity detected in chunk {i+1}")
            
            print("\n" + "="*50 + "\n")

    print("\nAnalysis complete.")

if __name__ == "__main__":
    main()
