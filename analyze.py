#!/usr/bin/env python3

import os
import glob
import argparse
from openai import OpenAI
from dotenv import load_dotenv

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

def chunk_content(content, max_chunk_size=4000):
    return [content[i:i+max_chunk_size] for i in range(0, len(content), max_chunk_size)]

def analyze_with_openai(content, severity_level="informational"):
    severity_levels = {"informational": 1, "warning": 2, "critical": 3}
    min_severity = severity_levels[severity_level.lower()]

    prompt = f"""
    You are an incident response investigator analyzing system logs for anomalous activity. 
    Please review the following log data and identify any suspicious activities. For each finding, 
    ensure you include the following details:

    1. **Timestamp**: The exact time the activity occurred.
    2. **Log Source**: Specify where the suspicious activity was found (e.g., which log file).
    3. **Host**: Identify the host from which the log data was collected.
    4. **Suspicious Activity Categories**:
       - Usernames that don't meet standard conventions
       - Activities performed by different IP addresses as root or admin
       - Failed login attempts that might indicate brute force attacks
           - *Note*: Failed login attempts should be downgraded to a low severity unless there is a successful login after 10 or more unsuccessful attempts. In that case, the severity should be marked as **Critical**.
       - Successful logins after multiple failed attempts
       - Unusual process executions or system modifications
       - Unexpected network connections or data transfers
       - Changes to critical system files or configurations
       - Evidence of privilege escalation
       - Unusual cron jobs or scheduled tasks
       - Signs of malware or unauthorized software installation
    5. **Severity Level**: Assign a severity level (Informational, Warning, Critical) to each finding. Only include findings that match or exceed the severity level of "{severity_level}".
    6. **Actionable Recommendations**: Provide specific recommendations for follow-up actions.

    Please provide a concise analysis of any suspicious findings, including specific log entries 
    and your reasoning for flagging them as potentially malicious. Only include findings with a severity level 
    of {severity_level} or higher. If no suspicious activity meeting this criteria is detected, 
    state "No suspicious activity detected at the {severity_level} level or above in this chunk."

    Log data:
    """

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in incident response and log analysis."},
                {"role": "user", "content": prompt + content}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error in OpenAI API call: {e}"

def main():
    parser = argparse.ArgumentParser(description="Analyze log files for suspicious activity.")
    parser.add_argument("-level", choices=["informational", "warning", "critical"],
                        default="informational", help="Minimum severity level to report")
    args = parser.parse_args()

    log_files = glob.glob('**/forensics.out', recursive=True) + \
                glob.glob('**/journalctl.out', recursive=True) + \
                glob.glob('**/new_files.out', recursive=True)

    for log_file in log_files:
        print(f"Analyzing {log_file}...")
        content = read_file(log_file)
        if content:
            chunks = chunk_content(content)
            print(f"File split into {len(chunks)} chunks.")
            all_analyses = []
            for i, chunk in enumerate(chunks):
                print(f"Analyzing chunk {i+1}/{len(chunks)}...")
                analysis = analyze_with_openai(chunk, args.level)
                if "No suspicious activity detected" not in analysis:
                    all_analyses.append(analysis)
                print(f"Analysis for chunk {i+1}:")
                print(analysis)
                print("\n" + "="*50 + "\n")
            
            if all_analyses:
                # Summarize all analyses
                summary_prompt = f"Summarize the following analyses of log file chunks, highlighting the most important findings (severity level: {args.level} and above):"
                summary = analyze_with_openai(summary_prompt + "\n\n".join(all_analyses), args.level)
                print(f"\nOverall summary for {log_file}:")
                print(summary)
            else:
                print(f"\nNo suspicious activity detected at the {args.level} level or above in {log_file}")
            print("\n" + "="*50 + "\n")

if __name__ == "__main__":
    main()
