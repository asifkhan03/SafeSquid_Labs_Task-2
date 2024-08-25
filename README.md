# SafeSquid_Labs_Task-2
For Task-2 (security_audit_and_hardening)
This repository contains a script to automate security audits and server hardening on Linux servers. The script covers various aspects such as user and group audits, file permissions, running services, firewall status, network configuration, and more. It also provides mechanisms to add custom security checks tailored to specific organizational needs.


## Prerequisites
- Linux Operating System
- Bash Shell
- Required Utilities: `netstat`, `find`, `awk`, `ufw`, `iptables`, `apt-get`


## Note

1. **Log File**: The script logs all output to a file named /var/log/security_audit_$DATE.log. Ensure that the directory exists and is writable by the user executing the script.
2. **Custom Checks**: You can extend the script functionality by adding custom security checks via a configuration file named security_config.conf. This file can include additional security checks tailored to specific requirements.
3. **Root Privileges**: The script must be run as root to perform certain checks and apply hardening measures.


## Instructions to perform the task:

- **Save the script above as 'security_audit_and_hardening.sh'**
Run the following command to make the script executable
         chmod +x security_audit_and_hardening.sh

- **Run the script:**
For the full dashboard with automatic refresh
  sudo ./security_audit_and_hardening.

## Custom Security Checks
To add custom security checks, create a **security_config.conf** file in the same directory as the script. 
Define your custom checks as functions within this file. 
The script will automatically source and execute them.


##Reporting
The script generates a log file for each execution, located in /var/log/ with a timestamp. Review these logs for detailed output and any identified security issues.


