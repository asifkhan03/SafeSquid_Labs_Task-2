#!/bin/bash

# security_audit_and_hardening.sh
# A script to automate security audits and server hardening on Linux servers.

# Variables
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_FILE="/var/log/security_audit_$DATE.log"

# Configuration file for custom checks (Optional)
CONFIG_FILE="./security_config.conf"

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Function to log messages
log_message() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a $LOG_FILE
}

# User and Group Audits
user_and_group_audit() {
    log_message "Starting user and group audits..."

    log_message "Listing all users and groups:"
    getent passwd | tee -a $LOG_FILE
    getent group | tee -a $LOG_FILE

    log_message "Checking for users with UID 0 (root privileges):"
    awk -F: '($3 == "0") {print}' /etc/passwd | tee -a $LOG_FILE

    log_message "Identifying users without passwords or with weak passwords:"
    awk -F: '($2 == "" || length($2) < 6) {print $1}' /etc/shadow | tee -a $LOG_FILE
}

# File and Directory Permissions Audit
file_permissions_audit() {
    log_message "Starting file and directory permissions audit..."

    log_message "Scanning for world-writable files and directories:"
    find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print | tee -a $LOG_FILE
    find / -xdev -type f -perm -0002 -print | tee -a $LOG_FILE

    log_message "Checking .ssh directories for secure permissions:"
    find /home -type d -name ".ssh" -exec chmod 700 {} \; -exec chown $(stat -c "%U:%G" {}) {} \; | tee -a $LOG_FILE

    log_message "Reporting files with SUID/SGID bits set:"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -ld {} \; | tee -a $LOG_FILE
}

# Service Audits
service_audit() {
    log_message "Starting service audit..."

    log_message "Listing all running services:"
    systemctl list-units --type=service | tee -a $LOG_FILE

    log_message "Checking for unnecessary or unauthorized services:"
    # List critical services that should be running
    critical_services=("sshd" "iptables" "ufw")
    for service in "${critical_services[@]}"; do
        systemctl is-active --quiet $service
        if [ $? -ne 0 ]; then
            log_message "Service $service is not running"
        fi
    done

    log_message "Checking for services listening on non-standard or insecure ports:"
    netstat -tuln | grep -E ":22|:80|:443|:3306" | tee -a $LOG_FILE
}

# Firewall and Network Security Checks
firewall_and_network_security() {
    log_message "Starting firewall and network security checks..."

    log_message "Verifying that a firewall is active:"
    ufw status | grep -qw active && log_message "UFW is active" || log_message "UFW is not active"
    iptables -L | tee -a $LOG_FILE

    log_message "Listing open ports and their associated services:"
    netstat -tulnp | tee -a $LOG_FILE

    log_message "Checking for IP forwarding settings:"
    sysctl net.ipv4.ip_forward | tee -a $LOG_FILE
}

# IP and Network Configuration Checks
ip_network_config_check() {
    log_message "Starting IP and network configuration checks..."

    log_message "Identifying public and private IP addresses:"
    ip addr | grep 'inet ' | grep -v '127.0.0.1' | tee -a $LOG_FILE
}

# Security Updates and Patching
security_updates_check() {
    log_message "Checking for available security updates..."

    apt-get update -y
    apt-get upgrade -s | grep -i security | tee -a $LOG_FILE
}

# Log Monitoring
log_monitoring() {
    log_message "Checking for recent suspicious log entries..."

    log_message "Checking auth.log for failed SSH login attempts:"
    grep "Failed password" /var/log/auth.log | tail -n 10 | tee -a $LOG_FILE
}

# Server Hardening Steps

# SSH Configuration Hardening
ssh_hardening() {
    log_message "Starting SSH configuration hardening..."

    sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
    log_message "SSH hardening completed."
}

# Disable IPv6 if not required
disable_ipv6() {
    log_message "Disabling IPv6 if not required..."

    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    log_message "IPv6 has been disabled."
}

# Secure BootLoader
secure_bootloader() {
    log_message "Securing the GRUB bootloader..."

    echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
    echo "password_pbkdf2 root $(grub-mkpasswd-pbkdf2 | grep "grub.pbkdf2" | awk '{print $7}')" >> /etc/grub.d/40_custom
    update-grub
    log_message "GRUB bootloader has been secured."
}

# Enable Automatic Security Updates
enable_automatic_updates() {
    log_message "Enabling automatic security updates..."

    apt-get install -y unattended-upgrades
    dpkg-reconfigure -plow unattended-upgrades
    log_message "Automatic security updates have been enabled."
}

# Custom Security Checks (optional)
custom_security_checks() {
    if [ -f "$CONFIG_FILE" ]; then
        log_message "Executing custom security checks from $CONFIG_FILE..."
        source $CONFIG_FILE
    else
        log_message "No custom security checks defined."
    fi
}

# Main Function
main() {
    log_message "Security audit and hardening script started."

    user_and_group_audit
    file_permissions_audit
    service_audit
    firewall_and_network_security
    ip_network_config_check
    security_updates_check
    log_monitoring
    ssh_hardening
    disable_ipv6
    secure_bootloader
    enable_automatic_updates
    custom_security_checks

    log_message "Security audit and hardening script completed."
}

main
