#!/bin/sh

# Your admin email and details
ADMIN_EMAIL="admin@example.com"
HOSTNAME=$(hostname)
DATE=$(date)

# Suspicious paths commonly associated with BRICKSTORM copies
SUSPICIOUS_PATHS="/etc/sysconfig /opt/vmware/sbin /opt/vmware/bin /usr/lib/vmware"

# Get current PATH (from cron environment; may be limited, but checks what processes would inherit)
CURRENT_PATH=$(echo $PATH)

# Check if any suspicious path is in PATH
echo "$CURRENT_PATH" | grep -E "$(echo $SUSPICIOUS_PATHS | tr ' ' '|')" > /dev/null
if [ $? -eq 0 ]; then
    # Suspicious PATH found – collect details
    ALERT_BODY="BRICKSTORM Indicator Detected on $HOSTNAME at $DATE

Current PATH: $CURRENT_PATH

Suspicious directories found in PATH. This may indicate PATH hijacking by BRICKSTORM.

Recommended actions:
- Inspect files in the suspicious directories (e.g., ls -l /opt/vmware/sbin/)
- Compare against known BRICKSTORM IOCs from CISA MAR.
- Consider isolating the host and forensic analysis."

    # Send email via netcat to an internal SMTP relay (replace with your SMTP server IP/port)
    SMTP_SERVER="192.168.1.10"  # Your internal SMTP server (must allow relay from ESXi IP)
    SMTP_PORT=25
    FROM="esxi-alert@$HOSTNAME"
    TO="$ADMIN_EMAIL"

    echo -e "EHLO $HOSTNAME\r\nMAIL FROM:<$FROM>\r\nRCPT TO:<$TO>\r\nDATA\r\nSubject: BRICKSTORM PATH Alert on $HOSTNAME\r\nFrom: $FROM\r\nTo: $TO\r\n\r\n$ALERT_BODY\r\n.\r\nQUIT\r\n" | nc $SMTP_SERVER $SMTP_PORT
fi
