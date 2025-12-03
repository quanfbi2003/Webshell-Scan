#!/bin/bash

# Directory to monitor for incoming backup files
WATCH_DIR="/home/sysadmin/backups"

# Base directory where files will be extracted
EXTRACT_BASE="/home/sysadmin/webshell-scan/source"

# Path to the webshell scanning tool
SCAN_TOOL="/home/sysadmin/webshell-scan/webshell-scan"

# Log file for the entire process
LOG_FILE="/home/sysadmin/webshell-scan/logs/webshell-scan-cron.log"

# Simple database (text file) to track already processed files
PROCESSED_DB="/home/sysadmin/webshell-scan/.processed_files.db"

# Create required directories and database file if they don't exist
mkdir -p "$EXTRACT_BASE/tmp" "$(dirname "$PROCESSED_DB")" "$(dirname "$LOG_FILE")"
touch "$PROCESSED_DB"

# Function: check if a file has already been processed
is_processed() {
    local file_path="$1"
    [ -f "$PROCESSED_DB" ] && grep -Fxq "$file_path" "$PROCESSED_DB"
}

# Function: mark a file as processed
mark_processed() {
    local file_path="$1"
    echo "$file_path" >> "$PROCESSED_DB"
}

# Function: log message with timestamp
log_message() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" >> "$LOG_FILE"
}

# Check if watch directory exists
if [ ! -d "$WATCH_DIR" ]; then
    log_message "ERROR: Watch directory does not exist: $WATCH_DIR"
    exit 1
fi

# Check if scan tool exists and is executable
if [ ! -x "$SCAN_TOOL" ]; then
    log_message "ERROR: Scan tool not found or not executable: $SCAN_TOOL"
    exit 1
fi

log_message "Starting monitor script - watching directory: $WATCH_DIR"

# Find all .tar.gz and .tgz files in the watch directory (sorted for consistent order)
# Use process substitution to avoid subshell issues
found_files=0
while IFS= read -r tarfile; do
    # Skip if this file was already processed
    if is_processed "$tarfile"; then
        log_message "Skipping already processed file: $tarfile"
        continue
    fi

    found_files=$((found_files + 1))
    filename=$(basename "$tarfile")
    log_message "New file detected: $tarfile"

    # Create a unique temporary extraction directory (using timestamp + random number)
    # Use a more portable method for generating unique directory name
    timestamp=$(date +%s)
    random_suffix=$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')
    extract_dir="$EXTRACT_BASE/tmp/$(basename "$filename" .tar.gz | sed 's/\.tgz$//')_${timestamp}_${random_suffix}"

    mkdir -p "$extract_dir"
    if [ $? -ne 0 ]; then
        log_message "ERROR: Failed to create extraction directory: $extract_dir"
        mark_processed "$tarfile"
        continue
    fi

    # Extract the archive (strip the first directory level)
    log_message "Extracting $tarfile to $extract_dir"
    if tar -xzf "$tarfile" -C "$extract_dir" --strip-components=1 2>>"$LOG_FILE"; then
        log_message "Extraction successful → $extract_dir"

        # Run webshell scan if the tool is executable
        log_message "Starting webshell scan on $extract_dir"
        scan_exit_code=0
        if sudo "$SCAN_TOOL" -p "$extract_dir" >>"$LOG_FILE" 2>&1; then
            scan_exit_code=$?
            log_message "Scan completed successfully (exit code: $scan_exit_code)"
        else
            scan_exit_code=$?
            log_message "Scan completed with errors (exit code: $scan_exit_code)"
        fi

        # Clean up temporary extraction directory
        if [ -d "$extract_dir" ]; then
            rm -rf "$extract_dir"
            log_message "Temporary directory removed: $extract_dir"
        fi

        # Mark file as successfully processed
        mark_processed "$tarfile"
        log_message "File marked as processed: $tarfile"

        # Optional: delete the original .tar.gz after successful processing
        # if [ $scan_exit_code -eq 0 ]; then
        #     rm -f "$tarfile"
        #     log_message "Original file deleted: $tarfile"
        # fi
    else
        log_message "ERROR: Failed to extract $tarfile"
        if [ -d "$extract_dir" ]; then
            rm -rf "$extract_dir"
        fi
        # Still mark as processed to prevent infinite retry
        mark_processed "$tarfile"
    fi
done < <(find "$WATCH_DIR" -type f \( -name "*.tar.gz" -o -name "*.tgz" \) 2>/dev/null | sort)

if [ $found_files -eq 0 ]; then
    log_message "No new files found to process"
else
    log_message "Processing completed. Total files processed: $found_files"
fi

log_message "Monitor script finished"

