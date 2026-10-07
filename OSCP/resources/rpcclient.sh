#!/bin/bash

# ------------ Configuration ------------
DOMAIN=""
USERNAME=""
PASSWORD=""
TARGETS=("x.x.x.x")  # Add more IPs/hostnames here
# --------------------------------------

for TARGET in "${TARGETS[@]}"; do
    echo -e "\n Enumerating users on $TARGET"
    
    # Get raw user lines
    RAW_USERS=$(rpcclient -U "${DOMAIN}\\${USERNAME}%${PASSWORD}" "$TARGET" -c "enumdomusers" 2>/dev/null)

    # Extract RIDs and Usernames
    echo "$RAW_USERS" | grep 'user:' | while read -r line; do
        USER=$(echo "$line" | cut -d '[' -f2 | cut -d ']' -f1)
        RID=$(echo "$line" | grep -oP 'rid:\[\K[^]]+')

        echo -e "\n[*] Querying user: $USER (RID: $RID)"
        rpcclient -U "${DOMAIN}\\${USERNAME}%${PASSWORD}" "$TARGET" -c "queryuser $RID" 2>/dev/null
    done
done
