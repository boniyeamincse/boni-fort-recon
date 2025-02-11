#!/bin/bash

# Slack webhook URL (if configured)
SLACK_WEBHOOK=""

# Discord webhook URL (if configured)
DISCORD_WEBHOOK=""

send_notification() {
    local message="$1"
    
    # Send to Slack
    if [ ! -z "$SLACK_WEBHOOK" ]; then
        curl -s -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$message\"}" \
            "$SLACK_WEBHOOK"
    fi
    
    # Send to Discord
    if [ ! -z "$DISCORD_WEBHOOK" ]; then
        curl -s -X POST -H "Content-Type: application/json" \
            --data "{\"content\":\"$message\"}" \
            "$DISCORD_WEBHOOK"
    fi
} 