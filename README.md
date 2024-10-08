# VirusTotal Discord Bot
# VirusTotal Discord Bot

## Overview
This is a simple, lightweight Discord bot that automatically scans URLs shared in channels using the VirusTotal HTTP-based public API. It then responds to the messages with a reply indicating vendors' flags: 'malicious', 'suspicious', 'undetected', or 'harmless'

## Prerequisites
## Prerequisites
- Python 3.5.3 or later
- Discord bot token
- VirusTotal API key

## Installation
## Installation
1. Clone the Repository
    `git clone https://github.com/Shmath64/VirusTotalDiscordBot.git` 
2. Install dependencies
    `pip install -r requirements.txt`
3. Set up environment variables
    Create a `.env` file in the root directory of the project for the Discord Bot token and teh VirusTotal API key:
    `DISCORD_TOKEN={your_discord_bot_token}`
    `VIRUSTOTAL_API_KEY={your_virustotal_api_key}`

## Usage
## Usage
1. Run the bot
    `python main.py`
2. Invite the bot to your server using the Discord Developer Portal 
    (https://discord.com/developers/applications)
3. Interact with the bot

