"""
SSH Honeypot Configuration for Cryptic Vault.

This module contains all configuration constants and settings for the SSH honeypot server.
Values can be overridden using environment variables.
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# SSH Server Configuration
SSH_HOST = os.getenv('SSH_HOST', '0.0.0.0')
SSH_PORT = int(os.getenv('SSH_PORT', '2222'))
SSH_BANNER = 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5'
SYSTEM_HOSTNAME = 'cryptic-vault-server'
SYSTEM_USERNAME = 'root'

# API Configuration - REMOVED: No longer using Gemini API
# GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
# if not GEMINI_API_KEY:
#     raise ValueError("GEMINI_API_KEY environment variable is required")

# Rate Limiting
MAX_CONNECTIONS_PER_IP = 3
CONNECTION_TIMEOUT = 300  # 5 minutes in seconds
COMMAND_TIMEOUT = 30     # 30 seconds for command execution

# Simulated System Information
SYSTEM_INFO = {
    'os_release': 'Ubuntu 20.04.5 LTS',
    'kernel': '5.4.0-135-generic',
    'arch': 'x86_64',
    'hostname': SYSTEM_HOSTNAME,
    'ip_address': '10.40.38.153',
}

# SSH Key Settings
SSH_KEY_FILE = os.path.join(os.path.dirname(__file__), 'ssh_host_key')
SSH_KEY_TYPE = 'rsa'
SSH_KEY_BITS = 2048

# Logging Configuration
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

# Database Configuration
DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'honeypot_logs.db')