# Cryptic Vault SSH Honeypot

An SSH honeypot that uses Google's Gemini API to create a realistic interactive terminal environment for capturing and studying attacker behavior.

## Overview

The SSH honeypot component extends the Cryptic Vault dark web marketplace honeypot by simulating a fully interactive Linux terminal. When attackers connect via SSH, their commands are processed by Gemini to provide realistic responses while logging all activity.

### Key Features

- Simulates a realistic Ubuntu 20.04 environment
- Accepts any username/password combination
- Maintains persistent session state
- Logs all commands and interactions
- Rate limits connections per IP
- Integrates with existing honeypot logging
- Provides consistent filesystem and process views

## Setup

### 1. Get a Gemini API Key

1. Go to https://makersuite.google.com/
2. Sign in with your Google account
3. Go to API Keys section
4. Create a new API key
5. Copy the key for the next step

### 2. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit with your settings
nano .env

# Required: Add your Gemini API key
GEMINI_API_KEY=your_key_here

# Optional: Change default port (2222)
SSH_PORT=2222
```

### 3. Install Dependencies

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows

# Install requirements
pip install -r requirements.txt
```

## Running the Honeypot

### Standalone Mode

```bash
# Start SSH honeypot only
python run_ssh_honeypot.py
```

### With Cryptic Vault

```bash
# Run both web and SSH honeypots
docker-compose up -d
```

## Testing

To test the SSH honeypot locally:

```bash
# Connect to honeypot
ssh -p 2222 anyuser@localhost

# Enter any password (will be accepted)

# Try some commands
ls
pwd
cat /etc/passwd
ps aux
```

## Viewing Logs

### Database Access

The honeypot logs to the same SQLite database as the web honeypot:

```bash
sqlite3 database/honeypot_logs.db

# View SSH sessions
SELECT * FROM ssh_sessions;

# View commands
SELECT * FROM ssh_commands;

# View login attempts
SELECT * FROM honeypot_events WHERE event_type = 'SSH_LOGIN_ATTEMPT';
```

### Log File

Check `ssh_honeypot.log` for operational logs and errors.

## Security Considerations

1. **Isolation**: Run the honeypot in a controlled environment (container/VM)
2. **Resource Limits**: Configure rate limiting and connection timeouts
3. **Monitoring**: Regularly check logs for abuse
4. **Updates**: Keep dependencies updated for security patches
5. **Backup**: Regularly backup the honeypot logs

## Architecture

### Components

- `ssh_honeypot.py`: Main SSH server implementation
- `gemini_terminal.py`: Gemini API integration
- `system_prompt.md`: Gemini context/personality
- `honeypot_logger.py`: Logging infrastructure
- `ssh_config.py`: Configuration settings
- `run_ssh_honeypot.py`: Runner script

### Data Flow

1. Attacker connects via SSH (port 2222)
2. Any username/password accepted
3. Commands sent to Gemini API
4. Responses returned to attacker
5. All activity logged to database

## Troubleshooting

### Common Issues

1. **Connection Refused**
   - Check if service is running
   - Verify correct port (2222)
   - Check firewall settings

2. **API Errors**
   - Verify GEMINI_API_KEY in .env
   - Check API rate limits
   - Look for errors in logs

3. **Database Errors**
   - Check file permissions
   - Verify SQLite is working
   - Check disk space

### Getting Help

1. Check ssh_honeypot.log for errors
2. Review honeypot_logs.db for issues
3. Create an issue in the repository

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes
4. Submit pull request

## License

See main project LICENSE file.

## Acknowledgments

- Google Gemini team for API access
- Paramiko SSH library
- Original Cryptic Vault team