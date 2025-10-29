# The Cryptic Vault - Advanced Adaptive Honeypot System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Flask-2.3.3-green)
![Docker](https://img.shields.io/badge/Docker-Required-blue)
![License](https://img.shields.io/badge/License-Research-red)

**An AI-powered, adaptive honeypot simulating a dark web marketplace for cybersecurity research**

[Features](#features) • [Architecture](#architecture) • [Installation](#installation) • [Usage](#usage) • [Research Goals](#research-goals)

</div>

---

## Overview

The Cryptic Vault is a sophisticated honeypot system designed for cybersecurity research that creates dynamic, adaptive fake environments to study malicious actor behavior. Unlike traditional static honeypots, this system analyzes attacker profiles in real-time and generates personalized convincing fake data to maximize behavioral intelligence collection.

### What Makes This Different?

- ** Dynamic Adaptation**: The system profiles each visitor and adapts its responses based on behavioral patterns
- ** AI-Powered Content**: Generates convincing fake marketplace data, vendor profiles, and transaction flows
- ** Behavioral Classification**: Automatically categorizes visitors (bots, researchers, casual browsers, serious buyers, advanced threats)
- ** Multi-Layer Traps**: Includes PGP-encrypted bait files, fake Bitcoin deposits, and realistic order fulfillment
- ** Comprehensive Logging**: Tracks every interaction for deep analysis of attacker tactics, techniques, and procedures (TTPs)

---

## Features

### Core Honeypot Capabilities

- **Realistic Dark Web Marketplace**: Full-featured marketplace UI with product listings, cart, checkout, and encrypted messaging
- **PGP Encryption Integration**: Realistic GPG key handling for "secure" communications
- **Bitcoin Testnet Lures**: Fake deposit addresses with real QR codes (uses testnet for safety)
- **Bait File Distribution**: Tracks downloads of honeypot files (e.g., "leaked databases")
- **Session Tracking**: UUID-based session monitoring across all interactions
- **User Registration & Authentication**: Captures credentials and behavioral patterns

### Intelligence Gathering

- **Event Logging**: Tracks 15+ event types (page views, logins, purchases, downloads, PGP submissions)
- **Session Analytics**: Comprehensive user journey mapping
- **Download Attribution**: Identifies who accesses bait files
- **Failed Login Tracking**: Monitors brute force attempts
- **Admin Dashboard**: Web-based interface for real-time monitoring

### Adaptive Response System (Planned)

- **Attacker Profiling**: Real-time classification into behavioral categories
- **Dynamic Content Generation**: Tailored fake products and vendors based on visitor profile
- **Triggered Actions**: Automated responses (promotional messages, exclusive "deals", fake admin panels)
- **LLM Integration Ready**: Architecture prepared for GPT-powered realistic content generation

---

## Architecture

### Technology Stack
```
Frontend:  Tailwind CSS, Jinja2 Templates
Backend:   Flask 2.3.3, SQLAlchemy
Database:  SQLite (users.db + honeypot_logs.db)
Security:  python-gnupg, PGP encryption
Container: Docker (for isolation and deployment)
Logging:   Custom HoneypotLogger class
```

### System Components
```
cryptic-vault/
├── app.py                  # Main Flask application
├── honeypot_logger.py      # Event tracking and analytics
├── init_db.py             # Database initialization script
├── relaunch.py            # Automated deployment script
├── Dockerfile             # Container configuration
├── requirements.txt       # Python dependencies
├── database/              # SQLite databases (created on first run)
│   ├── users.db          # User accounts and orders
│   └── honeypot_logs.db  # Event tracking database
├── static/
│   └── data/
│       ├── products.json # Marketplace inventory
│       └── orange.xlsx   # Bait file (honeypot asset)
└── templates/            # Jinja2 HTML templates
    ├── base.html
    ├── index.html
    ├── wallet.html
    ├── orders.html
    └── admin_dashboard.html
```

---

## Installation

### Prerequisites

- **Docker** (required for containerized deployment)
- **Python 3.12+** (if running on host)
- **Git** (to clone repository)

### Quick Start (Recommended)

1. **Clone the repository:**
```bash
   git clone https://github.com/yourusername/cryptic-vault.git
   cd cryptic-vault
```

2. **Launch with automated script:**
```bash
   python relaunch.py
```

   This script will:
   - Stop and remove any existing containers
   - Delete old databases for a fresh start
   - Build the Docker image
   - Launch the container with proper volume mounts
   - Initialize the database automatically

3. **Access the honeypot:**
```
   http://localhost:5000
```

4. **Admin Access:**
```
   Username: admin
   Password: adminadmin
   Dashboard: http://localhost:5000/admin/dashboard
```

---

## Usage

### Deployment Options

#### Option 1: Automated Docker Deployment (Recommended)

Use `relaunch.py` for complete automation:
```bash
python relaunch.py
```

**When to use `relaunch.py`:**
- ✅ First-time setup
- ✅ After code changes (rebuilds container)
- ✅ When you want a fresh database
- ✅ To reset the entire honeypot environment
- ✅ Production/research deployments

**What it does:**
1. Cleans up old containers
2. Deletes existing databases
3. Builds new Docker image
4. Launches container with volume mounts
5. Shows live logs and status

#### Option 2: Manual Database Initialization

If running on the **host machine** (without Docker):
```bash
# First time only - initialize database
python init_db.py

# Then run the application
python app.py
```

**When to use `init_db.py`:**
- ✅ Running directly on host (no Docker)
- ✅ Manual database setup/reset
- ✅ Development environment
- ✅ Troubleshooting database issues

**Note:** `relaunch.py` handles database initialization automatically, so you typically don't need `init_db.py` when using Docker.

### Deployment Environments

#### Ubuntu VM Deployment (Recommended for Research)
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
sudo apt install docker.io -y
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER

# Clone and launch
git clone https://github.com/yourusername/cryptic-vault.git
cd cryptic-vault
python relaunch.py
```

#### Host Machine Deployment (Development)
```bash
# Install Python dependencies
pip install -r requirements.txt

# Initialize database
python init_db.py

# Run application
python app.py

# Access at http://localhost:5000
```

### Container Management
```bash
# View live logs
docker logs -f honeypot-instance

# Stop container
docker stop honeypot-instance

# Restart container
docker restart honeypot-instance

# Access container shell
docker exec -it honeypot-instance /bin/bash

# Remove container
docker rm -f honeypot-instance
```

---

### Primary Objectives

This honeypot is designed to advance cybersecurity research in the following areas:

1. **Behavioral Analysis of Malicious Actors**
   - Profile attacker sophistication levels
   - Map attack patterns and methodologies
   - Identify reconnaissance techniques
   - Study decision-making processes

2. **Dynamic Honeypot Adaptation**
   - Real-time attacker classification
   - Personalized fake environment generation
   - Adaptive response strategies
   - Maximize engagement time for data collection

3. **AI-Powered Deception**
   - LLM-generated marketplace content
   - Realistic vendor personalities
   - Dynamic pricing and inventory
   - Convincing fake reviews and disputes

4. **Threat Intelligence Collection**
   - TTPs (Tactics, Techniques, Procedures)
   - Tools and exploit attempts
   - Credential harvesting methods
   - Bitcoin/cryptocurrency abuse patterns

### Data Collection

The system logs:
- Complete user journeys from entry to exit
- All interactions with marketplace features
- PGP key submissions (for OSINT analysis)
- Download attempts of bait files
- Failed authentication attempts
- Time-based behavioral patterns

### Attacker Profiles (Classification System)

| Profile Type | Indicators | Honeypot Response |
|-------------|-----------|-------------------|
| **Bot/Scraper** | Rapid requests, no JavaScript, suspicious UA | Serve all content, track patterns |
| **Researcher** | Reads docs, long sessions, no purchases | Standard experience + detailed logs |
| **Casual Viewer** | Short session, slow browsing, no cart | Normal marketplace behavior |
| **Serious Buyer** | Cart usage, PGP setup, wallet checks | Send promotional messages, show deals |
| **Advanced Threat** | SQL injection, path traversal, exploit attempts | Deploy advanced traps, fake admin panels |

---

## Security & Ethics

### Safety Features

- **Testnet Bitcoin Addresses**: No real cryptocurrency can be sent
- **Isolated Environment**: Docker containerization prevents host compromise
- **No Real Illegal Content**: All "products" are fake data
- **Controlled Bait Files**: Honeypot files are benign and tracked

### Ethical Considerations

⚠️ **This system is for authorized cybersecurity research only.**

- Only deploy in controlled environments
- Comply with all applicable laws and regulations
- Obtain proper authorization before deployment
- Do not use for entrapment or malicious purposes
- Respect privacy laws regarding data collection
- Anonymize and protect collected research data

### Legal Disclaimer

This tool is provided for educational and authorized security research purposes only. Users are responsible for ensuring their use complies with all applicable laws, regulations, and ethical guidelines. The authors assume no liability for misuse.

---

## Data Analysis

### Accessing Logs

**Via Admin Dashboard:**
```
http://localhost:5000/admin/dashboard
```

**Export Data:**
```
http://localhost:5000/admin/export_logs
```

**Direct Database Access:**
```bash
# Access logs database
sqlite3 database/honeypot_logs.db

# Example queries
SELECT * FROM sessions WHERE downloads_attempted > 0;
SELECT * FROM events WHERE event_type = 'DOWNLOAD';
```

### Event Types Tracked

- `PAGE_VIEW` - All page visits
- `REGISTER` - New account creation
- `LOGIN` / `LOGIN_FAILED` - Authentication attempts
- `LOGOUT` - Session termination
- `PRODUCT_VIEW` - Specific product views
- `CART_ADD` / `CART_REMOVE` - Shopping cart actions
- `PURCHASE` - Order placement
- `DOWNLOAD` - Bait file downloads (CRITICAL)
- `DEPOSIT_ATTEMPT` - Fake Bitcoin deposits (HIGH VALUE)
- `PGP_VERIFIED` - PGP key submission
- `SUPPORT_TICKET` - Support requests
- `VENDOR_APPLICATION` - Vendor registration attempts
- `PASSWORD_CHANGE` - Account modifications

---

## Future Enhancements

### Planned Features

- [ ] **LLM Integration**: OpenAI API for dynamic content generation
- [ ] **Advanced Profiler**: Machine learning-based attacker classification
- [ ] **Automated Responses**: Bot-driven vendor messages
- [ ] **Fake Admin Panel**: Honeypot within honeypot
- [ ] **Network Traffic Analysis**: Packet-level monitoring
- [ ] **Tor Hidden Service**: Deploy as .onion site
- [ ] **Multi-Tenant**: Support multiple concurrent honeypot instances
- [ ] **Alert System**: Real-time notifications for high-value events
- [ ] **MISP Integration**: Export threat intelligence to MISP platform
- [ ] **Elasticsearch Backend**: Advanced log analysis and visualization

### Research Extensions

- Integration with threat intelligence platforms
- Automated attacker fingerprinting
- Cross-honeypot correlation analysis
- Long-term behavioral trend analysis

---

## Contributing

This is a research project. Contributions that enhance the honeypot's realism, logging capabilities, or analytical features are welcome.

### Areas for Contribution

- More realistic marketplace content
- Additional bait file types
- Enhanced attacker profiling algorithms
- Better admin dashboard visualizations
- Additional trap mechanisms
- Documentation improvements

---

## References & Inspiration

- MITRE ATT&CK Framework
- OWASP Honeypot Project
- Kippo SSH Honeypot
- Modern Honey Network
- Dark Web Marketplace Research

---

## 📄 License

This project is licensed for research and educational purposes only.

---

<div align="center">

**⚠️ Use Responsibly | 🔬 For Research Only | 🛡️ Authorized Environments Only**

Made with 🐍 Python & ☕ Coffee for Cybersecurity Research

</div>