# The Cryptic Vault - Advanced Adaptive Honeypot System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Flask-2.3.3-green)
![Docker](https://img.shields.io/badge/Docker-Required-blue)
![License](https://img.shields.io/badge/License-Research-red)

**A self-evolving hybrid deception platform combining a fully functional dark web marketplace lure with SSH honeypot capabilities, powered by LLM-driven content generation and machine learning-based attacker profiling for advanced cybersecurity research**

[Features](#features) • [Architecture](#architecture) • [Installation](#installation) • [Usage](#usage) • [Research Goals](#research-goals)

</div>

---

## Overview

The Cryptic Vault is a **self-evolving hybrid deception platform** designed for advanced cybersecurity research that creates dynamic, adaptive fake environments to study malicious actor behavior. This platform uniquely combines two sophisticated attack surfaces: a fully functional **dark web marketplace frontend** and an **interactive SSH honeypot**, both enhanced with **LLM-powered content generation** (using models like Google Gemini or OpenAI) and **machine learning-driven behavioral analysis**.

Unlike traditional static honeypots, this system continuously learns from attacker interactions through a feedback loop: it collects telemetry, analyzes behavioral patterns using machine learning algorithms, trains predictive models, and automatically adjusts its deception strategies to maximize engagement and intelligence collection. The admin dashboard serves as the central hub for this self-evolving capability, allowing researchers to label sessions, retrain classification models, and deploy adaptive content in real-time.

### What Makes This Different?

- **Self-Evolving Architecture**: Continuous feedback loop where observed attacker behavior feeds machine learning models that automatically refine profiling accuracy and content generation strategies
- **Hybrid Dual-Lure System**: Combines a fully functional dark web marketplace (web-based) with an SSH honeypot (terminal-based) to capture both GUI-based and command-line threat actors
- **LLM-Powered Content Generation**: Integrates with large language models (Gemini, OpenAI, etc.) via `gemini_worker.py` and `gemini_terminal.py` to dynamically generate realistic vendor responses, product descriptions, system outputs, and fake file contents
- **Machine Learning-Based Profiling**: Admin dashboard with supervised and unsupervised ML capabilities for attacker classification, behavioral clustering, anomaly detection, and predictive threat scoring
- **Dynamic Adaptation**: Real-time classification system that profiles each visitor and adapts responses based on behavioral patterns, engagement level, and threat sophistication
- **Multi-Layer Traps**: Includes PGP-encrypted bait files, fake Bitcoin deposits, SSH command simulation, canary tokens, and realistic order fulfillment workflows
- **Comprehensive Telemetry**: Tracks every interaction across both web and SSH surfaces for deep analysis of attacker tactics, techniques, and procedures (TTPs)

---

## Features

### Hybrid Deception Surfaces

#### Dark Web Marketplace Lure (Web-Based)
- **Fully Functional Marketplace**: Complete e-commerce platform with product listings, shopping cart, checkout flows, vendor profiles, order tracking, and dispute resolution
- **PGP Encryption Integration**: Realistic GPG key handling and encrypted messaging using `python-gnupg` for "secure" communications
- **Bitcoin Testnet Lures**: Fake cryptocurrency deposit addresses with real QR codes (uses Bitcoin testnet for safety)
- **Bait File Distribution**: Downloadable honeypot assets (fake leaked databases, tools, credentials) with full download attribution and tracking
- **Session Tracking**: UUID-based session monitoring across all web interactions with behavioral timeline reconstruction
- **User Registration & Authentication**: Multi-factor credential capture with password complexity analysis and login pattern tracking

#### SSH Honeypot Lure (Terminal-Based)
- **Interactive SSH Sessions**: Fully functional SSH server (`ssh_honeypot.py`, `run_ssh_honeypot.py`) that accepts connections and presents a realistic fake Linux environment
- **Command Simulation Engine**: Responds to common reconnaissance commands (`ls`, `whoami`, `uname -a`, `cat /etc/passwd`, `dpkg -l`, etc.) with LLM-generated or templated outputs
- **Fake File System**: Simulated directory structures with bait files, fake configuration files, and canary tokens that trigger alerts when accessed
- **Persistence Detection**: Monitors for attacker attempts to establish persistence (SSH key injection, cron job creation, backdoor installation)
- **LLM-Enhanced Responses**: Uses `gemini_terminal.py` to generate contextually appropriate command outputs and system responses that adapt to attacker behavior
- **Command Logging**: Full transcript capture of all SSH session activity including timing analysis and command sequence profiling

### Machine Learning & Intelligence Gathering

- **ML-Powered Admin Dashboard**: Advanced web-based control center (`admin_dashboard.html`) for real-time monitoring, session labeling, model training, and predictive analytics
- **Supervised Learning Pipeline**: Train classification models to categorize attackers (Scanner, Interactive Recon, Fraudster, Data Exfiltrator) using labeled session data
- **Unsupervised Behavioral Clustering**: Automatically discover new attacker archetypes through clustering algorithms (k-means, HDBSCAN) applied to feature vectors
- **Predictive Threat Scoring**: Machine learning models assess likelihood of escalation, credential reuse, persistence attempts, and data exfiltration
- **Feature Engineering**: Automated extraction of behavioral features from event sequences using `profiler.py` (timing patterns, command TF-IDF, navigation graphs, interaction depth)
- **Model Retraining Workflow**: Human-in-the-loop labeling system where analysts mark sessions, triggering periodic model updates to improve classification accuracy
- **Event Telemetry**: Comprehensive logging of 15+ event types across both web and SSH surfaces (page views, logins, purchases, downloads, PGP submissions, SSH commands)
- **Session Analytics**: Multi-dimensional user journey mapping with behavioral timeline visualization, interaction heatmaps, and engagement metrics
- **Cross-Surface Correlation**: Links web marketplace activity with SSH honeypot sessions to identify sophisticated attackers operating across multiple vectors
- **Export & Integration**: JSON/CSV data exports (`honeypot_logs_export.json`) for offline analysis, integration with SIEM platforms, and external ML toolchains

### LLM-Powered Adaptive Response System

- **Real-Time LLM Integration**: Active integration with large language models (Google Gemini API, OpenAI GPT) via `gemini_worker.py` for dynamic content synthesis
- **Contextual Content Generation**: LLM generates vendor personalities, product descriptions, dispute conversations, support ticket responses, and marketplace reviews tailored to attacker behavior
- **SSH Response Synthesis**: `gemini_terminal.py` produces realistic command outputs, error messages, and system logs that adapt to reconnaissance patterns and skill level
- **Attacker-Specific Narratives**: ML profiling engine feeds attacker classification data to LLM prompt templates, generating personalized lures (e.g., "exclusive deals" for fraudsters, "admin access" for privilege escalators)
- **Automated Deception Deployment**: Trained models automatically select and deploy new LLM-generated assets (products, vendors, file contents) without manual template editing
- **Behavioral Trigger System**: Specific attacker actions trigger automated LLM-powered responses (promotional messages for browsers, fake admin panels for privilege seekers, canary tokens for exfiltrators)
- **Self-Improving Content**: Feedback loop where engagement metrics inform LLM prompt refinement, continuously improving deception effectiveness

---

## Architecture

### Technology Stack
```
Frontend:        Tailwind CSS, Jinja2 Templates, JavaScript (product_loader.js)
Backend:         Flask 2.3.3, SQLAlchemy, Python 3.12
Database:        SQLite (users.db + honeypot_logs.db)
SSH Honeypot:    Custom SSH server implementation (Paramiko-based)
LLM Integration: Google Gemini API, OpenAI-compatible endpoints
ML/Analytics:    scikit-learn, pandas, NumPy (profiler.py)
Security:        python-gnupg, PGP encryption, SSH host keys
Container:       Docker + docker-compose (for isolation and deployment)
Logging:         Custom HoneypotLogger class, JSON export utilities
Data Processing: convert_to_json.py, honeypot_logs_export.json
```

### System Components
```
cryptic-vault/
├── app.py                      # Main Flask application (web marketplace)
├── ssh_honeypot.py             # SSH honeypot server implementation
├── run_ssh_honeypot.py         # SSH honeypot launcher script
├── ssh_config.py               # SSH server configuration
├── ssh_host_key                # SSH server host key
├── gemini_worker.py            # LLM integration worker (Gemini API)
├── gemini_terminal.py          # LLM-powered SSH response generator
├── honeypot_logger.py          # Event tracking and analytics engine
├── profiler.py                 # ML feature extraction and profiling
├── convert_to_json.py          # Log export and conversion utilities
├── honeypot_logs_export.json   # Sample exported telemetry data
├── init_db.py                  # Database initialization script
├── relaunch.py                 # Automated deployment and orchestration
├── Dockerfile                  # Container configuration
├── docker-compose.yml          # Multi-container orchestration
├── requirements.txt            # Python dependencies
├── system_prompt.md            # LLM system prompts and templates
├── database/                   # SQLite databases (created on first run)
│   ├── users.db               # User accounts and orders
│   └── honeypot_logs.db       # Event tracking and session data
├── gpg_home/                   # GPG keyring and encryption data
├── static/
│   ├── css/                   # Stylesheet assets
│   ├── js/
│   │   └── product_loader.js  # Dynamic product loading
│   ├── images/                # Marketplace images
│   └── data/
│       ├── products.json      # Marketplace inventory (LLM-generated)
│       └── cryptic.xlsx       # Bait file (honeypot asset)
├── templates/                  # Jinja2 HTML templates
│   ├── admin_dashboard.html   # ML training and monitoring interface
│   ├── base.html
│   ├── index.html
│   ├── wallet.html
│   ├── orders.html
│   ├── messages.html
│   ├── support.html
│   └── vendor.html
└── tests/
    └── test_ssh_client.py      # SSH honeypot testing utilities
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

#### Option 3: SSH Honeypot Deployment

To run the SSH honeypot component:

```bash
# Run SSH honeypot on port 2222 (requires proper authorization)
python run_ssh_honeypot.py
```

**SSH Honeypot Configuration:**
- Default port: `2222` (configurable in `ssh_config.py`)
- Logs all commands to `honeypot_logs.db`
- Integrates with LLM worker for dynamic responses
- Captures full session transcripts with timing data

**⚠️ Important:** Only deploy SSH honeypots in isolated, authorized research environments. Never expose to production networks without proper authorization and legal review.

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

## Research Goals

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

3. **Machine Learning-Driven Deception**
   - **Supervised Classification**: Train models on labeled sessions to automatically categorize new attackers
   - **Unsupervised Discovery**: Clustering algorithms reveal novel attacker archetypes and behavioral patterns
   - **Predictive Analytics**: ML models forecast attack escalation, persistence attempts, and data exfiltration likelihood
   - **Feature Engineering**: Automated extraction of behavioral signatures (command sequences, timing patterns, navigation graphs)
   - **Model Retraining**: Admin dashboard enables continuous model improvement through human-in-the-loop labeling

4. **LLM-Enhanced Content Generation**
   - **Gemini/OpenAI Integration**: Real-time LLM-powered content synthesis via `gemini_worker.py`
   - **Contextual Marketplace Content**: Dynamic generation of products, vendor profiles, reviews, and dispute conversations
   - **SSH Response Synthesis**: Terminal output generation via `gemini_terminal.py` that adapts to attacker skill level
   - **Adaptive Narratives**: ML profiling informs LLM prompts to create attacker-specific lures and scenarios

5. **Threat Intelligence Collection**
   - TTPs (Tactics, Techniques, Procedures) across web and SSH attack surfaces
   - Tool and exploit fingerprinting (automated scanner detection, custom script identification)
   - Credential harvesting methods and password pattern analysis
   - Bitcoin/cryptocurrency abuse patterns and transaction flow analysis
   - Cross-surface attack correlation (linking web and SSH activity)

### Data Collection & Machine Learning Pipeline

The system implements a comprehensive telemetry and ML pipeline:

**Raw Telemetry Collection:**
- Complete user journeys from entry to exit across both web and SSH surfaces
- All marketplace interactions (browsing, purchasing, messaging, disputes)
- SSH command transcripts with full timing data and response analysis
- PGP key submissions (for OSINT and key-based attribution)
- Download attempts of bait files with attribution chains
- Failed authentication attempts and brute force patterns
- Cross-surface behavioral fingerprinting

**Feature Engineering (`profiler.py`):**
- Temporal features (session duration, inter-event timing, time-of-day patterns)
- Behavioral sequences (command n-grams, page navigation graphs, action chains)
- Statistical aggregates (request frequency, error rates, engagement depth)
- Text-based features (command TF-IDF, user-agent parsing, natural language analysis)
- Network features (IP geolocation, AS number, connection patterns)

**ML Model Training (Admin Dashboard):**
- Supervised classifiers for threat categorization
- Clustering algorithms for behavioral segmentation
- Anomaly detection for novel attack patterns
- Predictive models for threat escalation forecasting
- Continuous retraining loop with analyst-labeled data

### Attacker Profiles (Classification System)

| Profile Type | Indicators | Honeypot Response |
|-------------|-----------|-------------------|
| **Scanner** | Rapid requests, no JavaScript, suspicious UA | Serve all content, track patterns |
| **Interactive Recon** | Manual system info commands (uname -a, whoami, ip a), file system exploration (ls -laR, find / -name), checking configuration or installed packages (dpkg -l) | Inject soft bait. Collect detailed behavioral data for ML profiling. |
| **Fraudster** | Repeated failed sudo attempts, interaction with /etc/passwd or /etc/group, setting up unauthorized SSH keys or cron jobs for persistence | Escalate lure with high-value offer/Canary Token. Log all financial inputs and transactions. |
| **Data Exfiltrator** | Execution of commands like tar, zip, scp, rsync. Accessing system files (e.g., /etc/shadow). Attempting to read or move the Canary Token file. | Trigger immediate alert on token access. Allow simulated file access and deploy session slowdown traps. |

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

**Web Marketplace Events:**
- `PAGE_VIEW` - All page visits with referrer and navigation path
- `REGISTER` - New account creation with credential capture
- `LOGIN` / `LOGIN_FAILED` - Authentication attempts and brute force detection
- `LOGOUT` - Session termination and duration calculation
- `PRODUCT_VIEW` - Specific product views with dwell time
- `CART_ADD` / `CART_REMOVE` - Shopping cart actions and abandonment patterns
- `PURCHASE` - Order placement with full transaction details
- `DOWNLOAD` - Bait file downloads with attribution (CRITICAL)
- `DEPOSIT_ATTEMPT` - Fake Bitcoin deposits and wallet interactions (HIGH VALUE)
- `PGP_VERIFIED` - PGP key submission for encrypted communications
- `SUPPORT_TICKET` - Support requests and social engineering attempts
- `VENDOR_APPLICATION` - Vendor registration attempts (insider threat indicator)
- `PASSWORD_CHANGE` - Account modifications and security behavior

**SSH Honeypot Events:**
- `SSH_CONNECT` - New SSH connection establishment
- `SSH_AUTH_ATTEMPT` - Authentication attempts (password/key-based)
- `SSH_AUTH_SUCCESS` - Successful authentication events
- `SSH_COMMAND` - Individual command execution with full context
- `SSH_FILE_ACCESS` - File read/write/download attempts
- `SSH_PRIVILEGE_ESCALATION` - Sudo attempts and privilege seeking
- `SSH_PERSISTENCE_ATTEMPT` - SSH key injection, cron jobs, backdoors
- `SSH_CANARY_TRIGGER` - Canary token access (IMMEDIATE ALERT)
- `SSH_DISCONNECT` - Session termination with transcript summary

---

## Future Enhancements

### Planned Features

- [x] **LLM Integration**: Google Gemini and OpenAI API integration (implemented via `gemini_worker.py`, `gemini_terminal.py`)
- [x] **SSH Honeypot**: Interactive SSH sessions with command simulation (implemented)
- [x] **Machine Learning Profiling**: Behavioral classification and predictive analytics (implemented in admin dashboard)
- [ ] **Advanced Deep Learning Models**: Neural network-based sequence modeling (LSTM/Transformer) for command prediction
- [ ] **Automated LLM-Driven Responses**: Fully autonomous vendor conversation agents
- [ ] **Fake Admin Panel**: Multi-layer honeypot-within-honeypot with privilege escalation traps
- [ ] **Network Traffic Analysis**: Deep packet inspection and protocol anomaly detection
- [ ] **Tor Hidden Service**: Deploy marketplace as .onion site with enhanced anonymity
- [ ] **Multi-Tenant Architecture**: Support multiple concurrent honeypot instances with isolated data
- [ ] **Real-Time Alert System**: Webhook-based notifications for high-value events and canary triggers
- [ ] **MISP Integration**: Automated threat intelligence export to MISP/OpenCTI platforms
- [ ] **Elasticsearch Backend**: Advanced log aggregation, full-text search, and visualization (Kibana dashboards)
- [ ] **Reinforcement Learning**: RL agents that optimize deception strategies based on engagement metrics
- [ ] **Federated Learning**: Collaborative model training across multiple honeypot deployments

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