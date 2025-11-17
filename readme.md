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
 # The Cryptic Vault — A Self‑Evolving Hybrid Deception Platform

 <div align="center">

 ![Python](https://img.shields.io/badge/Python-3.12-blue)
 ![Flask](https://img.shields.io/badge/Flask-2.3-green)
 ![Docker](https://img.shields.io/badge/Docker-Recommended-blue)
 ![Research](https://img.shields.io/badge/License-Research-red)

 **An adaptive, machine-assisted deception platform that combines a realistic darkweb marketplace lure with SSH-based interaction traps and LLM-driven content to study and engage adversaries.**

 Features • Architecture • Installation • Usage • Research & ML

 </div>

 ---

 ## High-level Summary

 The Cryptic Vault is a research-focused, hybrid deception platform built to attract, engage, and profile malicious actors through highly convincing fake assets.

 At its core this project is self‑evolving: telemetry from the marketplace UI and SSH lures feeds an admin-driven machine learning pipeline that refines attacker profiles, updates deception content and policies, and automates tailored responses. The result is a continuous feedback loop that increases engagement fidelity and improves the quality of behavioral intelligence over time.

 Key capabilities at a glance:
 - Dual-lure approach: a darkweb marketplace frontend + SSH honeypot/backdoor-style interaction surface
 - LLM-assisted content generation (integrates with LLM backends such as Gemini / OpenAI for contextual fake outputs)
 - Admin dashboard for labeling, training, analyzing, and deploying profile-driven deception
 - Machine learning components for profiling, prediction and dynamic content selection
 - Full event logging, exports, and research-ready artifacts

 This README describes the platform in high level, lists technical components, and explains how the pieces work together so researchers can deploy, extend and study attacker behavior.

 ---

 ## Core Concepts — What makes this a "self‑evolving" deception platform

 - Continuous telemetry: every request, event, and interaction (marketplace actions, SSH commands, file downloads, PGP submissions) is recorded and available for analysis.
 - Human-in-the-loop training: analysts can label sessions and outcomes in the admin UI; labeled data is fed back into model training jobs to improve classification and prediction.
 - Automated policy & content rollout: trained models or simple heuristics can be used to select or generate new deception assets (product listings, vendor messages, faux admin responses) that are deployed without manual template edits.
 - LLM augmentation: an LLM worker (e.g., the included gemini_worker.py / gemini_terminal.py helpers) can synthesize realistic vendor replies, product descriptions, dispute conversations and other contextual text that increases believability.

 Together these elements produce an automated loop: observe → label → train → deploy → observe. That is the essence of the self‑evolving behavior.

 ---

 ## Features (expanded)

 - Hybrid deception surfaces
   - Realistic marketplace: listings, carts, checkout flows, messaging, vendor pages and simulated disputes.
   - SSH lure: interactive SSH sessions, fake file systems, canary tokens and command-response traps to capture manual reconnaissance and scripted attacks.

 - Machine learning and profiling
   - Session-level profiling (feature extraction from event sequences)
   - Supervised and unsupervised components (classification, clustering, anomaly scoring)
   - Predictive scoring (likelihood of escalation, credential reuse, persistence attempts)
   - Admin-driven retraining: labels from the dashboard are used for periodic retraining and model updates.

 - LLM integration (content synthesis)
   - Optional LLM worker that generates dynamic marketplace text, vendor replies and simulated logs to increase realism.
   - Designed to plug into any LLM API (Gemini/OpenAI-like endpoints); connectors and a worker script are provided to demonstrate the pattern.

 - High-fidelity lures
   - PGP key handling and encrypted messages to mimic real darkweb trade workflows
   - Testnet cryptocurrency addresses used as bait (no real funds)
   - Downloadable bait files (fully controlled and benign) with attribution and tracking

 - Rich telemetry & analysis
   - Fine-grained events (page view, product view, cart actions, login attempts, downloads, SSH commands)
   - Exports in JSON/CSV for offline ML and integration with analysis tools
   - Admin dashboard for session inspection, labeling, and metric visualization

 - Safety & isolation
   - Docker-friendly deployment for environment containment
   - Designed to run in isolated, authorized research environments only

 ---

 ## Architecture & Components

 This repository contains modular components that implement the different surfaces and the orchestration layer.

 - Frontend & web: Flask + Jinja2 templates serving the marketplace UI and admin dashboard (files such as `app.py`, templates under `templates/`, and static assets in `static/`).
 - Marketplace data: canned or generated product inventories in `static/data/products.json` and helper scripts like `product_loader.js`.
 - SSH lure: SSH honeypot entrypoints and configuration (`ssh_honeypot.py`, `run_ssh_honeypot.py`, `ssh_config.py`, `ssh_host_key`) that accept connections and present interactive traps.
 - LLM worker: scripts such as `gemini_worker.py` and `gemini_terminal.py` demonstrate the pattern of sending contextual prompts to an LLM and returning synthesized content to the platform.
 - Admin & orchestration: `admin_dashboard.html` and admin endpoints in `app.py` for labeling sessions, starting/stopping data exports, and kicking off retraining jobs.
 - Persistence and logs: SQLite databases under `database/` by default (e.g., `honeypot_logs.db`), plus JSON exports like `honeypot_logs_export.json` for analysis.
 - Utility scripts: `init_db.py`, `relaunch.py` (automation), `convert_to_json.py`, export helpers, and `profiler.py` for lightweight feature extraction.

 Assumption: the repo includes example worker scripts and a simple ML pipeline that can be extended with scikit-learn, PyTorch, or other libraries. If you plan to use a specific framework, update `requirements.txt` and the worker scripts accordingly.

 ---

 ## Machine Learning — how the platform learns

 This section describes the intended ML workflow (designed for research flexibility):

 1. Data collection: events and session traces are exported (JSON/SQLite). Important fields include timestamped event sequences, user-agent, IP (if available in controlled environment), command traces from SSH, and bait-file interactions.
 2. Feature engineering: `profiler.py` and admin tooling extract sequence-based features (counts, time deltas, command patterns, TF-IDF of textual commands, etc.).
 3. Model training: supervised classifiers for profile labels (scanner, recon, fraudster, exfiltrator), clustering for emergent groups, and anomaly detection for novel behaviors. Training can be run offline or scheduled from the dashboard.
 4. Deployment: model artifacts produce scored outputs (profiles, risk scores) that the platform uses to select content templates or LLM prompts.
 5. Feedback: analyst labels from the admin UI are merged back into training data to refine models on the next iteration.

 Typical model types used: logistic regression / random forest for interpretable classification, k-means / HDBSCAN for clustering, and lightweight sequence models for time-based patterns. LLMs are used for text synthesis, not for core detection logic (although they can assist with feature extraction or enrichment).

 Notes & assumption: The README references ML techniques generally; concrete implementations/dependencies will vary by research needs. The repo includes starter code and examples rather than a production ML platform.

 ---

 ## Installation & Quick Start

 These are high-level instructions. Use the included `relaunch.py` to automate most steps in a Docker-friendly way. On Windows, prefer running inside WSL2 / an Ubuntu VM for Docker compatibility.

 Prerequisites
 - Docker (recommended for isolation)
 - Python 3.10+ (host-side development)
 - Git

 Quick start (recommended - containerized):
 1. Clone the repo and change directory.
 2. Build and run with the automation script: `python relaunch.py` (this script orchestrates Docker build/run and database initialization).
 3. Browse the marketplace at `http://localhost:5000` and visit the admin dashboard at `/admin/dashboard`.

 Host (development) option:
 - Install dependencies: `pip install -r requirements.txt`
 - Initialize DB: `python init_db.py`
 - Run: `python app.py`

 For SSH lure testing, run `run_ssh_honeypot.py` or start the `ssh_honeypot` service as documented in repo scripts (ensure proper, authorized test environment).

 ---

 ## Usage Highlights — admin capabilities

 - Live session inspection: see full event timelines, SSH command transcripts, and bait file interactions.
 - Labeling: mark sessions as specific attacker types or outcomes (e.g., 'exfiltration', 'credential harvest').
 - Retraining: schedule or trigger retraining jobs from the dashboard to refresh prediction models.
 - Content rollout: push new generated assets (via LLM worker or templates) and measure engagement uplift.
 - Export: export session logs and event data (JSON/CSV) for offline research and model training.

 Example exports: `honeypot_logs_export.json` contains a sample export for quick analysis.

 ---

 ## Safety, Ethics & Legal

 Important: this project is explicitly for authorized research, education and defensive cybersecurity work. It must be run only in controlled environments by personnel who understand the legal and ethical constraints.

 Safety considerations implemented in the platform:
 - Use of testnet cryptocurrency addresses (no real funds)
 - Docker/container isolation recommended to reduce host risk
 - All bait files are benign and tracked for attribution

 Ethics & legal: obtain permission before deploying, respect privacy laws, do not use this platform for entrapment or offensive operations. The authors accept no responsibility for misuse.

 ---

 ## Files & Notable Scripts (quick reference)

 - `app.py` — main Flask app and HTTP endpoints
 - `ssh_honeypot.py`, `run_ssh_honeypot.py`, `ssh_config.py` — SSH lure and configuration
 - `gemini_worker.py`, `gemini_terminal.py` — example LLM worker/adapter scripts (plug in API keys to experiment)
 - `honeypot_logger.py` — centralized event logging
 - `init_db.py` — initialize SQLite DBs
 - `relaunch.py` — orchestration automation for Docker runs
 - `convert_to_json.py`, `profiler.py` — utility and feature-engineering helpers
 - `honeypot_logs_export.json` — example export
 - `static/data/products.json` — marketplace inventory (seed data)

 ---

 ## Extending & Research Suggestions

 - Replace the example ML components with your preferred stack (scikit-learn, XGBoost, PyTorch, etc.).
 - Implement an offline training pipeline that consumes exports and outputs versioned models.
 - Integrate with MISP, Elastic, or a SIEM for operational threat intelligence workflows.
 - Experiment with different LLM prompt templates to measure the impact on adversary engagement.

 ---

 ## Contributing

 Contributions that improve realism, logging fidelity, ML pipelines, or analysis tooling are welcome. Please open an issue or PR describing the intended change and the research rationale.

 ---

 ## Disclaimer & License

 For research and educational use only. Run in controlled environments and comply with applicable law. The maintainers are not responsible for misuse.

 ---

 Made for cybersecurity research — use responsibly.
