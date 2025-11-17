#!/usr/bin/env python3
"""
Runner script for the Cryptic Vault SSH Honeypot.

This script manages starting/stopping the SSH honeypot server and handles logging.
"""

import os
import sys
import signal
import logging
import asyncio
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('ssh_honeypot.log')
    ]
)

logger = logging.getLogger(__name__)

# Verify required environment variables
required_vars = ['GEMINI_API_KEY']
missing_vars = [var for var in required_vars if not os.getenv(var)]
if missing_vars:
    logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
    sys.exit(1)

def signal_handler(sig, frame):
    """Handle graceful shutdown on SIGINT/SIGTERM."""
    logger.info("Received shutdown signal...")
    sys.exit(0)

if __name__ == '__main__':
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Import here to catch any module errors after environment checks
        from gemini_worker import GeminiWorker
        from ssh_honeypot import ThreadedSSHServer

        # Start Gemini worker
        worker = GeminiWorker()
        worker.start()

        # Start the threaded SSH server with worker
        server = ThreadedSSHServer(worker=worker)
        logger.info("Starting SSH Honeypot server...")
        try:
            server.serve_forever()
        finally:
            worker.stop()
        
    except Exception as e:
        logger.error(f"Failed to start SSH Honeypot: {str(e)}")
        sys.exit(1)