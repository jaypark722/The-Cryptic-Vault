"""
SSH Honeypot Server for Cryptic Vault.

This module implements an SSH honeypot that routes all commands through the
Gemini API to simulate a realistic Linux environment while logging all activity.
"""

import os
import sys
import logging
import socket
import threading
import paramiko
from typing import Dict, Optional, Any
import uuid
from datetime import datetime

from ssh_config import (
    SSH_HOST,
    SSH_PORT,
    SSH_BANNER,
    SSH_KEY_FILE,
    SSH_KEY_BITS,
    MAX_CONNECTIONS_PER_IP
)
from honeypot_logger import HoneypotLogger
from gemini_worker import GeminiWorker

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SSHHoneypot(paramiko.ServerInterface):
    """
    Per-connection ServerInterface for Paramiko.
    """

    def __init__(self, ip_address: str):
        super().__init__()
        self.ip_address = ip_address
        self.session_id = str(uuid.uuid4())
        self.username: Optional[str] = None
        self.terminal: Optional[GeminiTerminal] = None
        # Use the same database path as the Flask app
        db_path = os.path.join(os.path.dirname(__file__), 'database', 'honeypot_logs.db')
        self.logger = HoneypotLogger(db_path=db_path)

    def check_auth_password(self, username: str, password: str) -> int:
        """Accept any username/password and log attempt."""
        self.username = username
        try:
            self.logger._log_generic_event('SSH_LOGIN_ATTEMPT', self.session_id, self.ip_address, {
                'username': username,
                'password': password,
                'timestamp': datetime.now().isoformat()
            })
        except Exception:
            pass
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username: str) -> str:
        return 'password'

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel) -> bool:
        # Do not create GeminiTerminal here; the centralized worker will
        # create/track session terminals inside the worker's event loop.
        try:
            self.logger.log_ssh_connection(self.session_id, self.ip_address, self.username or 'unknown')
        except Exception:
            pass
        return True


class ThreadedSSHServer:
    """Thread-per-connection SSH server using Paramiko transports over raw sockets."""

    def __init__(self, host: str = SSH_HOST, port: int = SSH_PORT, worker: GeminiWorker = None):
        self.host = host
        self.port = port
        self.host_key = self._get_host_key()
        self.active_connections: Dict[str, int] = {}
        self.lock = threading.Lock()
        self.should_stop = threading.Event()
        # Gemini worker: central event loop where GeminiTerminal instances are created
        self.worker = worker

    def _get_host_key(self) -> paramiko.RSAKey:
        if os.path.exists(SSH_KEY_FILE):
            return paramiko.RSAKey(filename=SSH_KEY_FILE)
        key = paramiko.RSAKey.generate(bits=SSH_KEY_BITS)
        key.write_private_key_file(SSH_KEY_FILE)
        return key

    def _check_rate_limit(self, ip_address: str) -> bool:
        with self.lock:
            current = self.active_connections.get(ip_address, 0)
            if current >= MAX_CONNECTIONS_PER_IP:
                return False
            self.active_connections[ip_address] = current + 1
            return True

    def _decrement_connection(self, ip_address: str) -> None:
        with self.lock:
            if ip_address in self.active_connections:
                self.active_connections[ip_address] -= 1
                if self.active_connections[ip_address] <= 0:
                    del self.active_connections[ip_address]

    def _client_thread(self, client_sock: socket.socket, addr):
        ip_address = addr[0] if addr else 'unknown'
        try:
            transport = paramiko.Transport(client_sock)
            transport.local_version = SSH_BANNER
            transport.add_server_key(self.host_key)

            server = SSHHoneypot(ip_address)
            try:
                transport.start_server(server=server)
            except Exception as e:
                logger.debug(f"Transport start failed for {ip_address}: {e}")
                return

            # Wait for a channel
            channel = transport.accept(20)
            if not channel:
                logger.debug(f"No channel for {ip_address}")
                return

            # Handle shell (blocking in this thread); pass worker
            self._handle_shell(channel, server)

        except Exception as e:
            logger.error(f"Connection handler error from {ip_address}: {e}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            self._decrement_connection(ip_address)

    def _handle_shell(self, channel: paramiko.Channel, server: SSHHoneypot) -> None:
        """Handle an interactive shell session."""
        # Validate server object
        if not server:
            logger.error("Invalid server object passed to shell handler", exc_info=True)
            return

        # Log detailed session information
        logger.info(f"Starting shell handler for session {server.session_id}")
        logger.debug(f"Channel info - Client: {server.ip_address}, "
                     f"Username: {server.username}, "
                     f"Session: {server.session_id}")

        # Note: terminal is created lazily by the worker on first command
        # No need to check server.terminal here
        def safe_send(data: str) -> bool:
            """Safely send data to the channel with error handling."""
            try:
                if channel.closed:
                    return False
                channel.send(data)
                return True
            except Exception as e:
                logger.error(f"Failed to send data on channel: {e}")
                return False

        try:
            # Configure channel
            channel.settimeout(3600)  # 1 hour timeout
            terminal_size = (80, 24)  # Default terminal size
            channel.set_environment_variable("TERM", "xterm")
            channel.set_environment_variable("SHELL", "/bin/bash")
            
            # Send welcome message
            welcome = (
                f"Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)\r\n"
                f"* Documentation:  https://help.ubuntu.com\r\n"
                f"* Management:     https://landscape.canonical.com\r\n"
                f"* Support:        https://ubuntu.com/advantage\r\n\r\n"
                f"Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from {server.ip_address}\r\n"
            )
            logger.debug(f"Sending welcome message to {server.session_id}")
            if not safe_send(welcome):
                logger.error(f"Failed to send welcome message to {server.session_id}")
                return

            logger.debug(f"Starting command loop for {server.session_id}")
            buffer = ''
            while True:
                logger.debug(f"Sending prompt to {server.session_id}")
                if not safe_send("root@cryptic-vault-server:~# "):
                    logger.error(f"Failed to send prompt to {server.session_id}")
                    break

                buffer = ''
                logger.debug(f"Waiting for input from {server.session_id}")
                while True:
                    try:
                        if channel.closed:
                            logger.info(f"Channel closed for session {server.session_id}")
                            return

                        logger.debug(f"Reading character from {server.session_id}")
                        data = channel.recv(1)
                        if not data:
                            logger.info(f"End of stream for session {server.session_id}")
                            return

                        # Handle special characters
                        char = data.decode('utf-8', errors='replace')
                        if char == '\x03':  # Ctrl+C
                            if not safe_send('^C\n'):
                                return
                            break
                        elif char == '\x04':  # Ctrl+D
                            if channel.recv_ready():  # Only exit if buffer is empty
                                continue
                            logger.info(f"Ctrl+D received, closing session {server.session_id}")
                            return
                        elif char == '\x7f' or char == '\x08':  # Backspace
                            if buffer:
                                buffer = buffer[:-1]
                                if not safe_send('\b \b'):  # Move back, clear char, move back
                                    return
                            continue
                        elif char == '\r':
                            if not safe_send('\r\n'):
                                return
                            break
                        elif char == '\n':
                            break
                        elif char.isprintable():
                            buffer += char
                            if not safe_send(char):
                                return

                    except socket.timeout:
                        continue
                    except Exception as e:
                        logger.error(f"Error reading from channel: {e}")
                        return

                command = buffer.strip()
                if command:
                    # Handle exit/logout commands
                    if command.lower() in ['exit', 'logout', 'quit']:
                        logger.info(f"User requested exit for session {server.session_id}")
                        safe_send("logout\r\n")
                        return
                    
                    out_text = ""
                    success = False
                    try:
                        # Execute command directly - no async needed
                        output, success = self.worker.submit(server.session_id, command)
                        out_text = str(output) if output else ""
                    except Exception as e:
                        logger.error(f"Command execution failed: {e}", exc_info=True)
                        out_text = f"Command execution failed: {str(e)}"
                        success = False

                    # Send the response to the client
                    # Clean output: strip trailing whitespace, ensure proper line endings
                    if out_text:
                        out_text = out_text.rstrip() + '\r\n'
                        if not safe_send(out_text):
                            break

                    try:
                        server.logger.log_ssh_command(server.session_id, command, out_text, bool(success))
                    except Exception:
                        pass

        except Exception as e:
            logger.error(f"Shell error: {e}")
        finally:
            try:
                server.logger.log_ssh_session_end(server.session_id)
            except Exception:
                pass
            try:
                channel.close()
            except Exception:
                pass

    def serve_forever(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(100)
        logger.info(f"SSH Honeypot listening on {self.host}:{self.port}")

        try:
            while not self.should_stop.is_set():
                try:
                    client_sock, addr = sock.accept()
                except OSError:
                    break

                ip_address = addr[0]
                if not self._check_rate_limit(ip_address):
                    logger.warning(f"Connection limit exceeded for {ip_address}")
                    try:
                        client_sock.close()
                    except Exception:
                        pass
                    continue

                t = threading.Thread(target=self._client_thread, args=(client_sock, addr), daemon=True)
                t.start()

        except KeyboardInterrupt:
            logger.info("Shutting down SSH Honeypot (KeyboardInterrupt)")
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def shutdown(self):
        self.should_stop.set()


def main():
    server = ThreadedSSHServer()
    server.serve_forever()


if __name__ == '__main__':
    main()
