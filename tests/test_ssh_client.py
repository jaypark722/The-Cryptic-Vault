"""
Basic functional test for the SSH honeypot.

This script attempts to connect to localhost:2222 using Paramiko, authenticates
with arbitrary credentials, runs simple commands, and prints the responses.

Note: This script is intended for local/manual testing only and will block or
fail if the honeypot is not running.
"""

import paramiko
import sys

HOST = '127.0.0.1'
PORT = 2222
USERNAME = 'anyuser'
PASSWORD = 'anything'


def run_test():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"Connecting to {HOST}:{PORT} as {USERNAME}...")
        client.connect(HOST, port=PORT, username=USERNAME, password=PASSWORD, look_for_keys=False, allow_agent=False, timeout=10)

        for cmd in ['whoami', 'pwd', 'ls -la /root | head -n 20']:
            print(f"\n$ {cmd}")
            stdin, stdout, stderr = client.exec_command(cmd, timeout=20)
            out = stdout.read().decode('utf-8', errors='ignore')
            err = stderr.read().decode('utf-8', errors='ignore')
            print(out.strip())
            if err:
                print('ERR:', err.strip())

        client.close()
        print('\nTest completed.')
    except Exception as e:
        print('Test failed:', e)
        sys.exit(2)


if __name__ == '__main__':
    run_test()
