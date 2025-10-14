import subprocess
import os
import sys

# --- Configuration ---
# Image name used for building and launching the container
IMAGE_NAME = "cryptic-vault"
# Container name used for stopping, removing, and launching the instance
CONTAINER_NAME = "honeypot-instance"
DB_FILES = ["users.db", "honeypot_logs.db"]
HOST_PORT = 5000
CONTAINER_PORT = 5000

# The complex command to initialize the database
DB_INIT_COMMAND = f"""
from app import db, app
with app.app_context():
    db.create_all()
"""

def run_command(command, check_success=True, ignore_errors=None):
    """Executes a shell command."""
    print(f"\n[EXEC] {' '.join(command)}")
    try:
        # Use shell=True for complex commands like the database initialization
        if ignore_errors is not None:
            # Command is run with shell=True, stderr is captured to check for ignorable errors
            result = subprocess.run(command, check=False, shell=True, stderr=subprocess.PIPE, text=True)
            # Check if the command failed (returncode != 0) but contains a known ignorable error
            if result.returncode != 0 and ignore_errors in result.stderr:
                print(f"[INFO] Ignored expected error: {ignore_errors.strip()}")
                return True
            
            # If it failed for another reason, or check_success is True, raise the error
            if result.returncode != 0 and check_success:
                 raise subprocess.CalledProcessError(result.returncode, command, output=result.stdout, stderr=result.stderr)

            # If check_success is False, simply return based on returncode
            return result.returncode == 0
        
        else:
            # Simple command execution without shell=True for security and simplicity
            subprocess.run(command, check=check_success)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Command failed with exit code {e.returncode}: {e.cmd}")
        # Only print output/stderr if available (might be large)
        if e.output: print(f"Output: {e.output}")
        if e.stderr: print(f"Stderr: {e.stderr}")
        return False
    except FileNotFoundError:
        print(f"[ERROR] Command not found. Ensure {' '.join(command)} is available.")
        return False

def relaunch_app():
    print(f"--- Starting Cryptic Vault Relaunch/Rebuild Process ---")

    # 1. Stop and remove the old container instance
    print("\n--- Step 1: Cleaning up old container ---")
    # Docker commands are often more robust when passed as lists without shell=True, 
    # but run_command is configured to handle complex string commands via shell=True for DB_INIT_COMMAND.
    # We will use shell=True for consistency in handling ignorable errors here.
    
    # Stop: Ignore error if container is not running
    run_command(f"docker stop {CONTAINER_NAME}", check_success=False, ignore_errors=f"Error response from daemon: No such container: {CONTAINER_NAME}")
    # Remove: Ignore error if container is not found
    run_command(f"docker rm {CONTAINER_NAME}", check_success=False, ignore_errors=f"Error: No such container: {CONTAINER_NAME}")
    print(f"[SUCCESS] Old container '{CONTAINER_NAME}' stopped and removed.")

    # 2. Delete database files
    print("\n--- Step 2: Deleting database files for clean start ---")
    for db_file in DB_FILES:
        if os.path.exists(db_file):
            os.remove(db_file)
            print(f"[DELETE] Removed {db_file}")
        else:
            print(f"[INFO] {db_file} not found, skipping removal.")

    # 3. Build the new Docker image
    print("\n--- Step 3: Building new Docker image ---")
    # For docker build, using a list is safer than a single string
    if not run_command(["docker build -t", IMAGE_NAME, "."]):
        sys.exit(1)
    print(f"[SUCCESS] Image '{IMAGE_NAME}:latest' built successfully.")

    # 4. Initialize the database (must be run after file deletion and build)
    print("\n--- Step 4: Initializing database tables ---")
    # We pass the full command string for shell=True handling
    db_command = f"docker run --rm {IMAGE_NAME} python -c '{DB_INIT_COMMAND.strip()}'"
    if not run_command(db_command):
        print("[CRITICAL] Database initialization failed. Cannot proceed.")
        sys.exit(1)
    print(f"[SUCCESS] Database initialized.")

    # 5. Launch the new container instance
    print("\n--- Step 5: Launching new container ---")
    launch_command = f"docker run -d -p {HOST_PORT}:{CONTAINER_PORT} --name {CONTAINER_NAME} {IMAGE_NAME}"
    if not run_command(launch_command):
        sys.exit(1)

    print(f"\n========================================================")
    print(f"✅ Success! The application is running.")
    print(f"Container: {CONTAINER_NAME}")
    print(f"Image: {IMAGE_NAME}")
    print(f"Access the app at: http://<Your-VM-IP>:{HOST_PORT}")
    print(f"========================================================")

if __name__ == "__main__":
    relaunch_app()
