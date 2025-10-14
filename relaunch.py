import subprocess
import os
import sys

# --- Configuration ---
IMAGE_NAME = "cryptic-vault"
CONTAINER_NAME = "honeypot-instance"
DB_FILES = ["users.db", "honeypot_logs.db"]
HOST_PORT = 5000
CONTAINER_PORT = 5000

# The complex command to initialize the database
DB_INIT_COMMAND = """from app import db, app
with app.app_context():
    db.create_all()"""

def run_command(command, check_success=True, shell=False, ignore_errors=None):
    """Executes a shell command."""
    if isinstance(command, list):
        print(f"\n[EXEC] {' '.join(command)}")
    else:
        print(f"\n[EXEC] {command}")
    
    try:
        result = subprocess.run(
            command,
            check=False,
            shell=shell,
            capture_output=True,
            text=True
        )
        
        # Print output if available
        if result.stdout:
            print(result.stdout.strip())
        
        # Handle errors
        if result.returncode != 0:
            if ignore_errors and ignore_errors in result.stderr:
                print(f"[INFO] Ignored expected error: {ignore_errors.strip()}")
                return True
            
            if result.stderr:
                print(f"[STDERR] {result.stderr.strip()}")
            
            if check_success:
                raise subprocess.CalledProcessError(
                    result.returncode, 
                    command, 
                    output=result.stdout, 
                    stderr=result.stderr
                )
            return False
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Command failed with exit code {e.returncode}")
        if e.stderr:
            print(f"[STDERR] {e.stderr}")
        return False
    except FileNotFoundError:
        print(f"[ERROR] Command not found.")
        return False

def relaunch_app():
    print(f"--- Starting Cryptic Vault Relaunch/Rebuild Process ---")

    # 1. Stop and remove the old container instance
    print("\n--- Step 1: Cleaning up old container ---")
    
    # Stop: Ignore error if container is not running
    run_command(
        ["docker", "stop", CONTAINER_NAME],
        check_success=False,
        ignore_errors="No such container"
    )
    
    # Remove: Ignore error if container is not found
    run_command(
        ["docker", "rm", CONTAINER_NAME],
        check_success=False,
        ignore_errors="No such container"
    )
    
    print(f"[SUCCESS] Old container '{CONTAINER_NAME}' cleaned up.")

    # 2. Delete database files
    print("\n--- Step 2: Deleting database files for clean start ---")
    for db_file in DB_FILES:
        db_path = os.path.join("database", db_file)
        if os.path.exists(db_path):
            os.remove(db_path)
            print(f"[DELETE] Removed {db_path}")
        else:
            print(f"[INFO] {db_path} not found, skipping removal.")

    # 3. Build the new Docker image
    print("\n--- Step 3: Building new Docker image ---")
    if not run_command(["docker", "build", "-t", IMAGE_NAME, "."]):
        print("[CRITICAL] Docker build failed. Cannot proceed.")
        sys.exit(1)
    print(f"[SUCCESS] Image '{IMAGE_NAME}:latest' built successfully.")

    # 4. Initialize the database
    print("\n--- Step 4: Initializing database tables ---")
    db_command = f'docker run --rm {IMAGE_NAME} python -c "{DB_INIT_COMMAND}"'
    if not run_command(db_command, shell=True):
        print("[CRITICAL] Database initialization failed. Cannot proceed.")
        sys.exit(1)
    print(f"[SUCCESS] Database initialized.")

    # 5. Launch the new container instance
    print("\n--- Step 5: Launching new container ---")
    if not run_command([
        "docker", "run", "-d",
        "-p", f"{HOST_PORT}:{CONTAINER_PORT}",
        "--name", CONTAINER_NAME,
        IMAGE_NAME
    ]):
        print("[CRITICAL] Container launch failed.")
        sys.exit(1)

    print(f"\n========================================================")
    print(f"✅ Success! The application is running.")
    print(f"Container: {CONTAINER_NAME}")
    print(f"Image: {IMAGE_NAME}")
    print(f"Access the app at: http://localhost:{HOST_PORT}")
    print(f"========================================================")
    
    # Show container status
    print("\n--- Container Status ---")
    run_command(["docker", "ps", "-f", f"name={CONTAINER_NAME}"], check_success=False)
    
    print("\n--- View logs with: ---")
    print(f"docker logs -f {CONTAINER_NAME}")

if __name__ == "__main__":
    relaunch_app()