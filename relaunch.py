import subprocess
import os
import sys
import time

# --- Configuration ---
IMAGE_NAME = "cryptic-vault"
CONTAINER_NAME = "honeypot-instance"
DB_FILES = ["users.db", "honeypot_logs.db"]
HOST_PORT = 5000
CONTAINER_PORT = 5000

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
            if ignore_errors:
                error_messages = ignore_errors if isinstance(ignore_errors, list) else [ignore_errors]
                for error_msg in error_messages:
                    if error_msg in result.stderr:
                        print(f"[INFO] Ignored expected error: {error_msg.strip()}")
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
        print(f"[ERROR] Command not found. Make sure Docker is installed.")
        return False

def relaunch_app():
    # Check for command-line arguments
    FRESH_START = "--fresh" in sys.argv
    
    print("=" * 70)
    print("    Cryptic Vault - Relaunch/Rebuild Process")
    if FRESH_START:
        print("    MODE: Fresh Start (databases will be reset)")
    else:
        print("    MODE: Persistent (databases will be preserved)")
    print("=" * 70)

    # 1. Stop and remove the old container instance
    print("\n[Step 1/5] Cleaning up old container...")
    
    # Stop container (ignore if not running)
    run_command(
        ["docker", "stop", CONTAINER_NAME],
        check_success=False,
        ignore_errors=["No such container", "is not running"]
    )
    
    # Remove container (ignore if not found)
    run_command(
        ["docker", "rm", CONTAINER_NAME],
        check_success=False,
        ignore_errors=["No such container", "Error: No such container"]
    )
    
    print("✓ Old container cleaned up.")

    # 2. Conditionally handle database files based on mode
    if FRESH_START:
        print(f"\n[Step 2/5] Deleting database files (fresh start mode)...")
        for db_file in DB_FILES:
            db_path = os.path.join("database", db_file)
            if os.path.exists(db_path):
                os.remove(db_path)
                print(f"  ✓ Removed {db_path}")
            else:
                print(f"  - {db_path} not found (skipping)")
        print("✓ Fresh start - databases cleared.")
    else:
        print(f"\n[Step 2/5] Preserving existing database files...")
        db_exists = False
        for db_file in DB_FILES:
            db_path = os.path.join("database", db_file)
            if os.path.exists(db_path):
                file_size = os.path.getsize(db_path)
                print(f"  ✓ Found {db_path} ({file_size} bytes)")
                db_exists = True
            else:
                print(f"  - {db_path} not found (will be created on first run)")
        
        if db_exists:
            print("✓ Existing databases will persist across this relaunch.")
        else:
            print("✓ No existing databases found - fresh databases will be created.")
        print("\n  💡 TIP: Use 'python relaunch.py --fresh' to reset databases")

    # Ensure database directory exists
    os.makedirs("database", exist_ok=True)
    print("✓ Database directory ready.")

    # 3. Build the new Docker image
    print(f"\n[Step 3/5] Building Docker image '{IMAGE_NAME}'...")
    if not run_command(["docker", "build", "-t", IMAGE_NAME, "."]):
        print("\n❌ CRITICAL: Docker build failed. Cannot proceed.")
        print("   Check your Dockerfile and requirements.txt")
        sys.exit(1)
    print(f"✓ Image '{IMAGE_NAME}:latest' built successfully.")

    # 4. Launch the new container with volume mount
    print(f"\n[Step 4/5] Launching container '{CONTAINER_NAME}'...")
    
    # Get absolute path to database directory
    db_abs_path = os.path.abspath("database")
    
    # Also mount static/data if it exists
    static_data_path = os.path.abspath("static/data")
    
    # Build the docker run command properly
    docker_run_cmd = [
        "docker", "run", "-d",
        "-p", f"{HOST_PORT}:{CONTAINER_PORT}",
        "-v", f"{db_abs_path}:/app/database"
    ]
    
    # Add static data mount if directory exists
    if os.path.exists(static_data_path):
        docker_run_cmd.extend(["-v", f"{static_data_path}:/app/static/data"])
        print(f"  ℹ️  Mounting static data directory: {static_data_path}")
    
    # Add container name and image at the end
    docker_run_cmd.extend(["--name", CONTAINER_NAME, IMAGE_NAME])
    
    print(f"  ℹ️  Mounting database directory: {db_abs_path}")
    
    if not run_command(docker_run_cmd):
        print("\n❌ CRITICAL: Container launch failed.")
        sys.exit(1)

    print(f"✓ Container launched with persistent volume mounts.")
    
    # 5. Wait for application to initialize
    print(f"\n[Step 5/5] Waiting for application to initialize...")
    time.sleep(5)
    
    # Check if container is still running
    result = subprocess.run(
        ["docker", "ps", "-q", "-f", f"name={CONTAINER_NAME}"],
        capture_output=True,
        text=True
    )
    
    if not result.stdout.strip():
        print("\n❌ ERROR: Container failed to start or exited immediately.")
        print("\n--- Container Logs ---")
        run_command(["docker", "logs", CONTAINER_NAME], check_success=False)
        print("\n--- Troubleshooting ---")
        print("1. Check if all dependencies are in requirements.txt")
        print("2. Verify honeypot_logger.py exists and is importable")
        print("3. Check for syntax errors in app.py")
        sys.exit(1)

    print("✓ Application started successfully.")

    # Success message
    print("\n" + "=" * 70)
    print("✅ SUCCESS! The Cryptic Vault is now running.")
    print("=" * 70)
    print(f"\n📍 Access the application:")
    print(f"   http://localhost:{HOST_PORT}")
    print(f"\n🔐 Admin credentials:")
    print(f"   Username: admin")
    print(f"   Password: adminadmin")
    print(f"\n📊 Container info:")
    print(f"   Name: {CONTAINER_NAME}")
    print(f"   Image: {IMAGE_NAME}")
    
    # Show persistence status
    if FRESH_START:
        print(f"\n⚠️  Mode: Fresh Start (all previous data cleared)")
    else:
        print(f"\n💾 Mode: Persistent (data preserved across relaunches)")
    
    # Show container status
    print("\n--- Container Status ---")
    run_command(["docker", "ps", "-f", f"name={CONTAINER_NAME}"], check_success=False)
    
    # Show initial logs
    print("\n--- Initial Application Logs ---")
    run_command(["docker", "logs", "--tail", "15", CONTAINER_NAME], check_success=False)
    
    # Helpful commands
    print("\n--- Useful Commands ---")
    print(f"📋 View live logs:     docker logs -f {CONTAINER_NAME}")
    print(f"🛑 Stop container:     docker stop {CONTAINER_NAME}")
    print(f"🔄 Restart container:  docker restart {CONTAINER_NAME}")
    print(f"🐚 Access shell:       docker exec -it {CONTAINER_NAME} /bin/bash")
    print(f"🗑️  Remove container:   docker rm -f {CONTAINER_NAME}")
    print(f"🔍 Check databases:    ls -lh ./database/")
    print(f"📊 Query users:        sqlite3 ./database/users.db 'SELECT username FROM user;'")
    
    # Show persistence commands
    print("\n--- Persistence Commands ---")
    print(f"♻️  Fresh start:        python relaunch.py --fresh")
    print(f"💾 Persistent mode:    python relaunch.py (default)")
    print(f"📦 Backup databases:   cp -r ./database ./database_backup")
    print(f"📥 Restore backup:     rm -rf ./database && mv ./database_backup ./database")
    print("\n")

def show_help():
    """Display help information"""
    print("=" * 70)
    print("    Cryptic Vault - Relaunch Script Help")
    print("=" * 70)
    print("\nUsage:")
    print("  python relaunch.py          - Relaunch with persistent databases")
    print("  python relaunch.py --fresh  - Relaunch with fresh databases (reset)")
    print("  python relaunch.py --help   - Show this help message")
    print("\nPersistence:")
    print("  By default, databases are preserved across relaunches.")
    print("  Use --fresh flag to completely reset all data.")
    print("\nDatabase Files:")
    for db_file in DB_FILES:
        print(f"  - ./database/{db_file}")
    print("\nExamples:")
    print("  # Normal relaunch (keeps all data)")
    print("  python relaunch.py")
    print()
    print("  # Fresh start (deletes all users, logs, orders)")
    print("  python relaunch.py --fresh")
    print("\n")

if __name__ == "__main__":
    try:
        # Check for help flag
        if "--help" in sys.argv or "-h" in sys.argv:
            show_help()
            sys.exit(0)
        
        relaunch_app()
    except KeyboardInterrupt:
        print("\n\n⚠️  Process interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)