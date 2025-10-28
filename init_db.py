#!/usr/bin/env python3
"""
Database initialization script for Cryptic Vault
This script creates all database tables and sets up the admin user.
"""

import os
import sys

# Add the parent directory to the path so we can import app
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, setup_admin_user

def init_database():
    """Initialize the database with all tables and admin user."""
    print("=" * 60)
    print("Cryptic Vault - Database Initialization")
    print("=" * 60)
    
    with app.app_context():
        print("\n[1/3] Creating database tables...")
        try:
            db.create_all()
            print("✓ Database tables created successfully")
        except Exception as e:
            print(f"✗ Error creating tables: {e}")
            sys.exit(1)
        
        print("\n[2/3] Setting up admin user...")
        try:
            setup_admin_user()
            print("✓ Admin user setup complete")
        except Exception as e:
            print(f"✗ Error setting up admin user: {e}")
            sys.exit(1)
        
        print("\n[3/3] Verifying database...")
        try:
            from app import User
            admin = User.query.filter_by(username='admin').first()
            if admin:
                print(f"✓ Admin user verified (ID: {admin.id})")
                print(f"  Username: admin")
                print(f"  Password: adminadmin")
            else:
                print("✗ Admin user not found in database")
                sys.exit(1)
        except Exception as e:
            print(f"✗ Error verifying database: {e}")
            sys.exit(1)
    
    print("\n" + "=" * 60)
    print("✅ Database initialization complete!")
    print("=" * 60)
    print("\nYou can now start the application with: python app.py")
    print("Or run the Docker container.\n")

if __name__ == "__main__":
    init_database()