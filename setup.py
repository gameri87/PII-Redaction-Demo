#!/usr/bin/env python3
"""
Setup script for PII Redaction Demo

This script helps users quickly set up the project environment.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

def main():
    """Main setup function."""
    print("🚀 Setting up PII Redaction Demo...")
    
    # Check if .env exists, if not copy from .env.sample
    if not os.path.exists('.env'):
        if os.path.exists('.env.sample'):
            shutil.copy('.env.sample', '.env')
            print("✅ Created .env from .env.sample")
            print("⚠️  Please edit .env with your actual API credentials")
        else:
            print("❌ .env.sample not found")
            return 1
    else:
        print("✅ .env already exists")
    
    # Check if virtual environment exists
    if not os.path.exists('.venv'):
        print("📦 Creating virtual environment...")
        subprocess.run([sys.executable, '-m', 'venv', '.venv'], check=True)
        print("✅ Virtual environment created")
    else:
        print("✅ Virtual environment already exists")
    
    # Determine python executable path 
    if os.name == 'nt':  # Windows
        python_exe = '.venv/Scripts/python.exe'
        pip_exe = '.venv/Scripts/pip.exe'
    else:  # Unix/Linux/macOS
        python_exe = '.venv/bin/python'
        pip_exe = '.venv/bin/pip'
    
    # Install dependencies
    print("📦 Installing dependencies...")
    try:
        subprocess.run([pip_exe, 'install', '-r', 'requirements.txt'], check=True)
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        return 1
    
    # Test imports
    print("🧪 Testing imports...")
    try:
        subprocess.run([
            python_exe, '-c', 
            'import presidio_analyzer, agent_framework, azure.monitor.opentelemetry; print("All core imports successful")'
        ], check=True, capture_output=True)
        print("✅ All core dependencies can be imported")
    except subprocess.CalledProcessError:
        print("⚠️  Some imports failed, but this might be expected without proper configuration")
    
    print("\n🎉 Setup complete!")
    print(f"\nTo run the demo:")
    print(f"1. Edit .env with your API credentials")
    print(f"2. Run: {python_exe} main.py")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())