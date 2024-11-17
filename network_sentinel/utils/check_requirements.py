import sys
import os
import subprocess
from rich.console import Console

console = Console()

def check_requirements():
    """Check and install missing requirements"""
    try:
        # Update pip
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        
        # Install requirements
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        
        console.print("[green]All requirements installed successfully![/green]")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error installing requirements: {e}[/red]")
        return False

if __name__ == "__main__":
    check_requirements()
