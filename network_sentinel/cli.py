import click
import sys
from rich.console import Console
from .config import NetworkSentinelConfig
from .main import NetworkSentinel

console = Console()

@click.group()
def cli():
    """Network Sentinel - Advanced Network Security Monitoring Tool"""
    pass

@cli.command()
@click.option('--interface', '-i', help='Network interface to monitor')
@click.option('--config', '-c', default='config.yaml', help='Path to config file')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def monitor(interface, config, verbose):
    """Start network monitoring"""
    try:
        # Check dependencies first
        from network_sentinel.utils.security_checks import SecurityChecker
        security = SecurityChecker()
        if not security.verify_dependencies():
            console.print("[red]Error: Required dependencies not satisfied[/red]")
            sys.exit(1)
            
        config = NetworkSentinelConfig.load(config)
        if verbose:
            config.log_level = "DEBUG"
            
        sentinel = NetworkSentinel(config)
        sentinel.start_monitoring(interface)
        
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)

@cli.command()
def list_interfaces():
    """List available network interfaces"""
    NetworkSentinel.list_interfaces() 
