import logging
from rich.logging import RichHandler
import os

def setup_logging(config):
    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=config.log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            RichHandler(rich_tracebacks=True),
            logging.FileHandler(f"logs/{config.log_file}")
        ]
    )
    
    # Set specific levels for some modules
    logging.getLogger("scapy").setLevel(logging.WARNING)
    logging.getLogger("matplotlib").setLevel(logging.WARNING) 