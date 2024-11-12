import signal
import sys
import logging

class GracefulExit:
    def __init__(self, sentinel):
        self.sentinel = sentinel
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, *args):
        logging.info("Shutting down Network Sentinel...")
        self.sentinel.running = False
        self.sentinel.save_state()
        sys.exit(0) 