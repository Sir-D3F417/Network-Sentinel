from collections import deque

class PerformanceMonitor:
    def __init__(self):
        self.packet_processing_times = deque(maxlen=1000)
        self.memory_usage = []
        self.cpu_usage = []
        
    def monitor(self):
        """Monitor system resources"""
        # Track resource usage
        # Alert on performance issues
        # Optimize packet processing 