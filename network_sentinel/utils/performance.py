from collections import deque
import psutil
import time
import logging

class PerformanceMonitor:
    def __init__(self):
        self.packet_processing_times = deque(maxlen=1000)
        self.memory_usage = deque(maxlen=3600)  # 1 hour of data
        self.cpu_usage = deque(maxlen=3600)
        self.last_check = time.time()
        self.check_interval = 1  # 1 second

    def monitor(self):
        """Monitor system resources"""
        current_time = time.time()
        if current_time - self.last_check < self.check_interval:
            return

        try:
            # CPU Usage
            self.cpu_usage.append(psutil.cpu_percent())

            # Memory Usage
            memory = psutil.Process().memory_info()
            self.memory_usage.append(memory.rss / 1024 / 1024)  # MB

            # Alert on high resource usage
            self._check_alerts()
            
            self.last_check = current_time

        except Exception as e:
            logging.error(f"Performance monitoring error: {e}")

    def _check_alerts(self):
        """Check for performance issues"""
        # CPU alerts
        if len(self.cpu_usage) > 10:
            avg_cpu = sum(list(self.cpu_usage)[-10:]) / 10
            if avg_cpu > 80:
                logging.warning(f"High CPU usage: {avg_cpu:.1f}%")

        # Memory alerts
        if len(self.memory_usage) > 10:
            avg_mem = sum(list(self.memory_usage)[-10:]) / 10
            if avg_mem > 1000:  # 1GB
                logging.warning(f"High memory usage: {avg_mem:.1f}MB")
