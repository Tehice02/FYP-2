"""
Logging utility for NIDS System
Provides centralized logging functionality with file rotation
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from datetime import datetime


class NIDSLogger:
    """Centralized logging system for NIDS"""
    
    def __init__(self, name='NIDS', log_file='logs/nids_system.log', 
                 log_level='INFO', max_bytes=10485760, backup_count=5):
        """
        Initialize logger
        
        Args:
            name: Logger name
            log_file: Path to log file
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            max_bytes: Maximum log file size before rotation
            backup_count: Number of backup files to keep
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Create logs directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # File handler with rotation
        file_handler = RotatingFileHandler(
            log_file, 
            maxBytes=max_bytes, 
            backupCount=backup_count
        )
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler with UTF-8 encoding support
        console_handler = logging.StreamHandler(sys.stdout)
        if hasattr(sys.stdout, 'reconfigure'):
            try:
                sys.stdout.reconfigure(encoding='utf-8', errors='replace')
            except:
                pass
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - [%(levelname)s] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers
        if not self.logger.handlers:
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)
    
    def debug(self, message, component=None):
        """Log debug message"""
        if component:
            message = f"[{component}] {message}"
        self.logger.debug(message)
    
    def info(self, message, component=None):
        """Log info message"""
        if component:
            message = f"[{component}] {message}"
        self.logger.info(message)
    
    def warning(self, message, component=None):
        """Log warning message"""
        if component:
            message = f"[{component}] {message}"
        self.logger.warning(message)
    
    def error(self, message, component=None, exc_info=False):
        """Log error message"""
        if component:
            message = f"[{component}] {message}"
        self.logger.error(message, exc_info=exc_info)
    
    def critical(self, message, component=None, exc_info=False):
        """Log critical message"""
        if component:
            message = f"[{component}] {message}"
        self.logger.critical(message, exc_info=exc_info)


class PerformanceLogger:
    """Logger for performance metrics"""
    
    def __init__(self):
        self.metrics = []
        self.start_times = {}
    
    def start_timer(self, operation_name):
        """Start timing an operation"""
        self.start_times[operation_name] = datetime.now()
    
    def end_timer(self, operation_name):
        """End timing and log duration"""
        if operation_name in self.start_times:
            duration = (datetime.now() - self.start_times[operation_name]).total_seconds()
            self.metrics.append({
                'operation': operation_name,
                'duration': duration,
                'timestamp': datetime.now()
            })
            del self.start_times[operation_name]
            return duration
        return None
    
    def get_average_time(self, operation_name, last_n=100):
        """Get average time for an operation"""
        relevant_metrics = [m for m in self.metrics if m['operation'] == operation_name][-last_n:]
        if relevant_metrics:
            return sum(m['duration'] for m in relevant_metrics) / len(relevant_metrics)
        return 0


# Create global logger instance
nids_logger = NIDSLogger()
performance_logger = PerformanceLogger()


def log_packet_capture(message):
    """Convenience function for packet capture logs"""
    nids_logger.info(message, component='PacketCapture')


def log_ml_prediction(message):
    """Convenience function for ML prediction logs"""
    nids_logger.info(message, component='MLPredictor')


def log_database(message):
    """Convenience function for database logs"""
    nids_logger.info(message, component='Database')


def log_api(message):
    """Convenience function for API logs"""
    nids_logger.info(message, component='API')


def log_error(message, component=None):
    """Convenience function for error logs"""
    nids_logger.error(message, component=component, exc_info=True)
