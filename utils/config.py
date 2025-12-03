"""
Configuration file for NIDS System
Enhanced Predictive Classification of Cyber Security Threats Using Machine Learning
Author: RASSYIDZ
University: Universiti Kuala Lumpur - FYP2
"""

import os

class Config:
    """Main configuration class for NIDS system"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'nids-fyp2-secret-key-2025'
    DEBUG = False
    HOST = '0.0.0.0'
    PORT = 5000
    
    # Database Configuration
    DATABASE_PATH = 'database/nids.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Network Capture Configuration
    DEFAULT_INTERFACE = 'eth0'
    PACKET_QUEUE_SIZE = 1000
    FLOW_TIMEOUT = 2  # seconds - very fast processing for demo
    FLOW_MAX_PACKETS = 5  # very small flows for more frequent updates
    
    # ML Model Configuration
    BINARY_MODEL_PATH = 'models/model_files/xgboost_binary.pkl'
    MULTICLASS_MODEL_PATH = 'models/model_files/xgboost_multiclass.pkl'
    SCALER_PATH = 'models/model_files/scaler.pkl'
    
    # Feature Configuration
    NUM_FEATURES = 34
    FEATURE_NAMES = [
        'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
        'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sintpkt',
        'dintpkt', 'sjit', 'djit', 'swin', 'dwin', 'stcpb', 'dtcpb', 'tcprtt',
        'synack', 'ackdat', 'smean', 'dmean', 'trans_depth', 'response_body_len',
        'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm'
    ]
    
    # Attack Type Mapping
    ATTACK_TYPES = [
        'Analysis', 'Backdoor', 'DoS', 'Exploits', 
        'Fuzzers', 'Generic', 'Reconnaissance', 
        'Shellcode', 'Worms', 'Benign'
    ]
    
    # Severity Thresholds
    CONFIDENCE_CRITICAL = 0.95
    CONFIDENCE_HIGH = 0.85
    CONFIDENCE_MEDIUM = 0.70
    
    # Critical Attack Types
    CRITICAL_ATTACKS = ['DoS', 'Exploits', 'Backdoor']
    HIGH_RISK_ATTACKS = ['Reconnaissance', 'Analysis', 'Fuzzers']
    
    # Port Classification
    CRITICAL_PORTS = [22, 23, 3389, 445, 1433, 3306, 5432]  # SSH, Telnet, RDP, SMB, MSSQL, MySQL, PostgreSQL
    COMMON_SERVICES = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 3306: 'MYSQL', 3389: 'RDP',
        5432: 'POSTGRESQL', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT'
    }
    
    # Performance Configuration
    MAX_ALERTS_IN_MEMORY = 1000
    MAX_HISTORICAL_DAYS = 30
    STATS_UPDATE_INTERVAL = 5  # seconds
    
    # WebSocket Configuration
    SOCKETIO_CORS_ALLOWED_ORIGINS = "*"
    SOCKETIO_ASYNC_MODE = 'threading'
    
    # Logging Configuration
    LOG_LEVEL = 'INFO'
    LOG_FILE = 'logs/nids_system.log'
    LOG_MAX_BYTES = 10485760  # 10MB
    LOG_BACKUP_COUNT = 5
    
    # Model Performance Monitoring
    DRIFT_DETECTION_ENABLED = True
    DRIFT_WINDOW_SIZE = 1000
    DRIFT_THRESHOLD = 0.10
    BASELINE_ACCURACY = 0.987
    
    # Alert Settings
    ENABLE_AUTO_RESPONSE = False
    ENABLE_EMAIL_ALERTS = False
    EMAIL_RECIPIENTS = []
    
    @staticmethod
    def get_severity(confidence, attack_type):
        """Calculate severity level based on confidence and attack type"""
        if confidence >= Config.CONFIDENCE_CRITICAL:
            if attack_type in Config.CRITICAL_ATTACKS:
                return 'CRITICAL'
            elif attack_type in Config.HIGH_RISK_ATTACKS:
                return 'HIGH'
            else:
                return 'MEDIUM'
        elif confidence >= Config.CONFIDENCE_HIGH:
            if attack_type in Config.CRITICAL_ATTACKS:
                return 'HIGH'
            else:
                return 'MEDIUM'
        elif confidence >= Config.CONFIDENCE_MEDIUM:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    @staticmethod
    def get_service_name(port):
        """Get service name from port number"""
        return Config.COMMON_SERVICES.get(port, 'UNKNOWN')
    
    @staticmethod
    def is_critical_port(port):
        """Check if port is critical"""
        return port in Config.CRITICAL_PORTS


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DATABASE_PATH = 'database/test_nids.db'


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
