"""
Database Manager for NIDS System
Handles all database operations including alerts, statistics, and logs
"""

import sqlite3
import json
import time
from datetime import datetime, timedelta
from contextlib import contextmanager
from utils.logger import nids_logger, log_database, log_error


class DatabaseManager:
    """Manages all database operations for NIDS"""
    
    def __init__(self, db_path='database/nids.db'):
        """Initialize database manager"""
        self.db_path = db_path
        self.connection = None
        log_database(f"Database manager initialized with path: {db_path}")
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            log_error(f"Database error: {str(e)}", component='Database')
            raise
        finally:
            conn.close()
    
    def initialize_database(self):
        """Create all necessary tables"""
        log_database("Initializing database schema...")
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip VARCHAR(45) NOT NULL,
                    dst_ip VARCHAR(45) NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol VARCHAR(10),
                    attack_type VARCHAR(50),
                    attack_category VARCHAR(50),
                    confidence_score FLOAT,
                    binary_prediction INTEGER,
                    multiclass_prediction INTEGER,
                    feature_vector TEXT,
                    packet_summary TEXT,
                    severity VARCHAR(20),
                    is_false_positive BOOLEAN DEFAULT 0,
                    notes TEXT
                )
            ''')
            
            # Statistics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date DATE DEFAULT CURRENT_DATE,
                    total_packets INTEGER DEFAULT 0,
                    total_flows INTEGER DEFAULT 0,
                    benign_count INTEGER DEFAULT 0,
                    attack_count INTEGER DEFAULT 0,
                    dos_count INTEGER DEFAULT 0,
                    reconnaissance_count INTEGER DEFAULT 0,
                    exploits_count INTEGER DEFAULT 0,
                    backdoor_count INTEGER DEFAULT 0,
                    analysis_count INTEGER DEFAULT 0,
                    fuzzers_count INTEGER DEFAULT 0,
                    shellcode_count INTEGER DEFAULT 0,
                    generic_count INTEGER DEFAULT 0,
                    worms_count INTEGER DEFAULT 0,
                    avg_confidence FLOAT,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # System logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    log_level VARCHAR(20),
                    component VARCHAR(50),
                    message TEXT,
                    details TEXT
                )
            ''')
            
            # Model performance table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS model_performance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    model_name VARCHAR(50),
                    accuracy FLOAT,
                    precision_score FLOAT,
                    recall_score FLOAT,
                    f1_score FLOAT,
                    inference_time_ms FLOAT,
                    samples_evaluated INTEGER
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_statistics_date ON statistics(date)')
            
            # Initialize today's statistics if not exists
            cursor.execute('''
                INSERT OR IGNORE INTO statistics (date) 
                VALUES (date('now'))
            ''')
            
            conn.commit()
            log_database("Database schema initialized successfully")
    
    def insert_alert(self, alert_data):
        """
        Insert new alert into database
        
        Args:
            alert_data: Dictionary containing alert information
            
        Returns:
            Alert ID
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO alerts (
                        timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                        attack_type, attack_category, confidence_score, 
                        binary_prediction, multiclass_prediction,
                        feature_vector, packet_summary, severity
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.fromtimestamp(float(alert_data.get('timestamp', time.time()))),
                    alert_data.get('src_ip'),
                    alert_data.get('dst_ip'),
                    alert_data.get('src_port'),
                    alert_data.get('dst_port'),
                    alert_data.get('protocol'),
                    alert_data.get('attack_type'),
                    self._get_attack_category(alert_data.get('attack_type')),
                    alert_data.get('confidence_score'),
                    alert_data.get('binary_prediction', 1),
                    alert_data.get('multiclass_prediction'),
                    json.dumps(alert_data.get('features', [])),
                    alert_data.get('packet_summary', ''),
                    alert_data.get('severity', 'MEDIUM')
                ))
                
                alert_id = cursor.lastrowid
                log_database(f"Alert inserted with ID: {alert_id}")
                return alert_id
                
        except Exception as e:
            log_error(f"Failed to insert alert: {str(e)}", component='Database')
            return None
    
    def get_recent_alerts(self, limit=50, offset=0, hours_back=24):
        """
        Get recent alerts from database, optionally filtered by time window
        
        Args:
            limit: Max number of alerts to return
            offset: Offset for pagination
            hours_back: Only return alerts from the last N hours (default 24)
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Filter by time window to exclude stale data
                time_filter = f"datetime(timestamp) >= datetime('now', '-{hours_back} hours')"
                
                cursor.execute(f'''
                    SELECT * FROM alerts 
                    WHERE {time_filter}
                    ORDER BY timestamp DESC 
                    LIMIT ? OFFSET ?
                ''', (limit, offset))
                
                rows = cursor.fetchall()
                alerts = [dict(row) for row in rows]
                
                # Convert timestamp to Unix timestamp (seconds since epoch) for frontend
                for alert in alerts:
                    if alert['timestamp']:
                        try:
                            # Parse datetime string and convert to Unix timestamp
                            if isinstance(alert['timestamp'], str):
                                dt = datetime.fromisoformat(alert['timestamp'])
                            else:
                                dt = alert['timestamp']
                            alert['timestamp'] = dt.timestamp()
                        except:
                            alert['timestamp'] = time.time()
                    # Ensure confidence_score is between 0-100
                    if 'confidence_score' in alert and alert['confidence_score']:
                        score = float(alert['confidence_score'])
                        if score > 100:
                            alert['confidence_score'] = min(score, 100.0)
                
                return alerts
                
        except Exception as e:
            log_error(f"Failed to get recent alerts: {str(e)}", component='Database')
            return []
    
    def get_alerts_by_filter(self, filters):
        """
        Get alerts with filters
        
        Args:
            filters: Dictionary with filter criteria (src_ip, dst_ip, attack_type, date_from, date_to, severity)
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM alerts WHERE 1=1"
                params = []
                
                if filters.get('src_ip'):
                    query += " AND src_ip = ?"
                    params.append(filters['src_ip'])
                
                if filters.get('dst_ip'):
                    query += " AND dst_ip = ?"
                    params.append(filters['dst_ip'])
                
                if filters.get('attack_type'):
                    query += " AND attack_type = ?"
                    params.append(filters['attack_type'])
                
                if filters.get('severity'):
                    query += " AND severity = ?"
                    params.append(filters['severity'])
                
                if filters.get('date_from'):
                    query += " AND timestamp >= ?"
                    params.append(filters['date_from'])
                
                if filters.get('date_to'):
                    query += " AND timestamp <= ?"
                    params.append(filters['date_to'])
                
                query += " ORDER BY timestamp DESC LIMIT 1000"
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                alerts = [dict(row) for row in rows]
                for alert in alerts:
                    if alert['timestamp']:
                        alert['timestamp'] = str(alert['timestamp'])
                
                return alerts
                
        except Exception as e:
            log_error(f"Failed to get filtered alerts: {str(e)}", component='Database')
            return []
    
    def update_statistics(self, attack_type=None):
        """Update statistics for today"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get or create today's statistics
                cursor.execute('''
                    INSERT OR IGNORE INTO statistics (date) 
                    VALUES (date('now'))
                ''')
                
                # Increment counters
                if attack_type and attack_type != 'Benign':
                    cursor.execute('''
                        UPDATE statistics 
                        SET attack_count = attack_count + 1,
                            total_flows = total_flows + 1,
                            last_updated = CURRENT_TIMESTAMP
                        WHERE date = date('now')
                    ''')
                    
                    # Increment specific attack type counter
                    column_name = f"{attack_type.lower()}_count"
                    try:
                        cursor.execute(f'''
                            UPDATE statistics 
                            SET {column_name} = {column_name} + 1
                            WHERE date = date('now')
                        ''')
                    except:
                        pass  # Column might not exist
                        
                else:
                    cursor.execute('''
                        UPDATE statistics 
                        SET benign_count = benign_count + 1,
                            total_flows = total_flows + 1,
                            last_updated = CURRENT_TIMESTAMP
                        WHERE date = date('now')
                    ''')
                
                conn.commit()
                
        except Exception as e:
            log_error(f"Failed to update statistics: {str(e)}", component='Database')
    
    def get_statistics(self, days=1):
        """Get statistics for last N days"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM statistics 
                    WHERE date >= date('now', ? || ' days')
                    ORDER BY date DESC
                ''', (f'-{days}',))
                
                rows = cursor.fetchall()
                stats = [dict(row) for row in rows]
                
                return stats
                
        except Exception as e:
            log_error(f"Failed to get statistics: {str(e)}", component='Database')
            return []
    
    def get_alert_count_today(self):
        """Get total alert count (all alerts with predictions)"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Count all alerts in database
                cursor.execute('''
                    SELECT COUNT(*) as count FROM alerts
                ''')
                
                result = cursor.fetchone()
                return result['count'] if result else 0
                
        except Exception as e:
            log_error(f"Failed to get alert count: {str(e)}", component='Database')
            return 0
    
    def clear_alerts(self):
        """Clear all alerts from database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM alerts')
                conn.commit()
                log_database("All alerts cleared from database")
                return True
        except Exception as e:
            log_error(f"Failed to clear alerts: {str(e)}", component='Database')
            return False
    
    def clear_old_data(self, days=30):
        """Clear data older than N days"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cutoff_date = datetime.now() - timedelta(days=days)
                
                cursor.execute('DELETE FROM alerts WHERE timestamp < ?', (cutoff_date,))
                cursor.execute('DELETE FROM statistics WHERE date < ?', (cutoff_date.date(),))
                cursor.execute('DELETE FROM system_logs WHERE timestamp < ?', (cutoff_date,))
                
                conn.commit()
                log_database(f"Cleared data older than {days} days")
                return True
                
        except Exception as e:
            log_error(f"Failed to clear old data: {str(e)}", component='Database')
            return False
    
    def _get_attack_category(self, attack_type):
        """Map attack type to category"""
        categories = {
            'DoS': 'Denial of Service',
            'Reconnaissance': 'Information Gathering',
            'Exploits': 'Exploitation',
            'Backdoor': 'Persistence',
            'Analysis': 'Analysis',
            'Fuzzers': 'Fuzzing',
            'Shellcode': 'Code Execution',
            'Generic': 'Generic Attack',
            'Worms': 'Malware'
        }
        return categories.get(attack_type, 'Unknown')
    
    def get_attack_distribution(self):
        """Get attack type distribution for last 24 hours"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT attack_type, COUNT(*) as count 
                    FROM alerts 
                    WHERE datetime(timestamp) >= datetime('now', '-24 hours')
                    GROUP BY attack_type
                    ORDER BY count DESC
                ''')
                
                rows = cursor.fetchall()
                distribution = {row['attack_type']: row['count'] for row in rows}
                
                return distribution
                
        except Exception as e:
            log_error(f"Failed to get attack distribution: {str(e)}", component='Database')
            return {}
    
    def export_alerts_csv(self, filename='alerts_export.csv'):
        """Export alerts to CSV file"""
        try:
            import csv
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC')
                
                rows = cursor.fetchall()
                
                if not rows:
                    return None
                
                # Write to CSV
                with open(filename, 'w', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=rows[0].keys())
                    writer.writeheader()
                    for row in rows:
                        writer.writerow(dict(row))
                
                log_database(f"Alerts exported to {filename}")
                return filename
                
        except Exception as e:
            log_error(f"Failed to export alerts: {str(e)}", component='Database')
            return None
