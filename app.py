"""
Main Flask Application for NIDS
Enhanced Predictive Classification of Cyber Security Threats Using Machine Learning
Author: RASSYIDZ - Universiti Kuala Lumpur FYP2
"""

from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import time
from datetime import datetime
import os

# Import NIDS components
from models.packet_capture import PacketCaptureEngine
from models.ml_predictor import MLPredictor, ModelDriftDetector
from database.db_manager import DatabaseManager
from utils.config import Config, config
from utils.logger import nids_logger, log_api, log_error

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY
app.config.from_object(config['development'])
CORS(app)

# Initialize SocketIO
socketio = SocketIO(
    app,
    cors_allowed_origins=Config.SOCKETIO_CORS_ALLOWED_ORIGINS,
    async_mode=Config.SOCKETIO_ASYNC_MODE
)

# Global instances
db_manager = DatabaseManager(Config.DATABASE_PATH)
ml_predictor = MLPredictor()
drift_detector = ModelDriftDetector()
capture_engine = None
monitoring_thread = None
is_monitoring = False

# Statistics
system_stats = {
    'total_packets': 0,
    'total_alerts': 0,
    'start_time': None
}


def initialize_system():
    """Initialize the NIDS system"""
    global capture_engine, is_monitoring

    log_api("Initializing NIDS system...")

    # Reset monitoring state
    is_monitoring = False
    capture_engine = None

    # Initialize database
    db_manager.initialize_database()
    log_api("[OK] Database initialized")

    # Clean up corrupted/old alerts from database
    cleanup_corrupted_data()
    log_api("[OK] Cleaned up corrupted/old alerts")

    # Load ML models
    if ml_predictor.load_models():
        log_api("[OK] ML models loaded")
    else:
        log_error("Failed to load ML models", component='App')

    log_api("[OK] NIDS system initialized successfully")


def cleanup_corrupted_data():
    """Remove obviously corrupted alerts and old stale data from database on startup"""
    try:
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()

            # Remove alerts with confidence > 100 (impossible)
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE confidence_score > 100")
            bad_confidence_count = cursor.fetchone()[0]
            if bad_confidence_count > 0:
                cursor.execute("DELETE FROM alerts WHERE confidence_score > 100")
                log_api(f"Removed {bad_confidence_count} alerts with impossible confidence (>100%)")

            # Remove alerts with timestamps in the future (> now + 1 hour)
            future_threshold = time.time() + 3600
            cursor.execute("""
                SELECT COUNT(*) FROM alerts 
                WHERE datetime(timestamp) > datetime('now', '+1 hour')
            """)
            future_count = cursor.fetchone()[0]
            if future_count > 0:
                cursor.execute("""
                    DELETE FROM alerts 
                    WHERE datetime(timestamp) > datetime('now', '+1 hour')
                """)
                log_api(f"Removed {future_count} alerts with future timestamps")

            # Remove alerts with timestamps older than 24 hours (stale data)
            cursor.execute("""
                SELECT COUNT(*) FROM alerts 
                WHERE datetime(timestamp) < datetime('now', '-24 hours')
            """)
            stale_count = cursor.fetchone()[0]
            if stale_count > 0:
                cursor.execute("""
                    DELETE FROM alerts 
                    WHERE datetime(timestamp) < datetime('now', '-24 hours')
                """)
                log_api(f"Removed {stale_count} stale alerts (older than 24 hours)")

            conn.commit()
            log_api(f"Database cleanup complete. Remaining alerts: {cursor.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]}")

    except Exception as e:
        log_error(f"Error during database cleanup: {str(e)}", component='App')


# ============================================================================
# WEB ROUTES
# ============================================================================

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/historical')
def historical():
    """Historical logs page"""
    return render_template('historical.html')


# ============================================================================
# API ROUTES - MONITORING CONTROL
# ============================================================================

@app.route('/api/interfaces', methods=['GET'])
def get_available_interfaces():
    """Get list of available network interfaces"""
    try:
        import platform
        from scapy.all import get_if_list
        
        interfaces = get_if_list()
        
        # On Windows, Scapy returns GUIDs. Try to get friendly names.
        if platform.system() == 'Windows':
            try:
                import subprocess
                import json
                # Use PowerShell to get friendly interface names
                ps_cmd = "Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -Property Name | ConvertTo-Json"
                result = subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    try:
                        adapters = json.loads(result.stdout)
                        if isinstance(adapters, list):
                            friendly_names = [a['Name'] for a in adapters if 'Name' in a]
                        else:
                            friendly_names = [adapters['Name']] if 'Name' in adapters else []
                        if friendly_names:
                            return jsonify({
                                'status': 'success',
                                'interfaces': friendly_names
                            })
                    except:
                        pass
            except Exception as e:
                log_error(f"Error getting Windows adapters: {str(e)}", component='App')
            
            # Fallback: filter out loopback and empty interfaces from GUIDs
            filtered = [iface for iface in interfaces if iface and not iface.startswith('lo') and not iface.startswith('\\')]
            if not filtered:
                filtered = interfaces
        else:
            # Linux/Mac: filter out loopback
            filtered = [iface for iface in interfaces if iface and not iface.startswith('lo')]
            if not filtered:
                filtered = interfaces
        
        return jsonify({
            'status': 'success',
            'interfaces': filtered
        })
    except Exception as e:
        log_error(f"Error getting interfaces: {str(e)}", component='App')
        return jsonify({
            'status': 'error',
            'interfaces': [],
            'message': str(e)
        }), 500


@app.route('/api/monitoring/start', methods=['POST'])
def start_monitoring():
    """Start network monitoring with real packet capture"""
    global capture_engine, monitoring_thread, is_monitoring
    
    try:
        if is_monitoring:
            return jsonify({
                'status': 'error',
                'message': 'Monitoring already active'
            }), 400
        
        data = request.get_json() or {}
        interface = data.get('interface', Config.DEFAULT_INTERFACE)
        
        log_api(f"Starting real-time monitoring on interface: {interface}")
        
        # Use real packet capture
        try:
            capture_engine = PacketCaptureEngine(
                interface=interface,
                on_prediction_callback=handle_prediction
            )
            capture_engine.start_capture()
        except Exception as e:
                log_error(f"Failed to start capture: {str(e)}", component='App')
                return jsonify({
                    'status': 'error',
                    'message': f'Failed to start capture: {str(e)}. Make sure interface exists and run with admin privileges.'
                }), 500
        
        is_monitoring = True
        system_stats['start_time'] = time.time()
        
        # Start system status broadcast
        start_status_broadcast()
        
        return jsonify({
            'status': 'success',
            'message': 'Monitoring started successfully'
        })
    
    except Exception as e:
        log_error(f"Error starting monitoring: {str(e)}", component='App')
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/monitoring/stop', methods=['POST'])
def stop_monitoring():
    """Stop network monitoring"""
    global capture_engine, is_monitoring
    
    try:
        log_api("Stop monitoring request received")
        
        if not is_monitoring:
            log_api("Monitoring not active, returning error")
            return jsonify({
                'status': 'error',
                'message': 'Monitoring not active'
            }), 400
        
        log_api("Stopping monitoring...")
        
        # Stop capture engine gracefully with extra protection
        if capture_engine:
            try:
                log_api("Stopping capture engine...")
                capture_engine.stop_capture()
                log_api("Capture engine stopped successfully")
            except Exception as e:
                log_error(f"Error while stopping capture engine: {str(e)}", component='App')
                # Continue anyway - don't let capture engine errors crash the app
            finally:
                try:
                    capture_engine = None
                    log_api("Capture engine reference cleared")
                except Exception as e:
                    log_error(f"Error clearing capture engine: {str(e)}", component='App')

        is_monitoring = False
        log_api("Monitoring flag set to False")

        # Prepare response first
        response_data = {
            'status': 'success',
            'message': 'Monitoring stopped successfully'
        }
        log_api("Preparing response...")
        
        # Create response object
        response = jsonify(response_data)
        log_api("Response created successfully")
        
        # Emit socket events with extra protection
        def emit_stop_events():
            try:
                log_api("Emitting stop events...")
                socketio.emit('monitoring_stopped', {'timestamp': time.time()})
                log_api("monitoring_stopped event emitted")
                
                # Get alert count safely
                alert_count = 0
                try:
                    if db_manager:
                        alert_count = db_manager.get_alert_count_today()
                except Exception as e:
                    log_error(f"Error getting alert count: {str(e)}", component='App')
                
                # Emit system status update
                status_data = {
                    'is_running': False,
                    'packet_rate': 0,
                    'total_flows': 0,
                    'alert_count': alert_count,
                    'total_packets': 0,
                    'total_alerts': system_stats.get('total_alerts', 0),
                    'timestamp': time.time()
                }
                socketio.emit('system_status_update', status_data)
                log_api("system_status_update event emitted")
                log_api("Stop events emitted successfully")
            except Exception as e:
                log_error(f"Error emitting stop events: {str(e)}", component='App')
                # Don't re-raise - this shouldn't crash the app
        
        # Emit events in a thread to prevent blocking - with timeout protection
        try:
            log_api("Starting emit thread...")
            emit_thread = threading.Thread(target=emit_stop_events, daemon=True)
            emit_thread.start()
            log_api("Emit thread started")
        except Exception as e:
            log_error(f"Error starting emit thread: {str(e)}", component='App')
        
        log_api("Stop monitoring completed successfully")
        return response
    
    except Exception as e:
        log_error(f"CRITICAL ERROR in stop_monitoring: {str(e)}", component='App')
        # Log the full traceback for debugging
        import traceback
        log_error(f"Traceback: {traceback.format_exc()}", component='App')
        try:
            return jsonify({
                'status': 'error',
                'message': f'Error stopping monitoring: {str(e)}'
            }), 500
        except Exception as response_error:
            log_error(f"Error creating error response: {str(response_error)}", component='App')
            # If we can't even return an error response, something is very wrong
            return "Error", 500


@app.route('/api/monitoring/status', methods=['GET'])
def get_monitoring_status():
    """Get current monitoring status"""
    status = {
        'is_running': is_monitoring,
        'mode': 'real',
        'uptime': time.time() - system_stats['start_time'] if system_stats['start_time'] else 0,
        'total_packets': system_stats['total_packets'],
        'total_alerts': system_stats['total_alerts']
    }
    
    if capture_engine and is_monitoring:
        status.update(capture_engine.get_statistics())
    
    return jsonify({
        'status': 'success',
        'data': status
    })


# ============================================================================
# API ROUTES - ALERTS
# ============================================================================

@app.route('/api/alerts/recent', methods=['GET'])
def get_recent_alerts():
    """Get recent alerts"""
    try:
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        alerts = db_manager.get_recent_alerts(limit, offset)
        
        return jsonify({
            'status': 'success',
            'data': alerts,
            'count': len(alerts)
        })
    
    except Exception as e:
        log_error(f"Error getting alerts: {str(e)}", component='App')
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/alerts/filter', methods=['POST'])
def get_filtered_alerts():
    """Get filtered alerts"""
    try:
        filters = request.get_json() or {}
        alerts = db_manager.get_alerts_by_filter(filters)
        
        return jsonify({
            'status': 'success',
            'data': alerts,
            'count': len(alerts)
        })
    
    except Exception as e:
        log_error(f"Error filtering alerts: {str(e)}", component='App')
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/alerts/clear', methods=['POST'])
def clear_alerts():
    """Clear all alerts"""
    try:
        db_manager.clear_alerts()
        system_stats['total_alerts'] = 0
        
        # Notify clients
        socketio.emit('alerts_cleared', {})
        
        return jsonify({
            'status': 'success',
            'message': 'All alerts cleared'
        })
    
    except Exception as e:
        log_error(f"Error clearing alerts: {str(e)}", component='App')
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/cleanup/corrupted', methods=['POST'])
def manual_cleanup_corrupted():
    """Manually cleanup corrupted data (called on-demand)"""
    try:
        cleanup_corrupted_data()
        return jsonify({
            'status': 'success',
            'message': 'Database cleanup completed'
        })
    except Exception as e:
        log_error(f"Error during manual cleanup: {str(e)}", component='App')
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/alerts/count', methods=['GET'])
def get_alert_count():
    """Get alert count for today"""
    try:
        count = db_manager.get_alert_count_today()
        
        return jsonify({
            'status': 'success',
            'data': {'count': count}
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ============================================================================
# API ROUTES - STATISTICS
# ============================================================================

@app.route('/api/statistics/summary', methods=['GET'])
def get_statistics_summary():
    """Get statistics summary"""
    try:
        days = request.args.get('days', 1, type=int)
        stats = db_manager.get_statistics(days)
        distribution = db_manager.get_attack_distribution()
        
        return jsonify({
            'status': 'success',
            'data': {
                'statistics': stats,
                'distribution': distribution
            }
        })
    
    except Exception as e:
        log_error(f"Error getting statistics: {str(e)}", component='App')
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/statistics/distribution', methods=['GET'])
def get_attack_distribution():
    """Get attack type distribution"""
    try:
        distribution = db_manager.get_attack_distribution()
        
        return jsonify({
            'status': 'success',
            'data': distribution
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ============================================================================
# API ROUTES - EXPORT
# ============================================================================

@app.route('/api/export/csv', methods=['GET'])
def export_alerts_csv():
    """Export alerts to CSV"""
    try:
        filename = f"nids_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = db_manager.export_alerts_csv(filename)
        
        if filepath and os.path.exists(filepath):
            return send_file(
                filepath,
                mimetype='text/csv',
                as_attachment=True,
                download_name=filename
            )
        else:
            return jsonify({
                'status': 'error',
                'message': 'No alerts to export'
            }), 404
    
    except Exception as e:
        log_error(f"Error exporting CSV: {str(e)}", component='App')
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    log_api(f"Client connected: {request.sid}")
    emit('connection_response', {
        'status': 'connected',
        'message': 'Connected to NIDS',
        'timestamp': time.time()
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    log_api(f"Client disconnected: {request.sid}")


@socketio.on('request_system_status')
def handle_status_request():
    """Handle request for system status"""
    status = {
        'is_running': is_monitoring,
        'packet_rate': capture_engine.get_packet_rate() if capture_engine and is_monitoring else 0,
        'alert_count': db_manager.get_alert_count_today(),
        'active_flows': len(capture_engine.flow_tracker) if capture_engine and is_monitoring else 0
    }
    emit('system_status', status)


# ============================================================================
# CALLBACKS AND HELPERS
# ============================================================================

def handle_prediction(prediction_result):
    """
    Callback function called when ML model makes a prediction

    Args:
        prediction_result: Dictionary with prediction information
    """
    try:
        if prediction_result['is_attack']:
            # Update statistics
            system_stats['total_alerts'] += 1

            # Save to database
            alert_id = db_manager.insert_alert(prediction_result)

            if alert_id:
                prediction_result['id'] = alert_id

            # Update statistics
            db_manager.update_statistics(prediction_result['attack_type'])

            # Check for model drift
            if Config.DRIFT_DETECTION_ENABLED:
                drift_status = drift_detector.check_drift(prediction_result)
                if drift_status['drift_detected']:
                    log_api(f"⚠️  Model drift detected: {drift_status['message']}")

            # Emit to connected clients via WebSocket
            socketio.emit('new_alert', prediction_result)

            # Log critical alerts
            if prediction_result['severity'] == 'CRITICAL':
                log_api(
                    f"CRITICAL ALERT: {prediction_result['attack_type']} from "
                    f"{prediction_result['src_ip']} (confidence: {prediction_result['confidence_score']:.2f}%)"
                )
        else:
            # Benign traffic - emit to show system is working
            # Show all benign traffic so user can see the system working
            socketio.emit('benign_traffic', prediction_result)

    except Exception as e:
        log_error(f"Error handling prediction: {str(e)}", component='App')


def start_status_broadcast():
    """Start broadcasting system status to clients"""
    def broadcast_status():
        while is_monitoring:
            try:
                total_packets = 0
                packet_rate = 0
                total_flows = 0
                if capture_engine:
                    stats = capture_engine.get_statistics()
                    total_packets = stats.get('total_packets', 0)
                    packet_rate = stats.get('packets_per_second', 0)
                    total_flows = stats.get('total_flows', 0)
                    # Sync system_stats with actual capture stats
                    system_stats['total_packets'] = total_packets
                
                status = {
                    'is_running': is_monitoring,
                    'packet_rate': packet_rate,
                    'total_flows': total_flows,
                    'alert_count': db_manager.get_alert_count_today(),
                    'total_packets': total_packets,
                    'total_alerts': system_stats['total_alerts'],
                    'timestamp': time.time()
                }
                
                socketio.emit('system_status_update', status)
                time.sleep(Config.STATS_UPDATE_INTERVAL)
            
            except Exception as e:
                log_error(f"Status broadcast error: {str(e)}", component='App')
                break
    
    broadcast_thread = threading.Thread(target=broadcast_status, daemon=True)
    broadcast_thread.start()


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'status': 'error',
        'message': 'Resource not found'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({
        'status': 'error',
        'message': 'Internal server error'
    }), 500


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    try:
        # Initialize system
        initialize_system()

        # Print startup message
        print("\n" + "="*70)
        print("  NIDS - Enhanced Predictive Classification of Cyber Security Threats")
        print("  Machine Learning-Based Network Intrusion Detection System")
        print("  Author: RASSYIDZ - Universiti Kuala Lumpur FYP2")
        print("="*70)
        print(f"\n🌐 Dashboard URL: http://{Config.HOST}:{Config.PORT}")
        print(f"📊 Database: {Config.DATABASE_PATH}")
        print(f"🤖 ML Models: {'Loaded' if ml_predictor.is_loaded else 'Not Loaded'}")
        print(f"\n⚠️  Note: Run with 'sudo' or 'admin privileges' for live packet capture")
        print(f"💡 Tip: Ensure network interface is specified in the dashboard\n")
        print(f"✅ Server is ready and waiting for connections...")
        print(f"📝 Activity logs will appear below when dashboard is accessed\n")
        print("="*70 + "\n")

        # Run Flask app with SocketIO
        socketio.run(
            app,
            host=Config.HOST,
            port=Config.PORT,
            debug=Config.DEBUG,
            use_reloader=False  # Disable reloader to prevent duplicate threads
        )

    except KeyboardInterrupt:
        print("\n\n" + "="*70)
        print("  Shutting down NIDS...")
        print("="*70)

        # Clean shutdown (capture_engine and is_monitoring are already global)
        if capture_engine:
            print("  Stopping packet capture...")
            capture_engine.stop_capture()

        print("  ✅ NIDS shut down successfully")
        print("="*70 + "\n")
