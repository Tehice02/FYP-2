"""
Packet Capture Engine - FIXED VERSION
Captures network packets using Scapy and aggregates them into flows
Implements proper 5-tuple flow tracking with bidirectional statistics
"""

import threading
import queue
import time
import platform
import numpy as np
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, get_if_list, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not installed. Install with: pip install scapy")

from models.feature_extraction import FlowRecord, FeatureExtractor
from models.ml_predictor import MLPredictor
from utils.config import Config
from utils.logger import nids_logger, log_packet_capture, log_error


class PacketCaptureEngine:
    """Captures and processes network packets in real-time"""
    
    def __init__(self, interface='eth0', on_prediction_callback=None, filter_str="ip"):
        """
        Initialize packet capture engine
        
        Args:
            interface: Network interface to capture from (e.g., 'eth0', 'wlan0', 'Wi-Fi')
            on_prediction_callback: Callback function for predictions
            filter_str: BPF filter string for packet capture
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for packet capture")
        
        # Convert interface name for Windows/Linux
        self.interface = self._get_valid_interface(interface)
        self.filter_str = filter_str
        self.callback = on_prediction_callback
        
        # Flow tracking with proper timeout and bidirectional support
        self.flow_tracker = {}  # dict of flow_key -> FlowRecord
        self.flow_times = {}    # dict of flow_key -> last_packet_time
        self.flow_lock = threading.Lock()
        
        # Packet queue for processing
        self.packet_queue = queue.Queue(maxsize=Config.PACKET_QUEUE_SIZE)
        
        # State management
        self.is_running = False
        self.capture_thread = None
        self.processing_thread = None
        self.timeout_check_thread = None
        
        # Statistics
        self.packet_count = 0
        self.flow_count = 0
        self.start_time = None
        self.dropped_packets = 0
        self.export_interval = 5  # Export/check flows every N seconds
        
        # ML Predictor
        self.predictor = MLPredictor()
        self.predictor.load_models()
        
        log_packet_capture(f"Packet capture engine initialized on interface {self.interface}")
    
    def _get_valid_interface(self, requested_interface):
        """
        Get a valid interface name for the current OS
        Properly resolves friendly names like 'Wi-Fi' to device paths
        """
        try:
            available_interfaces = get_if_list()
            
            log_packet_capture(f"Resolving interface: '{requested_interface}'")
            log_packet_capture(f"Available interfaces: {len(available_interfaces)}")
            
            # If already a device path, validate and return
            if requested_interface.startswith('\\Device\\NPF_'):
                if requested_interface in available_interfaces:
                    log_packet_capture(f"Using provided device path: {requested_interface}")
                    return requested_interface
            
            # Method 1: Try exact match
            if requested_interface in available_interfaces:
                log_packet_capture(f"Exact match found: {requested_interface}")
                return requested_interface
            
            # Method 2: Search by description and IP (most accurate)
            best_match = None
            best_score = 0
            
            for iface in available_interfaces:
                try:
                    iface_obj = conf.ifaces.get(iface)
                    if not iface_obj:
                        continue
                    
                    description = getattr(iface_obj, 'description', '').lower()
                    ip = str(getattr(iface_obj, 'ip', ''))
                    
                    score = 0
                    
                    # Check description match
                    req_lower = requested_interface.lower()
                    if req_lower in description:
                        score += 10
                        
                        # Boost score for exact Wi-Fi match
                        if req_lower == 'wi-fi' and 'wi-fi' in description:
                            score += 20
                        
                        # Prefer Intel/Realtek over Microsoft Virtual adapters
                        if any(brand in description for brand in ['intel', 'realtek', 'broadcom', 'qualcomm']):
                            score += 15
                        
                        # Penalize virtual adapters
                        if any(virt in description for virt in ['virtual', 'vmware', 'hyper-v', 'loopback']):
                            score -= 50
                        
                        # Bonus for having a real IP (not 169.254.x.x or 127.x.x.x)
                        if ip and not ip.startswith('169.254') and not ip.startswith('127.'):
                            score += 10
                            
                            # Extra bonus for private network IPs (192.168.x.x, 10.x.x.x)
                            if ip.startswith('192.168') or ip.startswith('10.'):
                                score += 5
                    
                    if score > best_score:
                        best_score = score
                        best_match = iface
                        log_packet_capture(f"  Candidate: {description} (IP: {ip}) - Score: {score}")
                
                except Exception as e:
                    continue
            
            if best_match and best_score > 0:
                iface_obj = conf.ifaces.get(best_match)
                desc = getattr(iface_obj, 'description', 'Unknown')
                ip = getattr(iface_obj, 'ip', 'Unknown')
                log_packet_capture(f"[OK] Selected interface: {best_match}")
                log_packet_capture(f"  Description: {desc}")
                log_packet_capture(f"  IP: {ip}")
                log_packet_capture(f"  Match score: {best_score}")
                return best_match
            
            # Method 3: Fallback - use first non-loopback with real IP
            for iface in available_interfaces:
                if 'Loopback' in iface:
                    continue
                
                try:
                    iface_obj = conf.ifaces.get(iface)
                    if iface_obj:
                        ip = str(getattr(iface_obj, 'ip', ''))
                        if ip and not ip.startswith('169.254') and not ip.startswith('127.'):
                            log_packet_capture(f"⚠️ Fallback: Using first available interface: {iface}")
                            return iface
                except:
                    continue
            
            # Last resort: return requested interface
            log_error(f"Could not resolve interface. Using as-is: {requested_interface}", component='PacketCapture')
            return requested_interface
        
        except Exception as e:
            log_error(f"Error resolving interface: {str(e)}", component='PacketCapture')
            return requested_interface
    
    def start_capture(self):
        """Start capturing packets"""
        if self.is_running:
            log_packet_capture("Capture already running")
            return
        
        self.is_running = True
        self.start_time = time.time()
        self.packet_count = 0
        self.flow_count = 0
        
        log_packet_capture(f"Starting packet capture on {self.interface}...")
        
        # Start processing thread
        self.processing_thread = threading.Thread(target=self._process_packets, daemon=True)
        self.processing_thread.start()
        
        # Start timeout check thread
        self.timeout_check_thread = threading.Thread(target=self._timeout_checker, daemon=True)
        self.timeout_check_thread.start()
        
        # Start capture thread
        self.capture_thread = threading.Thread(target=self._capture_packets, daemon=True)
        self.capture_thread.start()
        
        log_packet_capture("Packet capture started successfully")
    
    def stop_capture(self):
        """Stop capturing packets"""
        if not self.is_running:
            return
        
        log_packet_capture("Stopping packet capture...")
        self.is_running = False
        
        # Clear flow tracking immediately without processing remaining flows
        # This prevents potential crashes during shutdown
        with self.flow_lock:
            self.flow_tracker.clear()
            self.flow_times.clear()
        
        # Wait for threads to finish with shorter timeout
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=2)
        if self.timeout_check_thread and self.timeout_check_thread.is_alive():
            self.timeout_check_thread.join(timeout=2)
        
        log_packet_capture(f"Packet capture stopped. Total packets: {self.packet_count}, Total flows: {self.flow_count}")
    
    def _capture_packets(self):
        """Capture packets using Scapy (runs in separate thread)"""
        try:
            log_packet_capture(f"Sniffing on {self.interface} with filter '{self.filter_str}'")
            
            sniff(
                iface=self.interface,
                prn=self._packet_handler,  # ✅ FIXED: Was self.process_packet
                store=False,
                filter=None,  # No filter initially - capture everything
                stop_filter=lambda x: not self.is_running
            )
            
        except PermissionError:
            log_error(
                "Permission denied. Run with sudo/administrator privileges",
                component='PacketCapture'
            )
        except OSError as e:
            if "filename" in str(e) or "syntax" in str(e).lower():
                log_error(
                    f"Invalid network interface. Make sure you have network drivers installed. Error: {str(e)}",
                    component='PacketCapture'
                )
            else:
                log_error(f"Capture error: {str(e)}", component='PacketCapture')
        except Exception as e:
            log_error(f"Capture error: {str(e)}", component='PacketCapture')
    
    def _packet_handler(self, packet):
        """
        Handle each captured packet
        
        Args:
            packet: Scapy packet object
        """
        try:
            # Only process IP packets
            if not packet.haslayer(IP):
                return
            
            self.packet_count += 1
            
            # Log first few packets for debugging
            if self.packet_count <= 5:
                log_packet_capture(f"[OK] Packet {self.packet_count}: {packet.summary()}")
            
            # Add to queue for processing
            try:
                self.packet_queue.put((packet, time.time()), block=False)
            except queue.Full:
                self.dropped_packets += 1
                if self.dropped_packets % 100 == 0:
                    log_packet_capture(f"Warning: Dropped {self.dropped_packets} packets (queue full)")
        
        except Exception as e:
            log_error(f"Packet handler error: {str(e)}", component='PacketCapture')
    
    def _process_packets(self):
        """Process packets from queue and aggregate into flows"""
        log_packet_capture("Packet processing thread started")
        
        while self.is_running:
            try:
                # Get packet from queue with timeout
                packet, timestamp = self.packet_queue.get(timeout=1)
                
                # Extract flow key (5-tuple)
                flow_key = self._extract_flow_key(packet)
                if not flow_key:
                    continue
                
                # Get or create flow record
                with self.flow_lock:
                    if flow_key not in self.flow_tracker:
                        self.flow_tracker[flow_key] = FlowRecord(flow_key)
                        self.flow_count += 1
                        
                        # Log first few flows
                        if self.flow_count <= 3:
                            log_packet_capture(f"[OK] New flow {self.flow_count}: {flow_key}")
                    
                    flow_record = self.flow_tracker[flow_key]
                    self.flow_times[flow_key] = timestamp
                
                # Determine packet direction
                direction = self._determine_direction(packet, flow_key)
                
                # Add packet to flow
                flow_record.add_packet(packet, direction, timestamp)
                
            except queue.Empty:
                continue
            
            except Exception as e:
                log_error(f"Packet processing error: {str(e)}", component='PacketCapture')
        
        log_packet_capture("Packet processing thread stopped")
    
    def _timeout_checker(self):
        """Check for timed-out flows and export them"""
        log_packet_capture("Flow timeout checker started")
        
        while self.is_running:
            time.sleep(self.export_interval)
            
            try:
                current_time = time.time()
                expired_flows = []
                
                with self.flow_lock:
                    for flow_key, last_time in list(self.flow_times.items()):
                        # If flow hasn't seen a packet in FLOW_TIMEOUT seconds, it's expired
                        if (current_time - last_time) > Config.FLOW_TIMEOUT:
                            expired_flows.append(flow_key)
                
                # Process expired flows
                for flow_key in expired_flows:
                    with self.flow_lock:
                        if flow_key in self.flow_tracker:
                            flow_record = self.flow_tracker[flow_key]
                            if flow_record and flow_record.total_packets > 0:
                                # Export flow for prediction
                                self._predict_flow(flow_key, flow_record)
                            
                            # Remove flow
                            del self.flow_tracker[flow_key]
                            del self.flow_times[flow_key]
                
                # Log activity every minute
                if len(expired_flows) > 0:
                    log_packet_capture(f"Processed {len(expired_flows)} expired flows. Active flows: {len(self.flow_tracker)}")
                
            except Exception as e:
                log_error(f"Timeout checker error: {str(e)}", component='PacketCapture')
        
        log_packet_capture("Flow timeout checker stopped")
    
    def _extract_flow_key(self, packet):
        """
        Extract flow key from packet (5-tuple)
        Normalize bidirectional flows to single direction
        
        Returns:
            Tuple: (src_ip, dst_ip, src_port, dst_port, protocol)
        """
        try:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = None
            src_port = 0
            dst_port = 0
            
            # Extract ports based on protocol
            if packet.haslayer(TCP):
                protocol = 'TCP'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = 'UDP'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif packet.haslayer(ICMP):
                protocol = 'ICMP'
                src_port = 0
                dst_port = 0
            else:
                protocol = 'OTHER'
                src_port = 0
                dst_port = 0
            
            # Create flow key (5-tuple)
            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            
            return flow_key
        
        except Exception as e:
            log_error(f"Error extracting flow key: {str(e)}", component='PacketCapture')
            return None
    
    def _determine_direction(self, packet, flow_key):
        """
        Determine packet direction (forward or backward)
        
        Args:
            packet: Scapy packet
            flow_key: Flow key tuple
            
        Returns:
            'forward' or 'backward'
        """
        try:
            ip_layer = packet[IP]
            flow_src_ip, flow_dst_ip, _, _, _ = flow_key
            
            if ip_layer.src == flow_src_ip:
                return 'forward'
            else:
                return 'backward'
        except:
            return 'forward'
    
    def _predict_flow(self, flow_key, flow_record):
        """
        Extract features from flow and make ML prediction
        
        Args:
            flow_key: Flow identifier
            flow_record: FlowRecord object with aggregated flow data
        """
        try:
            # Calculate flow metrics
            flow_record.finalize()
            
            # Extract 34 features
            features_array = FeatureExtractor.extract_features(flow_record)
            
            if features_array is None or features_array.size == 0:
                log_error(f"Failed to extract features for flow {flow_key}", component='PacketCapture')
                return
            
            # Get prediction from ML model
            prediction = self.predictor.predict(features_array)
            
            if prediction is None:
                return
            
            # Prepare alert data
            alert_data = {
                'src_ip': flow_record.src_ip,
                'dst_ip': flow_record.dst_ip,
                'src_port': flow_record.src_port,
                'dst_port': flow_record.dst_port,
                'protocol': flow_record.protocol,
                'timestamp': time.time(),
                'packet_count': flow_record.total_packets,
                'bytes_total': flow_record.src_bytes + flow_record.dst_bytes,
                'is_attack': prediction['is_attack'],
                'attack_type': prediction['attack_type'],
                'confidence_score': prediction['confidence_score'],
                'severity': prediction['severity'],
                'duration': flow_record.duration,
                'features': features_array.tolist()  # Send raw features for analysis
            }
            
            # Call prediction callback if provided
            if self.callback:
                try:
                    self.callback(alert_data)
                except Exception as e:
                    log_error(f"Callback error: {str(e)}", component='PacketCapture')
            
        except Exception as e:
            log_error(f"Prediction error for flow {flow_key}: {str(e)}", component='PacketCapture')
    
    def get_statistics(self):
        """Get capture statistics"""
        return {
            'total_packets': self.packet_count,
            'total_flows': self.flow_count,
            'active_flows': len(self.flow_tracker),
            'packets_per_second': self.get_packet_rate(),
            'dropped_packets': self.dropped_packets,
            'uptime': time.time() - self.start_time if self.start_time else 0
        }
    
    def get_packet_rate(self):
        """Calculate packets per second"""
        if not self.start_time:
            return 0
        
        elapsed = time.time() - self.start_time
        if elapsed > 0:
            return self.packet_count / elapsed
        return 0


class SimulatedPacketGenerator:
    """
    Generates simulated network packets for testing
    Useful when running without network access or for demos
    """
    
    def __init__(self, callback=None):
        """Initialize packet generator"""
        self.callback = callback
        self.is_running = False
        self.packet_count = 0
        
    def start(self):
        """Start generating packets"""
        self.is_running = True
        self.thread = threading.Thread(target=self._generate_packets, daemon=True)
        self.thread.start()
        log_packet_capture("Simulated packet generator started")
    
    def stop(self):
        """Stop generating packets"""
        self.is_running = False
        if hasattr(self, 'thread'):
            self.thread.join(timeout=5)
        log_packet_capture("Simulated packet generator stopped")
    
    def _generate_packets(self):
        """Generate simulated packets"""
        import random
        
        attack_types = ['Benign', 'DoS', 'Reconnaissance', 'Exploits', 'Backdoor']
        
        while self.is_running:
            try:
                # Simulate a flow prediction
                alert_data = {
                    'src_ip': f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                    'dst_ip': f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}",
                    'src_port': random.randint(1024, 65535),
                    'dst_port': random.choice([80, 443, 22, 21, 25, 53, 3306]),
                    'protocol': random.choice(['TCP', 'UDP']),
                    'timestamp': datetime.now().isoformat(),
                    'packet_count': random.randint(5, 100),
                    'bytes_total': random.randint(100, 10000),
                    'is_attack': random.random() < 0.2,  # 20% attack rate
                    'attack_type': random.choice(attack_types),
                    'confidence_score': round(random.uniform(0.6, 1.0), 2),
                    'severity': random.choice(['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
                    'duration': round(random.uniform(0.1, 60.0), 2)
                }
                
                if self.callback:
                    try:
                        self.callback(alert_data)
                    except Exception as e:
                        log_error(f"Callback error: {str(e)}", component='PacketGenerator')
                
                self.packet_count += 1
                time.sleep(random.uniform(0.5, 2.0))
            
            except Exception as e:
                log_error(f"Packet generation error: {str(e)}", component='PacketGenerator')