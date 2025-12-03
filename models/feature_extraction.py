"""
Feature Extraction Engine - FIXED VERSION
Extracts 34 NetFlow features from flows for ML prediction
Uses exact feature ordering from feature_names.json for NF-UNSW-NB15-v3 dataset
"""

import numpy as np
import json
import os
from datetime import datetime
from collections import defaultdict
from utils.logger import log_error


class FlowRecord:
    """
    Stores aggregated packet information for a single network flow
    Tracks bidirectional statistics (forward and backward packets)
    """
    
    def __init__(self, flow_key):
        """
        Initialize flow record
        
        Args:
            flow_key: Tuple of (src_ip, dst_ip, src_port, dst_port, protocol)
        """
        self.flow_key = flow_key
        self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol = flow_key
        
        # Timing
        self.start_time = None
        self.end_time = None
        self.duration = 0.0
        
        # Forward direction stats (src -> dst)
        self.fwd_packets = 0
        self.fwd_bytes = 0
        self.fwd_pkt_sizes = []  # List of packet sizes for IAT calculation
        self.fwd_pkt_times = []  # List of packet timestamps
        self.fwd_min_pkt_size = float('inf')
        self.fwd_max_pkt_size = 0
        self.fwd_window_size = []  # TCP window sizes
        self.fwd_tcp_flags = defaultdict(int)  # Count of each TCP flag
        self.fwd_urg_flags = 0
        self.fwd_ack_flags = 0
        self.fwd_psh_flags = 0
        self.fwd_rst_flags = 0
        self.fwd_syn_flags = 0
        self.fwd_fin_flags = 0
        
        # Backward direction stats (dst -> src)
        self.bwd_packets = 0
        self.bwd_bytes = 0
        self.bwd_pkt_sizes = []
        self.bwd_pkt_times = []
        self.bwd_min_pkt_size = float('inf')
        self.bwd_max_pkt_size = 0
        self.bwd_window_size = []
        self.bwd_tcp_flags = defaultdict(int)
        self.bwd_urg_flags = 0
        self.bwd_ack_flags = 0
        self.bwd_psh_flags = 0
        self.bwd_rst_flags = 0
        self.bwd_syn_flags = 0
        self.bwd_fin_flags = 0
        
        # Bidirectional stats
        self.total_packets = 0
        self.src_bytes = 0
        self.dst_bytes = 0
        self.total_bytes = 0
        self.min_pkt_size = float('inf')
        self.max_pkt_size = 0
        
        # Protocol-specific
        self.icmp_type = None
        self.dns_query_id = None
        self.dns_query_type = None
        self.dns_ttl_answer = None
        self.ftp_command_return_code = None
        
        # Packet rate stats
        self.fwd_pkt_rate = 0
        self.bwd_pkt_rate = 0
    
    def add_packet(self, packet, direction, timestamp):
        """
        Add a packet to the flow record
        
        Args:
            packet: Scapy packet object
            direction: 'forward' or 'backward'
            timestamp: Packet timestamp
        """
        try:
            from scapy.all import IP, TCP, UDP, ICMP, Raw
            
            # Initialize start/end time
            if self.start_time is None:
                self.start_time = timestamp
            self.end_time = timestamp
            self.duration = (self.end_time - self.start_time) * 1000  # Convert to milliseconds
            
            # Get payload size (IP packet size - IP header)
            ip_layer = packet[IP]
            packet_size = len(ip_layer.payload)
            
            if direction == 'forward':
                self.fwd_packets += 1
                self.fwd_bytes += packet_size
                self.fwd_pkt_sizes.append(packet_size)
                self.fwd_pkt_times.append(timestamp)
                self.fwd_min_pkt_size = min(self.fwd_min_pkt_size, packet_size)
                self.fwd_max_pkt_size = max(self.fwd_max_pkt_size, packet_size)
                self.src_bytes += packet_size
                
                # TCP flags (forward)
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    flags = tcp_layer.flags
                    if flags & 0x20:  # URG
                        self.fwd_urg_flags += 1
                    if flags & 0x10:  # ACK
                        self.fwd_ack_flags += 1
                    if flags & 0x08:  # PSH
                        self.fwd_psh_flags += 1
                    if flags & 0x04:  # RST
                        self.fwd_rst_flags += 1
                    if flags & 0x02:  # SYN
                        self.fwd_syn_flags += 1
                    if flags & 0x01:  # FIN
                        self.fwd_fin_flags += 1
                    self.fwd_window_size.append(tcp_layer.window)
            else:
                self.bwd_packets += 1
                self.bwd_bytes += packet_size
                self.bwd_pkt_sizes.append(packet_size)
                self.bwd_pkt_times.append(timestamp)
                self.bwd_min_pkt_size = min(self.bwd_min_pkt_size, packet_size)
                self.bwd_max_pkt_size = max(self.bwd_max_pkt_size, packet_size)
                self.dst_bytes += packet_size
                
                # TCP flags (backward)
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    flags = tcp_layer.flags
                    if flags & 0x20:  # URG
                        self.bwd_urg_flags += 1
                    if flags & 0x10:  # ACK
                        self.bwd_ack_flags += 1
                    if flags & 0x08:  # PSH
                        self.bwd_psh_flags += 1
                    if flags & 0x04:  # RST
                        self.bwd_rst_flags += 1
                    if flags & 0x02:  # SYN
                        self.bwd_syn_flags += 1
                    if flags & 0x01:  # FIN
                        self.bwd_fin_flags += 1
                    self.bwd_window_size.append(tcp_layer.window)
            
            # Update bidirectional stats
            self.total_packets += 1
            self.total_bytes += packet_size
            self.min_pkt_size = min(self.min_pkt_size, packet_size)
            self.max_pkt_size = max(self.max_pkt_size, packet_size)
            
            # Protocol-specific parsing
            if packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                self.icmp_type = icmp_layer.type
            
        except Exception as e:
            log_error(f"Error adding packet to flow: {str(e)}", component='FlowRecord')
    
    def finalize(self):
        """Calculate final statistics for the flow"""
        if self.duration == 0:
            self.duration = 0.001  # Minimum 1ms
        
        # Calculate packet rates
        duration_sec = self.duration / 1000.0
        if duration_sec > 0:
            self.fwd_pkt_rate = self.fwd_packets / duration_sec
            self.bwd_pkt_rate = self.bwd_packets / duration_sec
        
        # Ensure min packet size defaults if not set
        if self.fwd_min_pkt_size == float('inf'):
            self.fwd_min_pkt_size = 0
        if self.bwd_min_pkt_size == float('inf'):
            self.bwd_min_pkt_size = 0
        if self.min_pkt_size == float('inf'):
            self.min_pkt_size = 0


class FeatureExtractor:
    """Extract 34 NetFlow features from flow records"""
    
    # Port to service mapping
    PORT_SERVICE_MAP = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
        53: 'DNS', 69: 'TFTP', 80: 'HTTP', 110: 'POP3', 123: 'NTP',
        135: 'RPC', 139: 'NETBIOS', 143: 'IMAP', 161: 'SNMP', 179: 'BGP',
        389: 'LDAP', 427: 'SLP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTP-SSL',
        514: 'SYSLOG', 587: 'SMTP', 636: 'LDAPS', 993: 'IMAP-SSL', 995: 'POP3-SSL',
        1433: 'MSSQL', 1521: 'ORACLE', 3306: 'MYSQL', 3389: 'RDP', 5432: 'POSTGRES',
        5984: 'COUCHDB', 6379: 'REDIS', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT',
        9200: 'ELASTICSEARCH', 27017: 'MONGODB', 50500: 'SAP'
    }
    
    @staticmethod
    def _get_service(port):
        """Get service name from port number"""
        return FeatureExtractor.PORT_SERVICE_MAP.get(port, 'OTHER')
    
    @staticmethod
    def _calculate_iat(packet_times):
        """
        Calculate Inter-Arrival Time (IAT) statistics
        
        Args:
            packet_times: List of packet timestamps
            
        Returns:
            Tuple: (min_iat, max_iat, avg_iat, stddev_iat)
        """
        if len(packet_times) < 2:
            return 0, 0, 0, 0
        
        iats = np.diff(np.array(packet_times)) * 1000  # Convert to milliseconds
        if len(iats) == 0:
            return 0, 0, 0, 0
        
        min_iat = float(np.min(iats))
        max_iat = float(np.max(iats))
        avg_iat = float(np.mean(iats))
        stddev_iat = float(np.std(iats))
        
        return min_iat, max_iat, avg_iat, stddev_iat
    
    @staticmethod
    def extract_features(flow_record):
        """
        Extract 34 NetFlow features from flow record
        EXACT feature order from NF-UNSW-NB15-v3 dataset
        
        Args:
            flow_record: FlowRecord object
            
        Returns:
            numpy array of 34 features in exact order
        """
        try:
            features = []
            
            # CORRECT order from feature_names.json
            # 1. FLOW_START_MILLISECONDS
            flow_start_ms = (flow_record.start_time * 1000) if flow_record.start_time else 0
            features.append(flow_start_ms)
            
            # 2. IN_BYTES (DST_TO_SRC bytes - backward)
            features.append(float(flow_record.bwd_bytes))
            
            # 3. IN_PKTS (DST_TO_SRC packets - backward)
            features.append(float(flow_record.bwd_packets))
            
            # 4. OUT_BYTES (SRC_TO_DST bytes - forward)
            features.append(float(flow_record.fwd_bytes))
            
            # 5. TCP_FLAGS (total TCP flags)
            # Include ALL TCP flags
            tcp_flags = (flow_record.fwd_syn_flags + flow_record.bwd_syn_flags +
                        flow_record.fwd_fin_flags + flow_record.bwd_fin_flags +
                        flow_record.fwd_rst_flags + flow_record.bwd_rst_flags +
                        flow_record.fwd_ack_flags + flow_record.bwd_ack_flags +
                        flow_record.fwd_psh_flags + flow_record.bwd_psh_flags +
                        flow_record.fwd_urg_flags + flow_record.bwd_urg_flags)
            features.append(float(tcp_flags))
            
            # 6. FLOW_DURATION_MILLISECONDS
            features.append(flow_record.duration)
            
            # 7. DURATION_OUT (forward direction duration)
            if flow_record.fwd_pkt_times and len(flow_record.fwd_pkt_times) > 1:
                fwd_duration = flow_record.fwd_pkt_times[-1] - flow_record.fwd_pkt_times[0]
            else:
                fwd_duration = 0
            features.append(fwd_duration)
            
            # 8. MIN_TTL (assuming TTL tracking - placeholder)
            features.append(64.0)  # Standard TTL
            
            # 9. LONGEST_FLOW_PKT (max packet size)
            max_pkt = max(flow_record.fwd_max_pkt_size, flow_record.bwd_max_pkt_size)
            features.append(float(max_pkt) if max_pkt > 0 else 0)
            
            # 10. SHORTEST_FLOW_PKT (min packet size)
            min_fwd = flow_record.fwd_min_pkt_size if flow_record.fwd_min_pkt_size != float('inf') else float('inf')
            min_bwd = flow_record.bwd_min_pkt_size if flow_record.bwd_min_pkt_size != float('inf') else float('inf')
            min_pkt = min(min_fwd, min_bwd)
            features.append(float(min_pkt) if min_pkt != float('inf') else 0)
            
            # 11. MIN_IP_PKT_LEN (minimum IP packet length)
            features.append(float(min_pkt) if min_pkt != float('inf') else 0)
            
            # 12. SRC_TO_DST_SECOND_BYTES (forward bytes per second)
            if flow_record.duration > 0:
                fwd_bps = flow_record.fwd_bytes / flow_record.duration
            else:
                fwd_bps = 0
            features.append(float(fwd_bps))
            
            # 13. DST_TO_SRC_SECOND_BYTES (backward bytes per second)
            if flow_record.duration > 0:
                bwd_bps = flow_record.bwd_bytes / flow_record.duration
            else:
                bwd_bps = 0
            features.append(float(bwd_bps))
            
            # 14. SRC_TO_DST_AVG_THROUGHPUT
            if flow_record.duration > 0:
                fwd_tput = flow_record.fwd_bytes / (flow_record.duration / 1000)
            else:
                fwd_tput = 0
            features.append(float(fwd_tput))
            
            # 15-19. Packet length distribution bins
            fwd_bins = [0, 0, 0, 0, 0]
            for pkt_size in flow_record.fwd_pkt_sizes:
                if pkt_size <= 128:
                    fwd_bins[0] += 1
                elif pkt_size <= 256:
                    fwd_bins[1] += 1
                elif pkt_size <= 512:
                    fwd_bins[2] += 1
                elif pkt_size <= 1024:
                    fwd_bins[3] += 1
                else:
                    fwd_bins[4] += 1
            for i in range(5):
                features.append(float(fwd_bins[i]))
            
            # 20. TCP_WIN_MAX_IN (max backward window)
            max_bwd_win = max(flow_record.bwd_window_size) if flow_record.bwd_window_size else 0
            features.append(float(max_bwd_win))
            
            # 21. TCP_WIN_MAX_OUT (max forward window)
            max_fwd_win = max(flow_record.fwd_window_size) if flow_record.fwd_window_size else 0
            features.append(float(max_fwd_win))
            
            # 22. ICMP_TYPE
            icmp_type = float(flow_record.icmp_type) if flow_record.icmp_type is not None else 0
            features.append(icmp_type)
            
            # 23. DNS_QUERY_ID
            dns_query_id = float(flow_record.dns_query_id) if flow_record.dns_query_id is not None else 0
            features.append(dns_query_id)
            
            # 24. DNS_QUERY_TYPE
            dns_type = float(flow_record.dns_query_type) if flow_record.dns_query_type is not None else 0
            features.append(dns_type)
            
            # 25. DNS_TTL_ANSWER
            dns_ttl = float(flow_record.dns_ttl_answer) if flow_record.dns_ttl_answer is not None else 0
            features.append(dns_ttl)
            
            # 26. FTP_COMMAND_RET_CODE
            ftp_ret = 0  # Placeholder
            features.append(float(ftp_ret))
            
            # 27-30. Forward IAT (Inter-Arrival Time)
            fwd_iat_min, fwd_iat_max, fwd_iat_avg, fwd_iat_std = FeatureExtractor._calculate_iat(flow_record.fwd_pkt_times)
            features.append(fwd_iat_min)
            features.append(fwd_iat_max)
            features.append(fwd_iat_avg)
            features.append(fwd_iat_std)
            
            # 31-34. Backward IAT
            bwd_iat_min, bwd_iat_max, bwd_iat_avg, bwd_iat_std = FeatureExtractor._calculate_iat(flow_record.bwd_pkt_times)
            features.append(bwd_iat_min)
            features.append(bwd_iat_max)
            features.append(bwd_iat_avg)
            features.append(bwd_iat_std)
            
            # Validate feature count
            if len(features) != 34:
                log_error(
                    f"Feature count mismatch: got {len(features)}, expected 34",
                    component='FeatureExtractor'
                )
                return None
            
            return np.array(features, dtype=np.float32)
        
        except Exception as e:
            log_error(f"Error extracting features: {str(e)}", component='FeatureExtractor')
            return None
