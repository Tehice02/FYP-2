"""
Real-time Network Flow Aggregator for NF-UNSW-NB15-v3 Feature Extraction

This module tracks network flows and computes all 34 features required by the
XGBoost NIDS model, matching the exact NF-UNSW-NB15-v3 dataset structure.

Author: RASSYIDZ - UniKL MIIT FYP
Dataset: NF-UNSW-NB15-v3
"""

import time
import numpy as np
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw
from typing import Dict, Tuple, Optional, List


class Flow:
    """Represents a bidirectional network flow with feature tracking."""

    def __init__(self, five_tuple: Tuple[str, str, int, int, int], first_packet_time: float):
        """
        Initialize a new flow.

        Args:
            five_tuple: (src_ip, dst_ip, src_port, dst_port, protocol)
            first_packet_time: Timestamp of first packet (in seconds)
        """
        self.five_tuple = five_tuple
        self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol = five_tuple

        # Timing
        self.start_time = first_packet_time
        self.end_time = first_packet_time
        self.last_packet_time = first_packet_time

        # Packet and byte counters
        self.out_pkts = 0  # Client → Server
        self.in_pkts = 0   # Server → Client
        self.out_bytes = 0
        self.in_bytes = 0

        # Packet sizes
        self.packet_lengths: List[int] = []
        self.ip_packet_lengths: List[int] = []

        # TTL tracking
        self.ttls: List[int] = []

        # TCP specific
        self.tcp_flags_out = 0  # Client flags
        self.tcp_flags_in = 0   # Server flags
        self.tcp_win_in: List[int] = []
        self.tcp_win_out: List[int] = []

        # TCP retransmission tracking
        self.seq_numbers_out: Dict[int, int] = {}  # seq -> count
        self.seq_numbers_in: Dict[int, int] = {}
        self.retrans_out_pkts = 0
        self.retrans_out_bytes = 0
        self.retrans_in_pkts = 0
        self.retrans_in_bytes = 0

        # Packet size distribution bins
        self.pkts_up_to_128 = 0
        self.pkts_128_to_256 = 0
        self.pkts_256_to_512 = 0
        self.pkts_512_to_1024 = 0
        self.pkts_1024_to_1514 = 0

        # Inter-arrival times
        self.last_out_time: Optional[float] = None
        self.last_in_time: Optional[float] = None
        self.iat_out: List[float] = []  # Src → Dst IAT (in milliseconds)
        self.iat_in: List[float] = []   # Dst → Src IAT (in milliseconds)

        # Protocol-specific features
        self.icmp_type = 0
        self.dns_query_id = 0
        self.dns_query_type = 0
        self.dns_ttl_answer = 0
        self.ftp_command_ret_code = 0

    def is_outgoing(self, pkt) -> bool:
        """
        Determine packet direction (True if client → server).

        Args:
            pkt: Scapy packet

        Returns:
            True if packet is from client to server (outgoing)
        """
        if IP in pkt:
            return (pkt[IP].src == self.src_ip and
                    pkt[IP].dst == self.dst_ip)
        return True  # Default to outgoing

    def update(self, pkt) -> None:
        """
        Update flow with new packet.

        Args:
            pkt: Scapy packet to add to this flow
        """
        packet_time = float(pkt.time)
        self.end_time = packet_time
        self.last_packet_time = packet_time

        # Determine direction
        is_out = self.is_outgoing(pkt)

        # Get packet length
        pkt_len = len(pkt)
        self.packet_lengths.append(pkt_len)

        # Update packet size bins
        if pkt_len <= 128:
            self.pkts_up_to_128 += 1
        elif pkt_len <= 256:
            self.pkts_128_to_256 += 1
        elif pkt_len <= 512:
            self.pkts_256_to_512 += 1
        elif pkt_len <= 1024:
            self.pkts_512_to_1024 += 1
        elif pkt_len <= 1514:
            self.pkts_1024_to_1514 += 1

        # IP layer features
        if IP in pkt:
            ip_len = pkt[IP].len
            self.ip_packet_lengths.append(ip_len)
            self.ttls.append(pkt[IP].ttl)

            # Update byte and packet counters
            if is_out:
                self.out_pkts += 1
                self.out_bytes += pkt_len
            else:
                self.in_pkts += 1
                self.in_bytes += pkt_len

        # TCP layer features
        if TCP in pkt:
            tcp_layer = pkt[TCP]

            # TCP flags
            if is_out:
                self.tcp_flags_out |= int(tcp_layer.flags)
                self.tcp_win_out.append(tcp_layer.window)

                # Retransmission detection (outgoing)
                seq = tcp_layer.seq
                if seq in self.seq_numbers_out:
                    self.retrans_out_pkts += 1
                    self.retrans_out_bytes += pkt_len
                else:
                    self.seq_numbers_out[seq] = 1
            else:
                self.tcp_flags_in |= int(tcp_layer.flags)
                self.tcp_win_in.append(tcp_layer.window)

                # Retransmission detection (incoming)
                seq = tcp_layer.seq
                if seq in self.seq_numbers_in:
                    self.retrans_in_pkts += 1
                    self.retrans_in_bytes += pkt_len
                else:
                    self.seq_numbers_in[seq] = 1

        # ICMP features
        if ICMP in pkt:
            self.icmp_type = pkt[ICMP].type

        # DNS features
        if DNS in pkt:
            dns_layer = pkt[DNS]
            self.dns_query_id = dns_layer.id
            if dns_layer.qd:  # Query
                self.dns_query_type = dns_layer.qd.qtype
            if dns_layer.an:  # Answer
                self.dns_ttl_answer = dns_layer.an.ttl

        # FTP features (basic detection from Raw payload)
        if Raw in pkt and self.dst_port == 21:
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                # Extract FTP response code (3 digits)
                if payload[:3].isdigit():
                    self.ftp_command_ret_code = int(payload[:3])
            except:
                pass

        # Inter-arrival time tracking
        if is_out:
            if self.last_out_time is not None:
                iat_ms = (packet_time - self.last_out_time) * 1000  # Convert to milliseconds
                self.iat_out.append(iat_ms)
            self.last_out_time = packet_time
        else:
            if self.last_in_time is not None:
                iat_ms = (packet_time - self.last_in_time) * 1000
                self.iat_in.append(iat_ms)
            self.last_in_time = packet_time

    def export_features(self) -> Dict[str, float]:
        """
        Export flow features in exact NF-UNSW-NB15-v3 format.

        Returns:
            Dictionary with 34 feature names matching the training dataset
        """
        # Calculate duration
        duration_ms = (self.end_time - self.start_time) * 1000
        duration_sec = max(duration_ms / 1000.0, 0.001)  # Avoid division by zero

        # Throughput calculations
        src_to_dst_second_bytes = self.out_bytes / duration_sec if duration_sec > 0 else 0
        dst_to_src_second_bytes = self.in_bytes / duration_sec if duration_sec > 0 else 0

        # IAT statistics
        def calc_iat_stats(iat_list):
            """Calculate min, max, avg, stddev for IAT list."""
            if len(iat_list) == 0:
                return 0, 0, 0, 0
            return (
                int(min(iat_list)),
                int(max(iat_list)),
                int(np.mean(iat_list)),
                int(np.std(iat_list))
            )

        iat_out_min, iat_out_max, iat_out_avg, iat_out_std = calc_iat_stats(self.iat_out)
        iat_in_min, iat_in_max, iat_in_avg, iat_in_std = calc_iat_stats(self.iat_in)

        # Build feature dictionary with EXACT column names from NF-UNSW-NB15-v3
        features = {
            # Timing
            'FLOW_START_MILLISECONDS': int(self.start_time * 1000),
            'FLOW_DURATION_MILLISECONDS': int(duration_ms),
            'DURATION_OUT': int(duration_ms) if self.out_pkts > 0 else 0,  # Approximation

            # Byte counters
            'IN_BYTES': self.in_bytes,
            'OUT_BYTES': self.out_bytes,

            # Packet counters
            'IN_PKTS': self.in_pkts,
            'OUT_PKTS': self.out_pkts,

            # TCP flags
            'TCP_FLAGS': self.tcp_flags_out | self.tcp_flags_in,
            'CLIENT_TCP_FLAGS': self.tcp_flags_out,
            'SERVER_TCP_FLAGS': self.tcp_flags_in,

            # TTL
            'MIN_TTL': min(self.ttls) if self.ttls else 0,
            'MAX_TTL': max(self.ttls) if self.ttls else 0,

            # Packet lengths
            'LONGEST_FLOW_PKT': max(self.packet_lengths) if self.packet_lengths else 0,
            'SHORTEST_FLOW_PKT': min(self.packet_lengths) if self.packet_lengths else 0,
            'MIN_IP_PKT_LEN': min(self.ip_packet_lengths) if self.ip_packet_lengths else 0,
            'MAX_IP_PKT_LEN': max(self.ip_packet_lengths) if self.ip_packet_lengths else 0,

            # Throughput
            'SRC_TO_DST_SECOND_BYTES': src_to_dst_second_bytes,
            'DST_TO_SRC_SECOND_BYTES': dst_to_src_second_bytes,
            'SRC_TO_DST_AVG_THROUGHPUT': int(src_to_dst_second_bytes),
            'DST_TO_SRC_AVG_THROUGHPUT': int(dst_to_src_second_bytes),

            # Retransmissions
            'RETRANSMITTED_IN_BYTES': self.retrans_in_bytes,
            'RETRANSMITTED_IN_PKTS': self.retrans_in_pkts,
            'RETRANSMITTED_OUT_BYTES': self.retrans_out_bytes,
            'RETRANSMITTED_OUT_PKTS': self.retrans_out_pkts,

            # Packet size distribution
            'NUM_PKTS_UP_TO_128_BYTES': self.pkts_up_to_128,
            'NUM_PKTS_128_TO_256_BYTES': self.pkts_128_to_256,
            'NUM_PKTS_256_TO_512_BYTES': self.pkts_256_to_512,
            'NUM_PKTS_512_TO_1024_BYTES': self.pkts_512_to_1024,
            'NUM_PKTS_1024_TO_1514_BYTES': self.pkts_1024_to_1514,

            # TCP window
            'TCP_WIN_MAX_IN': max(self.tcp_win_in) if self.tcp_win_in else 0,
            'TCP_WIN_MAX_OUT': max(self.tcp_win_out) if self.tcp_win_out else 0,

            # Protocol-specific
            'ICMP_TYPE': self.icmp_type,
            'ICMP_IPV4_TYPE': self.icmp_type,
            'DNS_QUERY_ID': self.dns_query_id,
            'DNS_QUERY_TYPE': self.dns_query_type,
            'DNS_TTL_ANSWER': self.dns_ttl_answer,
            'FTP_COMMAND_RET_CODE': self.ftp_command_ret_code,

            # Inter-arrival times
            'SRC_TO_DST_IAT_MIN': iat_out_min,
            'SRC_TO_DST_IAT_MAX': iat_out_max,
            'SRC_TO_DST_IAT_AVG': iat_out_avg,
            'SRC_TO_DST_IAT_STDDEV': iat_out_std,
            'DST_TO_SRC_IAT_MIN': iat_in_min,
            'DST_TO_SRC_IAT_MAX': iat_in_max,
            'DST_TO_SRC_IAT_AVG': iat_in_avg,
            'DST_TO_SRC_IAT_STDDEV': iat_in_std,
        }

        return features


class FlowAggregator:
    """
    Real-time network flow aggregator for NIDS feature extraction.

    Tracks bidirectional flows and computes NF-UNSW-NB15-v3 features.
    """

    def __init__(self, flow_timeout: int = 5, max_flows: int = 100000):
        """
        Initialize flow aggregator.

        Args:
            flow_timeout: Seconds of inactivity before flow expires (default: 30)
            max_flows: Maximum number of concurrent flows to track (default: 100000)
        """
        self.flows: Dict[Tuple, Flow] = {}
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        self.completed_flows: List[Dict] = []

    def get_five_tuple(self, pkt) -> Optional[Tuple[str, str, int, int, int]]:
        """
        Extract 5-tuple from packet for flow identification.

        Args:
            pkt: Scapy packet

        Returns:
            (src_ip, dst_ip, src_port, dst_port, protocol) or None
        """
        if IP not in pkt:
            return None

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = pkt[IP].proto

        # Extract ports for TCP/UDP
        src_port = 0
        dst_port = 0
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        return (src_ip, dst_ip, src_port, dst_port, protocol)

    def get_bidirectional_key(self, five_tuple: Tuple) -> Tuple:
        """
        Create bidirectional flow key (normalized).

        Args:
            five_tuple: (src_ip, dst_ip, src_port, dst_port, protocol)

        Returns:
            Normalized 5-tuple for bidirectional flow matching
        """
        src_ip, dst_ip, src_port, dst_port, protocol = five_tuple

        # Normalize: smaller IP/port combo first
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        else:
            return (dst_ip, src_ip, dst_port, src_port, protocol)

    def process_packet(self, pkt) -> Optional[Dict[str, float]]:
        """
        Process a single packet and update flows.

        Args:
            pkt: Scapy packet

        Returns:
            Feature dictionary if flow completed, None otherwise
        """
        # Extract 5-tuple
        five_tuple = self.get_five_tuple(pkt)
        if five_tuple is None:
            return None

        # Get bidirectional flow key
        flow_key = self.get_bidirectional_key(five_tuple)

        # Check if flow exists
        if flow_key in self.flows:
            flow = self.flows[flow_key]
            flow.update(pkt)
        else:
            # Create new flow
            if len(self.flows) >= self.max_flows:
                # Clean up oldest flows
                self.cleanup_old_flows()

            flow = Flow(flow_key, float(pkt.time))
            flow.update(pkt)
            self.flows[flow_key] = flow

        return None  # Flow not yet complete

    def cleanup_old_flows(self, force_timeout: Optional[float] = None) -> List[Dict[str, float]]:
        """
        Remove expired flows and export their features.

        Args:
            force_timeout: Force cleanup of flows older than this (seconds),
                          or None to use self.flow_timeout

        Returns:
            List of feature dictionaries for completed flows
        """
        current_time = time.time()
        timeout = force_timeout if force_timeout is not None else self.flow_timeout
        completed = []

        flows_to_remove = []
        for flow_key, flow in self.flows.items():
            # Check if flow has timed out
            if (current_time - flow.last_packet_time) > timeout:
                features = flow.export_features()
                completed.append(features)
                flows_to_remove.append(flow_key)

        # Remove expired flows
        for flow_key in flows_to_remove:
            del self.flows[flow_key]

        return completed

    def get_active_flow_count(self) -> int:
        """Get number of currently tracked flows."""
        return len(self.flows)

    def flush_all_flows(self) -> List[Dict[str, float]]:
        """
        Export all active flows (useful for shutdown).

        Returns:
            List of feature dictionaries for all active flows
        """
        completed = []
        for flow in self.flows.values():
            features = flow.export_features()
            completed.append(features)

        self.flows.clear()
        return completed


# Example usage
if __name__ == "__main__":
    from scapy.all import sniff
    import pandas as pd

    # Initialize aggregator
    aggregator = FlowAggregator(flow_timeout=5)

    def packet_callback(pkt):
        """Callback for each captured packet."""
        aggregator.process_packet(pkt)

        # Periodically clean up old flows
        if aggregator.get_active_flow_count() % 100 == 0:
            completed_flows = aggregator.cleanup_old_flows()
            if completed_flows:
                print(f"[+] Exported {len(completed_flows)} completed flows")
                # Convert to DataFrame for model prediction
                df = pd.DataFrame(completed_flows)
                print(df.head())

    print("[*] Starting packet capture...")
    print("[*] Press Ctrl+C to stop")

    try:
        # Capture packets (adjust interface as needed)
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopping capture...")
        # Flush remaining flows
        remaining = aggregator.flush_all_flows()
        print(f"[+] Exported {len(remaining)} remaining flows")
