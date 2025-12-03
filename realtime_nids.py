"""
Real-time Network Intrusion Detection System (NIDS)
Integrates FlowAggregator with XGBoost models for live threat detection

Author: RASSYIDZ - UniKL MIIT FYP
Dataset: NF-UNSW-NB15-v3
"""

import joblib
import pandas as pd
import numpy as np
from scapy.all import sniff
from flow_aggregator import FlowAggregator
from datetime import datetime
import json
import warnings
warnings.filterwarnings('ignore')


class RealtimeNIDS:
    """Real-time Network Intrusion Detection System."""

    def __init__(self, model_dir: str = "./models/model_files/"):
        """
        Initialize NIDS with trained models.

        Args:
            model_dir: Directory containing model files
        """
        print(f"[*] Initializing NIDS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Load models
        self.model_binary = joblib.load(f"{model_dir}xgboost_binary.pkl")
        self.model_multiclass = joblib.load(f"{model_dir}xgboost_multiclass.pkl")
        self.scaler_binary = joblib.load(f"{model_dir}scaler_binary.pkl")
        self.scaler_multiclass = joblib.load(f"{model_dir}scaler_multiclass.pkl")
        self.label_encoder = joblib.load(f"{model_dir}label_encoder_multiclass.pkl")

        # Load feature names
        with open(f"{model_dir}feature_names.json", 'r') as f:
            self.feature_names = json.load(f)

        print(f"[✓] Loaded binary model: XGBoost")
        print(f"[✓] Loaded multi-class model: XGBoost")
        print(f"[✓] Features: {len(self.feature_names)}")
        print(f"[✓] Attack classes: {len(self.label_encoder.classes_)}")

        # Initialize flow aggregator
        self.aggregator = FlowAggregator(flow_timeout=30, max_flows=100000)

        # Statistics
        self.stats = {
            'packets_processed': 0,
            'flows_completed': 0,
            'benign': 0,
            'attacks': 0,
            'attack_types': {}
        }

        print(f"[✓] NIDS ready for packet capture\n")

    def prepare_features(self, flow_features: dict) -> pd.DataFrame:
        """
        Convert flow features to model input format.

        Args:
            flow_features: Dictionary from FlowAggregator.export_features()

        Returns:
            DataFrame with features in correct order
        """
        # Create DataFrame with single row
        df = pd.DataFrame([flow_features])

        # Ensure all required features exist (fill missing with 0)
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0

        # Select features in exact order
        df = df[self.feature_names]

        return df

    def predict(self, flow_features: dict) -> dict:
        """
        Predict if flow is benign or attack, and classify attack type.

        Args:
            flow_features: Dictionary from FlowAggregator.export_features()

        Returns:
            Dictionary with prediction results
        """
        # Prepare features
        X = self.prepare_features(flow_features)

        # Stage 1: Binary classification (Benign vs Attack)
        X_scaled_binary = self.scaler_binary.transform(X)
        binary_pred = self.model_binary.predict(X_scaled_binary)[0]
        binary_proba = self.model_binary.predict_proba(X_scaled_binary)[0]

        result = {
            'is_attack': bool(binary_pred),
            'benign_confidence': float(binary_proba[0]),
            'attack_confidence': float(binary_proba[1]),
            'attack_type': 'Benign',
            'attack_type_confidence': 0.0
        }

        # Stage 2: Multi-class classification (if attack detected)
        if binary_pred == 1:
            X_scaled_multi = self.scaler_multiclass.transform(X)
            multi_pred = self.model_multiclass.predict(X_scaled_multi)[0]
            multi_proba = self.model_multiclass.predict_proba(X_scaled_multi)[0]

            attack_type = self.label_encoder.inverse_transform([multi_pred])[0]
            attack_confidence = float(multi_proba[multi_pred])

            result['attack_type'] = attack_type
            result['attack_type_confidence'] = attack_confidence

        return result

    def handle_completed_flow(self, flow_features: dict) -> None:
        """
        Process a completed flow and make prediction.

        Args:
            flow_features: Dictionary from FlowAggregator.export_features()
        """
        # Make prediction
        prediction = self.predict(flow_features)

        # Update statistics
        self.stats['flows_completed'] += 1

        if prediction['is_attack']:
            self.stats['attacks'] += 1
            attack_type = prediction['attack_type']
            self.stats['attack_types'][attack_type] = self.stats['attack_types'].get(attack_type, 0) + 1

            # Alert
            self.alert_attack(flow_features, prediction)
        else:
            self.stats['benign'] += 1

    def alert_attack(self, flow_features: dict, prediction: dict) -> None:
        """
        Display attack alert.

        Args:
            flow_features: Flow feature dictionary
            prediction: Prediction result dictionary
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        print(f"\n{'='*80}")
        print(f"🚨 ATTACK DETECTED - {timestamp}")
        print(f"{'='*80}")
        print(f"  Type: {prediction['attack_type']}")
        print(f"  Confidence: {prediction['attack_type_confidence']*100:.2f}%")
        print(f"  Attack Probability: {prediction['attack_confidence']*100:.2f}%")
        print(f"\n  Flow Details:")
        print(f"    Duration: {flow_features.get('FLOW_DURATION_MILLISECONDS', 0)} ms")
        print(f"    Packets: IN={flow_features.get('IN_PKTS', 0)}, OUT={flow_features.get('OUT_PKTS', 0)}")
        print(f"    Bytes: IN={flow_features.get('IN_BYTES', 0)}, OUT={flow_features.get('OUT_BYTES', 0)}")
        print(f"    TCP Flags: {flow_features.get('TCP_FLAGS', 0)}")
        print(f"{'='*80}\n")

    def packet_callback(self, pkt) -> None:
        """
        Callback for each captured packet.

        Args:
            pkt: Scapy packet
        """
        self.stats['packets_processed'] += 1

        # Process packet
        self.aggregator.process_packet(pkt)

        # Periodically cleanup old flows
        if self.stats['packets_processed'] % 500 == 0:
            completed_flows = self.aggregator.cleanup_old_flows()

            for flow_features in completed_flows:
                self.handle_completed_flow(flow_features)

            # Display statistics
            if self.stats['packets_processed'] % 5000 == 0:
                self.print_statistics()

    def print_statistics(self) -> None:
        """Display current statistics."""
        print(f"\n{'─'*80}")
        print(f"📊 NIDS Statistics - {datetime.now().strftime('%H:%M:%S')}")
        print(f"{'─'*80}")
        print(f"  Packets Processed: {self.stats['packets_processed']:,}")
        print(f"  Flows Completed: {self.stats['flows_completed']:,}")
        print(f"  Active Flows: {self.aggregator.get_active_flow_count():,}")
        print(f"  Benign: {self.stats['benign']:,} ({self.stats['benign']/max(self.stats['flows_completed'],1)*100:.1f}%)")
        print(f"  Attacks: {self.stats['attacks']:,} ({self.stats['attacks']/max(self.stats['flows_completed'],1)*100:.1f}%)")

        if self.stats['attack_types']:
            print(f"\n  Attack Breakdown:")
            for attack_type, count in sorted(self.stats['attack_types'].items(), key=lambda x: x[1], reverse=True):
                print(f"    {attack_type}: {count}")

        print(f"{'─'*80}\n")

    def start_capture(self, interface: str = None, packet_count: int = None, pcap_file: str = None) -> None:
        """
        Start packet capture and detection.

        Args:
            interface: Network interface to capture on (None for default)
            packet_count: Number of packets to capture (None for unlimited)
            pcap_file: Path to PCAP file for offline analysis (None for live capture)
        """
        if pcap_file:
            print(f"[*] Starting offline analysis from: {pcap_file}")
            print("[*] Press Ctrl+C to stop\n")
            try:
                sniff(offline=pcap_file, prn=self.packet_callback, store=False, count=packet_count)
            except KeyboardInterrupt:
                print("\n[*] Stopping analysis...")
        else:
            print(f"[*] Starting live packet capture...")
            if interface:
                print(f"[*] Interface: {interface}")
            print("[*] Press Ctrl+C to stop\n")

            try:
                sniff(iface=interface, prn=self.packet_callback, store=False, count=packet_count)
            except KeyboardInterrupt:
                print("\n[*] Stopping capture...")

        # Flush remaining flows
        print("[*] Processing remaining flows...")
        remaining_flows = self.aggregator.flush_all_flows()
        for flow_features in remaining_flows:
            self.handle_completed_flow(flow_features)

        # Final statistics
        print("\n" + "="*80)
        print("📊 FINAL STATISTICS")
        print("="*80)
        self.print_statistics()
        print("✅ NIDS shutdown complete")


# Example usage
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Real-time Network Intrusion Detection System')
    parser.add_argument('-i', '--interface', type=str, help='Network interface to capture on')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    parser.add_argument('-r', '--read', type=str, help='Read from PCAP file (offline analysis)')
    parser.add_argument('-m', '--models', type=str, default='./models/model_files/',
                        help='Directory containing model files')

    args = parser.parse_args()

    # Initialize NIDS
    nids = RealtimeNIDS(model_dir=args.models)

    # Start capture
    nids.start_capture(
        interface=args.interface,
        packet_count=args.count,
        pcap_file=args.read
    )
