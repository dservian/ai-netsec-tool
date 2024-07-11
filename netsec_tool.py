import scapy.all as scapy
from scapy.layers import http
import pandas as pd
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.ensemble import IsolationForest
import numpy as np
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.exceptions import NotFittedError
import joblib
import threading
import time
import argparse
import logging
from typing import Dict, Any, List
from dataclasses import dataclass, asdict

# Set up parameters
REPORT_INTERVAL_SECONDS = 5 

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@dataclass
class PacketFeatures:
    time: float
    size: float
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: float
    dst_port: float
    http_method: str
    http_host: str
    http_path: str

class NetworkSecurityTool:
    def __init__(self, interface: str, model_path: str = None, initial_training_packets: int = 10000):
        self.interface = interface
        self.packet_buffer: List[Dict[str, Any]] = []
        self.anomaly_buffer: List[Dict[str, Any]] = []
        self.preprocessor = self.create_preprocessor()
        self.is_preprocessor_fitted = False
        self.initial_training_packets = initial_training_packets
        self.model = self.load_model(model_path) if model_path else self.train_new_model()
        self.is_capturing = False

    def capture_packets(self) -> None:
        """Continuously capture packets"""
        self.is_capturing = True
        while self.is_capturing:
            packet = scapy.sniff(iface=self.interface, count=1)[0]
            self.packet_buffer.append(asdict(self.extract_features(packet)))

    def extract_features(self, packet: scapy.Packet) -> PacketFeatures:
        """Extract relevant features from a packet"""
        return PacketFeatures(
            time=float(packet.time),
            size=float(len(packet)),
            protocol=packet.name,
            src_ip=packet[scapy.IP].src if packet.haslayer(scapy.IP) else 'Unknown',
            dst_ip=packet[scapy.IP].dst if packet.haslayer(scapy.IP) else 'Unknown',
            src_port=float(packet.sport) if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP) else np.nan,
            dst_port=float(packet.dport) if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP) else np.nan,
            http_method=packet[http.HTTPRequest].Method.decode() if packet.haslayer(http.HTTPRequest) else 'Unknown',
            http_host=packet[http.HTTPRequest].Host.decode() if packet.haslayer(http.HTTPRequest) else 'Unknown',
            http_path=packet[http.HTTPRequest].Path.decode() if packet.haslayer(http.HTTPRequest) else 'Unknown',
        )

    def create_preprocessor(self) -> ColumnTransformer:
        """Create a preprocessing pipeline"""
        categorical_features = ['protocol', 'src_ip', 'dst_ip', 'http_method', 'http_host', 'http_path']
        numerical_features = ['time', 'size', 'src_port', 'dst_port']

        categorical_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='constant', fill_value='Unknown')),
            ('onehot', OneHotEncoder(handle_unknown='ignore'))
        ])

        numerical_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='mean')),
            ('scaler', StandardScaler())
        ])

        return ColumnTransformer(
            transformers=[
                ('num', numerical_transformer, numerical_features),
                ('cat', categorical_transformer, categorical_features)
            ])

    def is_preprocessor_fitted(self) -> bool:
        try:
            self.preprocessor.transform(pd.DataFrame())
            return True
        except NotFittedError:
            return False

    def preprocess_data(self, data: List[Dict[str, Any]]) -> np.ndarray:
        """Preprocess the extracted features"""
        df = pd.DataFrame(data)
        
        if not self.is_preprocessor_fitted:
            self.preprocessor.fit(df)
            self.is_preprocessor_fitted = True

        return self.preprocessor.transform(df)

    def train_new_model(self) -> IsolationForest:
        """Train a new Isolation Forest model"""
        logging.info(f"Capturing {self.initial_training_packets} packets for initial model training...")
        initial_packets = scapy.sniff(iface=self.interface, count=self.initial_training_packets)
        data = [asdict(self.extract_features(packet)) for packet in initial_packets]
        preprocessed_data = self.preprocess_data(data)
        
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(preprocessed_data)
        logging.info("New model trained successfully.")
        return model

    def load_model(self, model_path: str) -> IsolationForest:
        """Load a pre-trained model"""
        logging.info(f"Loading model from {model_path}")
        return joblib.load(model_path)

    def save_model(self, model_path: str) -> None:
        """Save the current model"""
        joblib.dump(self.model, model_path)
        logging.info(f"Model saved to {model_path}")

    def detect_anomalies(self) -> None:
        """Detect anomalies in the packet buffer"""
        if not self.packet_buffer:
            return
        
        try:
            data = self.preprocess_data(self.packet_buffer)
            predictions = self.model.predict(data)
            anomalies = np.where(predictions == -1)[0]
            
            for idx in anomalies:
                anomaly = self.packet_buffer[idx]
                anomaly['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S')
                self.anomaly_buffer.append(anomaly)
                logging.warning(f"Anomaly detected: {anomaly}")
            
            self.packet_buffer.clear()
        except Exception as e:
            logging.error(f"Error in detect_anomalies: {str(e)}")
            self.packet_buffer.clear()

    def start(self) -> None:
        """Start the network security tool"""
        capture_thread = threading.Thread(target=self.capture_packets)
        capture_thread.start()
        
        try:
            while True:
                self.detect_anomalies()
                time.sleep(REPORT_INTERVAL_SECONDS)
        except KeyboardInterrupt:
            self.stop()
        
        capture_thread.join()

    def stop(self) -> None:
        """Stop the network security tool"""
        self.is_capturing = False
        logging.info("Stopping network capture...")

def main() -> None:
    parser = argparse.ArgumentParser(description="AI-Powered Network Security Tool")
    parser.add_argument("--interface", required=True, help="Network interface to monitor")
    parser.add_argument("--initial-packets", type=int, default=10000, help="Number of packets for the initial training")
    parser.add_argument("--model", help="Path to pre-trained model")
    parser.add_argument("--save-model", help="Path to save the trained model")
    args = parser.parse_args()

    tool = NetworkSecurityTool(args.interface, args.model, args.initial_packets)
    
    logging.info(f"Starting Network Security Tool on interface {args.interface}")
    tool.start()
    
    if args.save_model:
        tool.save_model(args.save_model)

if __name__ == "__main__":
    main()