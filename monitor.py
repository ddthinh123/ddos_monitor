import pandas as pd
import numpy as np
import pickle
from scapy.all import sniff
from sklearn.ensemble import RandomForestClassifier

class DDoSMonitor:
    def __init__(self, model_file):
        # Tải mô hình đã huấn luyện
        self.classifier = self.load_model(model_file)

    def load_model(self, model_file):
        try:
            with open(model_file, 'rb') as file:
                model = pickle.load(file)
            print("Model loaded successfully.")
            return model
        except Exception as e:
            print(f"Error loading model: {e}")
            return None

    def packet_features(self, packet):
        if packet.haslayer('IP'):
            ip_layer = packet['IP']
            return {
                'Destination Port': ip_layer.dport,
                'Flow Duration': 1,  # Giả định mỗi gói là 1 giây
                'Total Fwd Packets': 1,  # Chỉ gói này
                'Total Backward Packets': 0,  # Chưa có gói phản hồi
                'Total Length of Fwd Packets': len(packet),
                'Total Length of Bwd Packets': 0,
                'Fwd Packet Length Max': len(packet),
                'Fwd Packet Length Min': len(packet),
                'Fwd Packet Length Mean': len(packet),
                'Fwd Packet Length Std': 0,
                'Bwd Packet Length Max': 0,
                'Bwd Packet Length Min': 0,
                'Bwd Packet Length Mean': 0,
                'Bwd Packet Length Std': 0,
                'Flow Bytes/s': len(packet),
                'Flow Packets/s': 1,
                'Flow IAT Mean': 1,
                'Flow IAT Std': 0,
                'Flow IAT Max': 1,
                'Flow IAT Min': 1,
                'Fwd IAT Total': 1,
                'Fwd IAT Mean': 1,
                'Fwd IAT Std': 0,
                'Fwd IAT Max': 1,
                'Fwd IAT Min': 1,
                'Bwd IAT Total': 0,
                'Bwd IAT Mean': 0,
                'Bwd IAT Std': 0,
                'Bwd IAT Max': 0,
                'Bwd IAT Min': 0,
                'Fwd PSH Flags': 0,
                'Bwd PSH Flags': 0,
                'Fwd URG Flags': 0,
                'Bwd URG Flags': 0,
                'Fwd Header Length': 20,  # Chiều dài tiêu đề IP
                'Bwd Header Length': 0,
                'Fwd Packets/s': 1,
                'Bwd Packets/s': 0,
                'Min Packet Length': len(packet),
                'Max Packet Length': len(packet),
                'Packet Length Mean': len(packet),
                'Packet Length Std': 0,
                'Packet Length Variance': 0,
                'FIN Flag Count': 0,
                'SYN Flag Count': 0,
                'RST Flag Count': 0,
                'PSH Flag Count': 0,
                'ACK Flag Count': 0,
                'URG Flag Count': 0,
                'CWE Flag Count': 0,
                'ECE Flag Count': 0,
                'Down/Up Ratio': 1,
                'Average Packet Size': len(packet),
                'Avg Fwd Segment Size': len(packet),
                'Avg Bwd Segment Size': 0,
                'Fwd Header Length.1': 20,
                'Fwd Avg Bytes/Bulk': len(packet),
                'Fwd Avg Packets/Bulk': 1,
                'Fwd Avg Bulk Rate': len(packet),
                'Bwd Avg Bytes/Bulk': 0,
                'Bwd Avg Packets/Bulk': 0,
                'Bwd Avg Bulk Rate': 0,
                'Subflow Fwd Packets': 1,
                'Subflow Fwd Bytes': len(packet),
                'Subflow Bwd Packets': 0,
                'Subflow Bwd Bytes': 0,
                'Init_Win_bytes_forward': 0,
                'Init_Win_bytes_backward': 0,
                'act_data_pkt_fwd': 0,
                'min_seg_size_forward': 0,
                'Active Mean': 1,
                'Active Std': 0,
                'Active Max': 1,
                'Active Min': 1,
                'Idle Mean': 0,
                'Idle Std': 0,
                'Idle Max': 0,
                'Idle Min': 0
            }
        return None

    def detect_ddos(self, packet):
        features = self.packet_features(packet)
        if features:
            df = pd.DataFrame([features])
            prediction = self.classifier.predict(df)
            if prediction[0] == 'DDoS':
                print(f"DDoS attack detected from {packet['IP'].src} to {packet['IP'].dst}!")

    def start_monitoring(self):
        print("Starting DDoS monitoring...")
        sniff(prn=self.detect_ddos, filter="ip", store=0)

if __name__ == "__main__":
    monitor = DDoSMonitor(model_file='model.pkl')
    monitor.start_monitoring()
