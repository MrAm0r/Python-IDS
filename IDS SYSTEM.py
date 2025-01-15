import pyshark
from sklearn.ensemble import IsolationForest
import numpy as np

# List to store anomaly packets
anomaly_packets = []

# Function to convert packet to features
def packet_to_features(packet):
    features = []
    features.append(len(packet)) # For packet length
    return features

# Function to detect anomalies in network packets
def detect_anomaly(packet):
    features = np.array(packet_to_features(packet)).reshape(1, -1) # Converts packet to features and reshape for model input
    if model.predict(features) == -1: # Predicts using model
        print(f"Anomaly detected: Packet length {len(packet)}")
        anomaly_packets.append(packet) # Store the anomaly packet

# Capturing the packet using pyshark
def capture_packets(count=1000):
    capture = pyshark.LiveCapture(interface='Wi-Fi', output_file='packets.pcap') # Capturing packets over Wi-Fi & saving them to a pcap file for veiwing in wireshark
    packets = []
    for packet in capture.sniff_continuously(packet_count=count):
        packets.append(packet)
    return packets


# Capturing the packets for training
print("Capturing packets for training....")
packets = capture_packets(1000)
X = np.array([packet_to_features(packet) for packet in packets])

# Checking if X is correctly defined
print(f"Feature matrix X shape: {X.shape}")

# Training the model
print("Training the model......") 
model = IsolationForest(contamination=0.01)
model.fit(X)

# Starting the intrusion detection
print("Starting the intrusion detection...")
capture = pyshark.LiveCapture(interface='Wi-Fi') 
#Manully stopping the packet capturing
try:
    for packet in capture.sniff_continuously():
        detect_anomaly(packet)
except (KeyboardInterrupt, EOFError):
    print("Packet capture stopped by user or EOFError encountered.")


# Viewing the packets after the detection
print(f"Total anomalies detected: {len(anomaly_packets)}")
for anomaly in anomaly_packets:
    print(anomaly)

