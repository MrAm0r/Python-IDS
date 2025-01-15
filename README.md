# Intrusion Detection System

This project implements a simple Intrusion Detection System (IDS) using network packet capture and anomaly detection with Isolation Forest.

## Requirements

- Python 3.x
- pyshark
- scikit-learn
- numpy

## Installation

1. Install the required Python packages:
    ```sh
    pip install pyshark scikit-learn numpy
    ```

## Usage

1. Capture packets for training:
    ```sh
    python IDS_SYSTEM.py
    ```

2. The script will capture 1000 packets for training and then start real-time intrusion detection.

3. Anomalies detected will be printed to the console and stored in the [anomaly_packets](http://_vscodecontentref_/0) list.

## Files

- `IDS_SYSTEM.py`: Main script for capturing packets, training the model, and detecting anomalies.
- [packets.pcap](http://_vscodecontentref_/1): File where captured packets are saved for viewing in Wireshark.

## How It Works

1. **Packet Capture**: The script captures network packets using [pyshark](http://_vscodecontentref_/2) and saves them to [packets.pcap](http://_vscodecontentref_/3).
2. **Feature Extraction**: Each packet is converted to a feature vector based on its length.
3. **Model Training**: An Isolation Forest model is trained on the captured packets to learn normal network behavior.
4. **Anomaly Detection**: The trained model is used to detect anomalies in real-time packet capture. Anomalous packets are printed and stored.

## Stopping the Script

To stop the packet capture and intrusion detection, press `Ctrl+C` in the terminal.

## License

This project is licensed under the MIT License.
