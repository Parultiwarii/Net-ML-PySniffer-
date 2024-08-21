from flask import Flask, render_template
from scapy.all import *
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB

app = Flask(__name__)

# Packet Sniffing Module
def packet_sniffer():
    packets = sniff(iface="wlp1s0", count=2, timeout=15)  # Capture 100 packets
    return packets

def extract_features(packets):
    data = []
    labels = []

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        else:
            src_ip = "N/A"
            dst_ip = "N/A"

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            src_port = "N/A"
            dst_port = "N/A"

        payload = packet.payload

        # Create a dictionary with the extracted features
        packet_data = {
            'payload': payload,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port
        }

        data.append(packet_data)
        labels.append("malicious")  # Modify this according to your classification logic

    return data, labels

# Machine Learning Model Training Module
def train_model(data, labels):
    vectorizer = CountVectorizer()
    X = vectorizer.fit_transform([f"{packet['payload']} {packet['src_ip']} {packet['dst_ip']} {packet['src_port']} {packet['dst_port']}" for packet in data])
    y = labels

    classifier = MultinomialNB()
    classifier.fit(X, y)

    return vectorizer, classifier

# Determine category based on your specific use case
def determine_category(packet):
    # Implement your logic to determine the category for the packet
    # For example, you can analyze packet features and return 'normal' or 'malicious' based on certain conditions
    # This function should be tailored to your specific use case

    return 'normal'  # Placeholder value

# Home Page
@app.route('/')
def index():
    return render_template('index.html')

# Packet Sniffing and Feature Extraction
@app.route('/sniff')
def sniff_packets():
    packets = packet_sniffer()
    data, labels = extract_features(packets)
    vectorizer, classifier = train_model(data, labels)

    return render_template('features.html', data=data)

if __name__ == '__main__':
    app.run()
