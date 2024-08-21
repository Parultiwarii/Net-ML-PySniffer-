from flask import Flask, render_template, request
from scapy.all import sniff, TCP, UDP, IP
import os

app = Flask(__name__)
# app1 = Flask(__name__,static_folder = 'css')
# Global variables
captured_packets = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sniff', methods=['POST'])
def start_sniffing():
    global captured_packets

    # Clear the captured packets list
    captured_packets = []

    # Start sniffing packets
    sniff_packets()

    return render_template('index.html')

@app.route('/features')
def show_features():
    return render_template('features.html', packets=captured_packets)

def sniff_packets():
    sniffed_packets = sniff(filter="tcp or udp", count=10)

    for packet in sniffed_packets:
        if IP in packet:
            protocol = packet[IP].proto
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if protocol == 6 and TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                payloads = packet[TCP].payload
            elif protocol == 17 and UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                payloads = packet[UDP].payload
            else:
                continue

            packet_data = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'payloads': payloads,
                'protocol': protocol
            }

            captured_packets.append(packet_data)

if __name__ == '__main__':
    app.run(debug=True)
