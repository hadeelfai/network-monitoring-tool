from scapy.all import sniff, conf, Ether, IP, TCP, UDP
import threading
from collections import defaultdict
import time
import logging
import matplotlib.pyplot as plt
import signal
import sys

#the record
logging.basicConfig(
    filename="network_events.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

throughput_data = defaultdict(int)
historical_throughput = defaultdict(list)
latency_data = {}
packet_count = defaultdict(int)
unique_ips = set()
unique_macs = set()
average_packet_size = defaultdict(list)
connection_count = defaultdict(int)
stop_flag = threading.Event()

#process and log packet details
def log_packet(packet):
    try:
        if packet.haslayer(Ether):
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            unique_macs.update([src_mac, dst_mac])
        
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            protocol = {6: "TCP", 17: "UDP"}.get(proto, "IP")
            size = len(packet)
            
             # Log packet details
            logging.info(f"MAC Src: {src_mac}, MAC Dst: {dst_mac}, Src IP: {src_ip}, Dst IP: {dst_ip}, Protocol: {protocol}, Size: {size} bytes")
            
            #update metrics
            unique_ips.update([src_ip, dst_ip])
            packet_count[protocol] += 1
            throughput_data[protocol] += size
            average_packet_size[protocol].append(size)

            if protocol in ["TCP", "UDP"]:
                conn_key = (src_ip, dst_ip)
                connection_count[protocol] += 1

            if protocol in ["TCP", "UDP"]:
                conn_key = (src_ip, dst_ip)
                timestamp = time.time()
                if conn_key not in latency_data:
                    latency_data[conn_key] = {"start": timestamp}
                else:
                    latency_data[conn_key]["end"] = timestamp
    except Exception as e:
        print(f"Error processing packet: {e}")

#calculate and log throughput
def calculate_throughput(interval=10):
    while not stop_flag.is_set():
        time.sleep(interval)
        print("\n--- Throughput (bps) ---")
        for protocol, byte_count in throughput_data.items():
            throughput_bps = (byte_count * 8) / interval
            print(f"{protocol}: {throughput_bps:.2f} bps")
            historical_throughput[protocol].append(throughput_bps)
        throughput_data.clear()

def calculate_latency():
    total_latency = 0
    count = 0
    for conn_key, timestamps in latency_data.items():
        if "start" in timestamps and "end" in timestamps:
            latency = (timestamps["end"] - timestamps["start"]) * 1000
            total_latency += latency
            count += 1
    avg_latency = total_latency / count if count > 0 else 0
    print(f"\nAverage Latency: {avg_latency:.2f} ms")

#display periodic statistical information
def display_periodic_stats(interval=30):
    while not stop_flag.is_set():
        time.sleep(interval)
        print("\n--- 30-Second Overview ---")
        print(f"Number of connections per protocol: {dict(connection_count)}")
        print("Average packet size per protocol:")
        for protocol, sizes in average_packet_size.items():
            avg_size = sum(sizes) / len(sizes) if sizes else 0
            print(f"  {protocol}: {avg_size:.2f} bytes")
        print(f"Number of unique IP addresses: {len(unique_ips)}")
        print(f"Number of unique MAC addresses: {len(unique_macs)}")

def visualize_results():
    plt.figure(figsize=(15, 5))
    
    plt.subplot(131)
    plt.title("Throughput Over Time")
    for protocol, values in historical_throughput.items():
        plt.plot(range(len(values)), values, label=protocol)
    plt.xlabel("Time Intervals")
    plt.ylabel("Throughput (bps)")
    plt.legend()

    latencies = [
        (timestamps["end"] - timestamps["start"]) * 1000
        for timestamps in latency_data.values()
        if "start" in timestamps and "end" in timestamps
    ]
    plt.subplot(132)
    plt.title("Latency Distribution")
    plt.hist(latencies, bins=5, color="blue", alpha=0.7)
    plt.xlabel("Latency (ms)")
    plt.ylabel("Frequency")

    plt.subplot(133)
    plt.title("Protocol Usage & Unique Addresses")
    
    metrics = {
        'TCP': packet_count.get('TCP', 0),
        'UDP': packet_count.get('UDP', 0),
        'Ethernet': len(unique_macs),  
        'Unique IPs': len(unique_ips),
        'Unique MACs': len(unique_macs)
    }
    
    bars = plt.bar(list(metrics.keys()), list(metrics.values()))
    
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']
    for bar, color in zip(bars, colors):
        bar.set_color(color)
    
    # Rotate x-axis labels for better readability
    plt.xticks(rotation=45, ha='right')
    plt.xlabel("Protocol/Metric")
    plt.ylabel("Count")
    
    # Adjust layout to prevent label cutoff
    plt.tight_layout()
    plt.show()

def signal_handler(sig, frame):
    print("\nStopping packet capture...")
    stop_flag.set()
    
    calculate_latency()
    
    visualize_results()
    
    print("\n--- Final Network Statistics ---")
    print(f"Number of unique IP addresses: {len(unique_ips)}")
    print(f"Number of unique MAC addresses: {len(unique_macs)}")
    print(f"Packet counts per protocol: {dict(packet_count)}")
    total_connections = sum(connection_count.values())
    print(f"Total number of connections: {total_connections}")
    print(f"Connections per protocol: {dict(connection_count)}")
    
    print("Average packet size per protocol:")
    for protocol, sizes in average_packet_size.items():
        avg_size = sum(sizes) / len(sizes) if sizes else 0
        print(f"  {protocol}: {avg_size:.2f} bytes")
    
    sys.exit(0)

def start_sniffing():
    signal.signal(signal.SIGINT, signal_handler)
    interface = conf.iface
    print(f"Starting packet capture on {interface}. Press Ctrl+C to stop.")
    
    threading.Thread(target=calculate_throughput, daemon=True).start()
    threading.Thread(target=display_periodic_stats, daemon=True).start()
    
    sniff(iface=interface, prn=log_packet, store=False)

if __name__ == "__main__":
    start_sniffing()