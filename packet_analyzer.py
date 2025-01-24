import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict
import re
from dataclasses import dataclass
from typing import List, Dict, Optional, Set
import os
import statistics
from datetime import datetime

@dataclass
class SecurityAlert:
    source_ip: str
    hostname: str
    total_packets: int
    packet_size_mean: float
    syn_packets: int
    targeted_ports: int
    behavior_pattern: str
    related_ips: Set[str]

@dataclass
class NetworkTraffic:
    source: str
    destination: str
    tcp_flags: str
    size: int
    time: str
    dest_port: Optional[int] = None

class ThreatDetector:
    def __init__(self):
        self.threats = defaultdict(lambda: {
            'traffic': [],
            'sizes': [],
            'syn_packets': 0,
            'ports': set(),
            'hostname': 'Unknown',
            'related_ips': set()
        })

    def classify_behavior(self, syn_packets: int, ports: int, size: float) -> str:
        patterns = []
        if ports > 4:
            patterns.append("Port Enumeration")
        if syn_packets > 90:
            patterns.append("SYN Attack")
        elif syn_packets > 4:
            patterns.append("Suspicious SYN Activity")
        return " | ".join(patterns) if patterns else "Unknown Pattern"

    def analyze_threats(self) -> Dict:
        consolidated = {}
        processed = set()
        
        sorted_threats = sorted(
            self.threats.items(),
            key=lambda x: len(x[1]['traffic']),
            reverse=True
        )
        
        for ip, data in sorted_threats:
            if ip in processed:
                continue
            consolidated[ip] = data.copy()
            processed.add(ip)
        
        return consolidated

class TrafficMonitor:
    def __init__(self):
        self.traffic_data: List[NetworkTraffic] = []
        self.flag_distribution = defaultdict(int)
        self.size_distribution = []
        self.packet_total = 0
        self.potential_threats = defaultdict(lambda: {
            'syn_count': 0,
            'ports': set(),
            'sizes': []
        })
        self.threat_detector = ThreatDetector()
    
    def generate_report_content(self, alerts: List[SecurityAlert]) -> str:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Security Analysis</title>
            <style>
                body {{ 
                    font-family: 'Arial', sans-serif;
                    background: linear-gradient(135deg, #1a237e, #311b92);
                    color: #ffffff;
                    margin: 0;
                    padding: 3rem;
                }}
                h1, h2, h3 {{ 
                    color: #ffd700;
                    font-weight: 800;
                    text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
                }}
                .alert {{ 
                    background: rgba(255,255,255,0.1);
                    backdrop-filter: blur(10px);
                    border-radius: 15px;
                    margin: 2rem 0;
                    padding: 2.5rem;
                    box-shadow: 0 8px 32px rgba(0,0,0,0.3);
                }}
                .threat-level {{ 
                    color: #ff4081;
                    font-size: 1.2em;
                    letter-spacing: 2px;
                }}
                .metrics {{ 
                    background: rgba(0,0,0,0.2);
                    padding: 1.5rem;
                    border-radius: 10px;
                    border: 1px solid rgba(255,255,255,0.2);
                    margin-top: 1rem;
                }}
                #charts {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 2rem;
                    margin: 3rem 0;
                }}
                img {{
                    width: 100%;
                    border-radius: 12px;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.4);
                    transition: transform 0.3s ease;
                }}
                img:hover {{
                    transform: scale(1.02);
                }}
            </style>
        </head>
        <body>
            <h1>Security Analysis Report</h1>
            <p>Generated: {timestamp}</p>

            <div id="charts">
                <div>
                    <h3>TCP Flags Analysis</h3>
                    <img src="flag_analysis.png" alt="TCP Flags">
                </div>
                <div>
                    <h3>Packet Size Analysis</h3>
                    <img src="size_analysis.png" alt="Packet Sizes">
                </div>
            </div>

            <h2>Security Alerts</h2>
            {"".join(f'''
            <div class="alert">
                <h3>Alert Details</h3>
                <p><b>IP:</b> {alert.source_ip}</p>
                <p class="threat-level">Pattern: {alert.behavior_pattern}</p>
                <div class="metrics">
                    <p>Packets: {alert.total_packets}</p>
                    <p>Avg Size: {alert.packet_size_mean:.1f} bytes</p>
                    <p>SYN Count: {alert.syn_packets}</p>
                    <p>Port Count: {alert.targeted_ports}</p>
                </div>
            </div>
            ''' for alert in alerts)}
        </body>
        </html>
        """

    def get_alerts(self) -> List[SecurityAlert]:
        alerts = []
        for ip, data in self.threat_detector.threats.items():
            if not data['traffic']:
                continue
                
            avg = statistics.mean(data['sizes']) if data['sizes'] else 0
            alert = SecurityAlert(
                source_ip=ip,
                hostname=data['hostname'],
                total_packets=len(data['traffic']),
                packet_size_mean=avg,
                syn_packets=data['syn_packets'],
                targeted_ports=len(data['ports']),
                behavior_pattern=self.threat_detector.classify_behavior(
                    data['syn_packets'],
                    len(data['ports']),
                    avg
                ),
                related_ips=data['related_ips']
            )
            alerts.append(alert)
        
        return sorted(alerts, key=lambda x: x.total_packets, reverse=True)

    def save_report(self, output_path: str):
        alerts = self.get_alerts()
        html = self.generate_report_content(alerts)
        with open(os.path.join(output_path, 'security_report.html'), 'w', encoding='utf-8') as f:
            f.write(html)

    def parse_traffic(self, line: str) -> Optional[NetworkTraffic]:
        if not line.strip() or line.startswith('0x'):
            return None

        patterns = {
            'time': r'^(\d{2}:\d{2}:\d{2}\.\d{6})',
            'ip': r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            'flags': r'Flags \[(.*?)\]',
            'size': r'length (\d+)',
            'port': r'\.(\d+)'
        }

        try:
            matches = {k: re.search(v, line) for k, v in patterns.items()}
            ips = re.findall(patterns['ip'], line)
            ports = re.findall(patterns['port'], line)

            if all([matches['time'], ips, matches['flags'], matches['size']]):
                return NetworkTraffic(
                    source=ips[0],
                    destination=ips[1] if len(ips) > 1 else None,
                    tcp_flags=matches['flags'].group(1),
                    size=int(matches['size'].group(1)),
                    time=matches['time'].group(1),
                    dest_port=int(ports[1]) if len(ports) > 1 else None
                )
        except (IndexError, AttributeError, ValueError):
            pass
        return None

    def process_traffic(self, traffic: NetworkTraffic):
        if not traffic:
            return

        self.packet_total += 1
        self.size_distribution.append(traffic.size)

        if traffic.tcp_flags:
            flag_type = self._categorize_flags(traffic.tcp_flags)
            self.flag_distribution[flag_type] += 1

            if 'S' in traffic.tcp_flags and '.' not in traffic.tcp_flags:
                threat_data = self.threat_detector.threats[traffic.source]
                threat_data['syn_packets'] += 1
                if traffic.dest_port:
                    threat_data['ports'].add(traffic.dest_port)
                threat_data['sizes'].append(traffic.size)
                threat_data['hostname'] = traffic.source
                threat_data['related_ips'].add(traffic.source)
                threat_data['traffic'].append(traffic)

    def _categorize_flags(self, flags: str) -> str:
        categories = {
            ('S', '.'): 'SYN-ACK',
            ('S',): 'SYN',
            ('P', '.'): 'PSH-ACK',
            ('F', '.'): 'FIN-ACK',
            ('.',): 'ACK'
        }
        
        for flag_combo, category in categories.items():
            if all(f in flags for f in flag_combo):
                return category
        return flags

    def analyze_log(self, filepath: str):
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                if traffic := self.parse_traffic(line):
                    self.process_traffic(traffic)

    def create_visualizations(self, output_path: str):
        os.makedirs(output_path, exist_ok=True)
        
        if self.size_distribution:
            plt.figure(figsize=(12, 6))
            bins = np.linspace(0, max(self.size_distribution), 40)
            plt.hist(self.size_distribution, bins=bins, color='#4a148c', 
                    edgecolor='#e1bee7', alpha=0.8)
            plt.title('Packet Size Distribution')
            plt.xlabel('Size (bytes)')
            plt.ylabel('Frequency')
            plt.grid(True, alpha=0.3)
            plt.savefig(os.path.join(output_path, 'size_analysis.png'),
                       facecolor='#1a237e', edgecolor='none')
            plt.close()

        if self.flag_distribution:
            plt.figure(figsize=(10, 10))
            flags = list(self.flag_distribution.keys())
            counts = list(self.flag_distribution.values())
            colors = ['#ff4081', '#ffd700', '#18ffff', '#69f0ae', '#b388ff']
            plt.pie(counts, labels=flags, autopct='%1.1f%%', colors=colors)
            plt.title('TCP Flag Distribution', color='white')
            plt.axis('equal')
            plt.savefig(os.path.join(output_path, 'flag_analysis.png'),
                       facecolor='#1a237e', edgecolor='none')
            plt.close()

    def get_metrics(self) -> Dict:
        return {
            'packets_processed': self.packet_total,
            'unique_sizes': len(set(self.size_distribution)),
            'mean_size': statistics.mean(self.size_distribution) if self.size_distribution else 0,
            'threat_count': len(self.potential_threats),
            'flags': dict(self.flag_distribution)
        }

def main():
    monitor = TrafficMonitor()
    
    import tkinter as tk
    from tkinter import filedialog
    root = tk.Tk()
    root.withdraw()
    
    log_path = filedialog.askopenfilename(
        title='Select tcpdump log file',
        filetypes=[('Text files', '*.txt'), ('All files', '*.*')]
    )
    
    if not log_path:
        print("No file selected")
        return

    print(f"Analyzing: {log_path}")
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(base_dir, 'analysis_output')
    os.makedirs(output_dir, exist_ok=True)
    
    monitor.analyze_log(log_path)
    monitor.create_visualizations(output_dir)
    monitor.save_report(output_dir)
    
    metrics = monitor.get_metrics()
    print("\nAnalysis Summary:")
    print(f"Total packets: {metrics['packets_processed']}")
    print(f"Distinct sizes: {metrics['unique_sizes']}")
    print(f"Average size: {metrics['mean_size']:.2f} bytes")
    print(f"Potential threats: {metrics['threat_count']}")
    
    print("\nTCP Flags Distribution:")
    for flag, count in metrics['flags'].items():
        print(f"{flag}: {count}")

    print(f"\nVisualizations saved to: {output_dir}")
    
    print("\nDetected Threats:")
    for alert in monitor.get_alerts():
        print(f"\nSource: {alert.source_ip}")
        print(f"Pattern: {alert.behavior_pattern}")
        print(f"Packet count: {alert.total_packets}")
        print(f"Targeted ports: {alert.targeted_ports}")
        print(f"Average packet size: {alert.packet_size_mean:.2f} bytes")

if __name__ == "__main__":
    main()