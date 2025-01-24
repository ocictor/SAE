import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict
import re
from dataclasses import dataclass
from typing import List, Dict, Optional
import os
import statistics
from datetime import datetime
from typing import Set

# 1. La classe AttackerProfile qui définit la structure
@dataclass
class AttackerProfile:
    ip_address: str
    hostname: str
    packet_count: int
    avg_packet_size: float
    syn_count: int
    unique_ports_targeted: int
    attack_type: str
    original_ips: Set[str]

# 2. La méthode qui crée les profils dans AttackAnalyzer
def get_top_attackers(self, limit: int = 5) -> List[AttackerProfile]:
    grouped_attackers = self._group_similar_attackers()
    profiles = []
    
    for ip, data in grouped_attackers.items():
        if not data['packets']:
            continue
            
        avg_size = statistics.mean(data['packet_sizes']) if data['packet_sizes'] else 0
        profile = AttackerProfile(
            ip_address=ip,
            hostname=data['hostname'],
            packet_count=len(data['packets']),
            avg_packet_size=avg_size,
            syn_count=data['syn_count'],
            unique_ports_targeted=len(data['ports_targeted']),
            attack_type=self._determine_attack_type(
                syn_count=data['syn_count'],
                unique_ports=len(data['ports_targeted']),
                avg_packet_size=avg_size
            ),
            original_ips=data['original_ips']
        )
        profiles.append(profile)

@dataclass
class NetworkPacket:
    source_ip: str
    destination_ip: str
    flags: str
    length: int
    timestamp: str
    port: Optional[int] = None

class AttackAnalyzer:
    def __init__(self):
        self.attackers = defaultdict(lambda: {
            'packets': [],
            'packet_sizes': [],
            'syn_count': 0,
            'ports_targeted': set(),
            'hostname': 'Unknown',
            'original_ips': set()
        })

    def _determine_attack_type(self, syn_count: int, unique_ports: int, avg_packet_size: float) -> str:
        attack_types = []
        if unique_ports >= 5:
            attack_types.append("Port Scan")
        if syn_count >= 100:
            attack_types.append("DDoS (SYN Flood)")
        elif syn_count >= 5:
            attack_types.append("Potential SYN Flood")
        return " + ".join(attack_types) if attack_types else "Suspicious Activity"

    def _group_similar_attackers(self):
        """Groupe les attaquants similaires ensemble."""
        grouped = {}
        processed = set()
        
        # Trie les attaquants par nombre de paquets
        sorted_attackers = sorted(
            self.attackers.items(),
            key=lambda x: len(x[1]['packets']),
            reverse=True
        )
        
        for attacker1, data1 in sorted_attackers:
            if attacker1 in processed:
                continue
                
            group_key = attacker1
            group_data = data1.copy()
            processed.add(attacker1)
            grouped[group_key] = group_data
        
        return grouped

class PacketAnalyzer:
    def __init__(self):
        self.packets: List[NetworkPacket] = []
        self.tcp_flags = defaultdict(int)
        self.packet_sizes = []
        self.total_packets = 0
        self.suspicious_ips = defaultdict(lambda: {
            'syn_count': 0,
            'ports': set(),
            'packet_sizes': []
        })
        self.attack_analyzer = AttackAnalyzer()
    
    def _generate_html_template(self, attackers: List[AttackerProfile]) -> str:
        """Génère le template HTML pour le rapport."""
        date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Analyse de Sécurité Réseau</title>
            <style>
                body {{ 
                    font-family: Arial, sans-serif; 
                    line-height: 1.6; 
                    margin: 0; 
                    padding: 20px; 
                }}
                .container {{ 
                    max-width: 1200px; 
                    margin: 0 auto; 
                }}
                .attacker-card {{
                    border: 1px solid #ddd;
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 5px;
                    background-color: #f8f9fa;
                }}
                .attack-type {{ color: #dc3545; font-weight: bold; }}
                .stats {{ color: #0056b3; }}
                .visualizations {{
                    display: flex;
                    flex-wrap: wrap;
                    gap: 20px;
                    margin: 20px 0;
                }}
                .visualization-card {{
                    flex: 1;
                    min-width: 300px;
                    border: 1px solid #ddd;
                    padding: 15px;
                    border-radius: 5px;
                }}
                .visualization-card img {{
                    width: 100%;
                    height: auto;
                    border-radius: 5px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Analyse de Sécurité Réseau</h1>
                <p><em>Généré le {date_str}</em></p>

                <div class="visualizations">
                    <div class="visualization-card">
                        <h2>Distribution des Flags TCP</h2>
                        <img src="tcp_flags.png" alt="Distribution des Flags TCP">
                    </div>
                    <div class="visualization-card">
                        <h2>Distribution des tailles de paquets</h2>
                        <img src="packet_sizes.png" alt="Distribution des tailles de paquets">
                    </div>
                </div>

                <h2>Profils des Attaques</h2>
        """
        
        # Ajout des attaquants
        for attacker in attackers:
            html += f"""
                <div class="attacker-card">
                    <h3>Attack Profile</h3>
                    <p><strong>Destination:</strong> {attacker.ip_address}</p>
                    <p class="attack-type">Attack Type: {attacker.attack_type}</p>
                    <div class="stats">
                        <p>Total Packets: {attacker.packet_count}</p>
                        <p>Average Packet Size: {attacker.avg_packet_size:.2f} bytes</p>
                        <p>SYN Packets: {attacker.syn_count}</p>
                        <p>Unique Ports Targeted: {attacker.unique_ports_targeted}</p>
                    </div>
                </div>
            """
        
        # Fermeture du HTML
        html += """
            </div>
        </body>
        </html>
        """
        return html

    def get_attackers(self) -> List[AttackerProfile]:
        """Retourne les profils des attaquants."""
        profiles = []
        for ip, data in self.attack_analyzer.attackers.items():
            if not data['packets']:
                continue
                
            avg_size = statistics.mean(data['packet_sizes']) if data['packet_sizes'] else 0
            profile = AttackerProfile(
                ip_address=ip,
                hostname=data['hostname'],
                packet_count=len(data['packets']),
                avg_packet_size=avg_size,
                syn_count=data['syn_count'],
                unique_ports_targeted=len(data['ports_targeted']),
                attack_type=self.attack_analyzer._determine_attack_type(
                    data['syn_count'],
                    len(data['ports_targeted']),
                    avg_size
                ),
                original_ips=data['original_ips']
            )
            profiles.append(profile)
        
        return sorted(profiles, key=lambda x: x.packet_count, reverse=True)

    def generate_html_report(self, output_dir: str):
        attackers = self.get_attackers()
        html_content = self._generate_html_template(attackers)
        report_path = os.path.join(output_dir, 'analysis_report.html')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)


    def parse_packet(self, line: str) -> Optional[NetworkPacket]:
        """Parse une ligne de tcpdump et retourne un objet NetworkPacket."""
        if not line.strip() or line.strip().startswith('0x'):
            return None

        # Pattern pour l'extraction des données
        timestamp_pattern = r'^(\d{2}:\d{2}:\d{2}\.\d{6})'
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        flags_pattern = r'Flags \[(.*?)\]'
        length_pattern = r'length (\d+)'
        port_pattern = r'\.(\d+)'

        try:
            # Extraction des informations
            timestamp = re.search(timestamp_pattern, line)
            ips = re.findall(ip_pattern, line)
            flags = re.search(flags_pattern, line)
            length = re.search(length_pattern, line)
            ports = re.findall(port_pattern, line)

            if timestamp and ips and flags and length:
                packet = NetworkPacket(
                    source_ip=ips[0],
                    destination_ip=ips[1] if len(ips) > 1 else None,
                    flags=flags.group(1),
                    length=int(length.group(1)),
                    timestamp=timestamp.group(1),
                    port=int(ports[1]) if len(ports) > 1 else None
                )
                return packet
        except (IndexError, AttributeError, ValueError):
            pass
        return None

    def analyze_packet(self, packet: NetworkPacket):
        """Analyse un paquet réseau."""
        if not packet:
            return

        self.total_packets += 1
        self.packet_sizes.append(packet.length)

        # Analyse des flags
        if packet.flags:
            flag_type = self._determine_flag_type(packet.flags)
            self.tcp_flags[flag_type] += 1

            # Détection des paquets suspects (SYN)
            if 'S' in packet.flags and '.' not in packet.flags:
                # Mise à jour de l'AttackAnalyzer
                attacker = self.attack_analyzer.attackers[packet.source_ip]
                attacker['syn_count'] += 1
                if packet.port:
                    attacker['ports_targeted'].add(packet.port)
                attacker['packet_sizes'].append(packet.length)
                attacker['hostname'] = packet.source_ip
                attacker['original_ips'].add(packet.source_ip)
                attacker['packets'].append(packet)

    def _determine_flag_type(self, flags: str) -> str:
        """Détermine le type de flag TCP."""
        if 'S' in flags and '.' in flags:
            return 'SYN-ACK'
        elif 'S' in flags:
            return 'SYN'
        elif 'P' in flags and '.' in flags:
            return 'PUSH-ACK'
        elif 'F' in flags and '.' in flags:
            return 'FIN-ACK'
        elif '.' in flags:
            return 'ACK'
        return flags

    def analyze_file(self, filepath: str):
        """Analyse un fichier tcpdump."""
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                packet = self.parse_packet(line)
                if packet:
                    self.analyze_packet(packet)

    def generate_visualizations(self, output_dir: str):
        """Génère les visualisations des données analysées."""
        os.makedirs(output_dir, exist_ok=True)

        # Distribution des tailles de paquets
        plt.figure(figsize=(12, 6))
        if self.packet_sizes:
            bins = np.linspace(0, max(self.packet_sizes), 50)
            plt.hist(self.packet_sizes, bins=bins, color='skyblue', edgecolor='black')
            plt.title('Distribution des tailles de paquets')
            plt.xlabel('Taille (octets)')
            plt.ylabel('Nombre de paquets')
            plt.grid(True, alpha=0.3)
            plt.savefig(os.path.join(output_dir, 'packet_sizes.png'))
        plt.close()

        # Distribution des flags TCP
        plt.figure(figsize=(10, 10))
        if self.tcp_flags:
            labels = list(self.tcp_flags.keys())
            sizes = list(self.tcp_flags.values())
            plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
            plt.title('Distribution des Flags TCP')
            plt.axis('equal')
            plt.savefig(os.path.join(output_dir, 'tcp_flags.png'))
        plt.close()

    def get_summary(self) -> Dict:
        """Retourne un résumé de l'analyse."""
        return {
            'total_packets': self.total_packets,
            'unique_sizes': len(set(self.packet_sizes)),
            'avg_size': statistics.mean(self.packet_sizes) if self.packet_sizes else 0,
            'suspicious_ips': len(self.suspicious_ips),
            'tcp_flags': dict(self.tcp_flags)
        }

def main():
    import tkinter as tk
    from tkinter import filedialog
    
    # Configuration du projet
    analyzer = PacketAnalyzer()
    
    # Sélection du fichier
    root = tk.Tk()
    root.withdraw()
    
    file_path = filedialog.askopenfilename(
        title='Sélectionner le fichier tcpdump à analyser',
        filetypes=[('Fichiers texte', '*.txt'), ('Tous les fichiers', '*.*')]
    )
    
    if not file_path:
        print("Aucun fichier sélectionné")
        return

    print(f"Analyse du fichier: {file_path}")
    
    # Création du dossier exports
    current_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(current_dir, 'exports')
    os.makedirs(output_dir, exist_ok=True)
    
    # Une seule analyse du fichier
    analyzer.analyze_file(file_path)
    
    # Génération des rapports
    analyzer.generate_visualizations(output_dir)
    analyzer.generate_html_report(output_dir)
    
    # Affichage du résumé
    summary = analyzer.get_summary()
    print("\nRésumé de l'analyse:")
    print(f"Total des paquets: {summary['total_packets']}")
    print(f"Tailles uniques: {summary['unique_sizes']}")
    print(f"Taille moyenne: {summary['avg_size']:.2f} bytes")
    print(f"IPs suspectes: {summary['suspicious_ips']}")
    
    print("\nDistribution des flags TCP:")
    for flag, count in summary['tcp_flags'].items():
        print(f"{flag}: {count}")

    print(f"\nVisualisations sauvegardées dans: {output_dir}")
    
    # Affichage des attaquants
    print("\nAttaquants détectés:")
    for attacker in analyzer.get_attackers():
        print(f"\nPrincipal : {attacker.ip_address}")
        print(f"Type d'attaque : {attacker.attack_type}")
        print(f"Nombre total de paquets : {attacker.packet_count}")
        print(f"Ports uniques ciblés : {attacker.unique_ports_targeted}")
        print(f"Taille moyenne des paquets : {attacker.avg_packet_size:.2f} bytes")

if __name__ == "__main__":
    main()