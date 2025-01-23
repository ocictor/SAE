import pandas as pd
import markdown
from datetime import datetime
import logging
import re
from pathlib import Path

class NetworkDataAnalyzer:
    def __init__(self, tcpdump_file):
        self.tcpdump_file = tcpdump_file
        self.data = []
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(message)s'
        )

    def parse_tcpdump(self):
        pattern = r'(\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+([\d\.]+)(?:\.(\d+))?\s+>\s+([\d\.]+)(?:\.(\d+))?'
        
        with open(self.tcpdump_file, 'r') as f:
            for line in f:
                match = re.search(pattern, line)
                if match:
                    self.data.append({
                        'time': match.group(1),
                        'source_ip': match.group(2),
                        'source_port': match.group(3),
                        'dest_ip': match.group(4),
                        'dest_port': match.group(5)
                    })

    def analyze_data(self):
        df = pd.DataFrame(self.data)
        
        # Analyses clés
        results = {
            'total_connections': len(df),
            'unique_ips': df['source_ip'].nunique(),
            'top_source_ips': df['source_ip'].value_counts().head(10),
            'top_dest_ports': df['dest_port'].value_counts().head(10),
            'hourly_traffic': df['time'].str[:2].value_counts().sort_index()
        }
        
        # Export CSV
        df.to_csv('network_data.csv', index=False)
        
        return results

    def generate_web_report(self, results):
        markdown_content = f"""
# Analyse du Trafic Réseau
*Rapport généré le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*

## Statistiques Générales
- Total des connexions: {results['total_connections']}
- IPs uniques: {results['unique_ips']}

## Top 10 des IPs Source
```
{results['top_source_ips'].to_markdown()}
```

## Top 10 des Ports de Destination
```
{results['top_dest_ports'].to_markdown()}
```

## Distribution Horaire du Trafic
```
{results['hourly_traffic'].to_markdown()}
```
"""
        # Conversion en HTML et sauvegarde
        html = markdown.markdown(markdown_content)
        with open('rapport_reseau.html', 'w') as f:
            f.write(f"""
            <html>
                <head>
                    <style>
                        body {{ font-family: Arial; margin: 40px; }}
                        table {{ border-collapse: collapse; }}
                        th, td {{ border: 1px solid #ddd; padding: 8px; }}
                    </style>
                </head>
                <body>{html}</body>
            </html>
            """)

def main():
    try:
        analyzer = NetworkDataAnalyzer('DumpFile.txt')
        analyzer.parse_tcpdump()
        results = analyzer.analyze_data()
        analyzer.generate_web_report(results)
        logging.info("Analyse terminée - Fichiers générés: network_data.csv et rapport_reseau.html")
    except Exception as e:
        logging.error(f"Erreur: {str(e)}")

if __name__ == "__main__":
    main()