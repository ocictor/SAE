import pandas as pd
import re
from datetime import datetime
import logging
from typing import Dict, Any
import json

class NetworkAnalyzer:
    def __init__(self, input_file: str, suspicious_threshold: int = 1000):
        """
        Initialize the NetworkAnalyzer with input file and threshold for suspicious activity.
        
        Args:
            input_file: Path to the tcpdump file
            suspicious_threshold: Threshold for marking traffic as suspicious
        """
        self.input_file = input_file
        self.data = []
        self.suspicious_threshold = suspicious_threshold
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def parse_tcpdump(self) -> None:
        """Parse tcpdump file and extract relevant network information."""
        # Enhanced pattern to capture more tcpdump format variations
        pattern = r'''
            (\d{2}:\d{2}:\d{2}\.\d+)\s+    # Timestamp
            IP\s+                           # IP marker
            ([\w\-\.]+?)\.?(\d+)?\s+>\s+   # Source IP and port
            ([\w\-\.]+?)\.?(\d+)?:?\s*     # Destination IP and port
            (?:Flags\s+\[(.*?)\])?         # Optional flags
            (?:\s+length\s+(\d+))?         # Optional packet length
        '''
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                for line in f:
                    match = re.search(pattern, line.strip(), re.VERBOSE)
                    if match:
                        entry = {
                            'timestamp': match.group(1),
                            'src_ip': match.group(2),
                            'src_port': match.group(3) or 'unknown',
                            'dst_ip': match.group(4),
                            'dst_port': match.group(5) or 'unknown',
                            'flags': match.group(6) or '',
                            'length': int(match.group(7)) if match.group(7) else 0
                        }
                        self.data.append(entry)
            
            self.logger.info(f"Successfully parsed {len(self.data)} entries")
            
        except FileNotFoundError:
            self.logger.error(f"Input file {self.input_file} not found")
            raise
        except Exception as e:
            self.logger.error(f"Error parsing file: {str(e)}")
            raise

    def analyze_traffic(self) -> Dict[str, Any]:
        """
        Analyze network traffic for suspicious patterns.
        
        Returns:
            Dictionary containing analysis results
        """
        if not self.data:
            self.logger.warning("No data to analyze")
            return {}
            
        df = pd.DataFrame(self.data)
        
        # IP-based analysis
        src_ip_counts = df['src_ip'].value_counts()
        suspicious_ips = src_ip_counts[src_ip_counts > self.suspicious_threshold]
        
        # Port analysis
        dst_port_counts = df['dst_port'].value_counts()
        suspicious_ports = dst_port_counts[dst_port_counts > self.suspicious_threshold]
        
        # Time-based analysis
        df['hour'] = pd.to_datetime(df['timestamp'].str[:8], format='%H:%M:%S').dt.hour
        hourly_traffic = df['hour'].value_counts().sort_index()
        
        # Volume analysis
        total_traffic = df['length'].sum()
        avg_packet_size = df['length'].mean()
        
        # Pattern detection
        potential_scan = df.groupby('src_ip')['dst_port'].nunique()
        port_scanners = potential_scan[potential_scan > 100].index.tolist()
        
        return {
            'suspicious_ips': suspicious_ips,
            'suspicious_ports': suspicious_ports,
            'hourly_traffic': hourly_traffic,
            'total_traffic_bytes': total_traffic,
            'avg_packet_size': avg_packet_size,
            'potential_port_scanners': port_scanners
        }

    def generate_csv(self, output_file: str) -> None:
        """Generate CSV report of parsed data."""
        if not self.data:
            self.logger.warning("No data to export to CSV")
            return
            
        df = pd.DataFrame(self.data)
        df.to_csv(output_file, index=False, encoding='utf-8')
        self.logger.info(f"CSV report generated: {output_file}")

    def generate_markdown_report(self, analysis_results: Dict[str, Any], output_file: str) -> None:
        """
        Generate detailed Markdown report of the analysis.
        
        Args:
            analysis_results: Dictionary containing analysis results
            output_file: Path for the output markdown file
        """
        if not analysis_results:
            self.logger.warning("No analysis results to generate report")
            return
            
        report = f"""# Network Traffic Analysis Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Overview
- Total Traffic Analyzed: {len(self.data):,} packets
- Total Traffic Volume: {analysis_results['total_traffic_bytes']:,} bytes
- Average Packet Size: {analysis_results['avg_packet_size']:.2f} bytes

## Suspicious Activities

### High-Volume Source IPs (>{self.suspicious_threshold} connections)
```
{analysis_results['suspicious_ips'].to_string() if not analysis_results['suspicious_ips'].empty else 'None detected'}
```

### Frequently Targeted Ports (>{self.suspicious_threshold} connections)
```
{analysis_results['suspicious_ports'].to_string() if not analysis_results['suspicious_ports'].empty else 'None detected'}
```

### Potential Port Scanners
```
{json.dumps(analysis_results['potential_port_scanners'], indent=2)}
```

## Traffic Distribution

### Hourly Traffic Pattern
```
{analysis_results['hourly_traffic'].to_string()}
```
"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        self.logger.info(f"Markdown report generated: {output_file}")

def main():
    try:
        analyzer = NetworkAnalyzer('DumpFile.txt')
        analyzer.parse_tcpdump()
        results = analyzer.analyze_traffic()
        analyzer.generate_csv('network_analysis.csv')
        analyzer.generate_markdown_report(results, 'network_analysis.md')
    except Exception as e:
        logging.error(f"Analysis failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()