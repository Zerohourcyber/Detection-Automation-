# Detection & Automation Lab 🔍🤖

A comprehensive Security Operations Center (SOC) automation platform demonstrating end-to-end alert handling, detection engineering, and incident response automation.

## 🎯 Overview

This project showcases a production-ready detection and automation pipeline that integrates multiple security tools and platforms to create an efficient SOC workflow. It demonstrates real-world capabilities for threat detection, alert enrichment, and automated response.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Data Sources  │───▶│  Detection Lab  │───▶│   Automation    │
│                 │    │                 │    │    Pipeline     │
│ • System Logs   │    │ • Wazuh SIEM    │    │ • Enrichment    │
│ • Network Data  │    │ • Elasticsearch │    │ • Remediation   │
│ • Endpoint Data │    │ • Kibana        │    │ • Notifications │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │  Integrations   │
                       │                 │
                       │ • Jira Tickets  │
                       │ • Slack/Teams   │
                       │ • pfSense FW    │
                       │ • EDR Systems   │
                       └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.9+
- Git

### Launch the Lab
```bash
git clone https://github.com/yourusername/detection-automation-lab.git
cd detection-automation-lab
cp .env.example .env
# Edit .env with your configuration
docker-compose up -d
```

### Access Services
- **Wazuh Dashboard**: http://localhost:443 (admin/SecretPassword)
- **Kibana**: http://localhost:5601
- **Automation API**: http://localhost:8000

## 📋 Features

### Detection Rules (8-10 High-Impact)
- **SSH Brute Force Detection** - MITRE T1110.001
- **DNS Tunneling Detection** - MITRE T1071.004
- **PowerShell Obfuscation** - MITRE T1059.001
- **Credential Dumping** - MITRE T1003
- **Web Shell Detection** - MITRE T1505.003
- **Lateral Movement** - MITRE T1021
- **Data Exfiltration** - MITRE T1041
- **Privilege Escalation** - MITRE T1068

### Automation Scripts (5-6 Core)
- **VirusTotal Enrichment** - Hash/IP/Domain lookup
- **Jira Ticket Creation** - Automated incident tracking
- **pfSense IP Blocking** - Network-level remediation
- **EDR Host Isolation** - Endpoint containment
- **Slack/Teams Notifications** - Real-time alerting
- **Threat Intelligence Lookup** - IOC enrichment

### Integrations
- **SIEM**: Wazuh + Elasticsearch + Kibana
- **Ticketing**: Jira API integration
- **Communication**: Slack/Microsoft Teams
- **Firewall**: pfSense API
- **Threat Intel**: VirusTotal, AbuseIPDB
- **EDR**: Generic API framework

## 📁 Project Structure

```
detection-automation-lab/
├── README.md
├── docker-compose.yml
├── .env.example
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── security-scan.yml
├── detection-rules/
│   ├── wazuh/
│   │   ├── ssh-bruteforce.xml
│   │   ├── dns-tunneling.xml
│   │   └── ...
│   └── sigma/
│       ├── ssh-bruteforce.yml
│       ├── dns-tunneling.yml
│       └── ...
├── automation/
│   ├── src/
│   │   ├── enrichment/
│   │   ├── remediation/
│   │   └── integrations/
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
├── infrastructure/
│   ├── wazuh/
│   ├── elasticsearch/
│   └── kibana/
├── docs/
│   ├── architecture.md
│   ├── deployment.md
│   └── api-reference.md
├── demo-data/
│   ├── sample-logs/
│   └── test-scenarios/
└── scripts/
    ├── setup.sh
    └── test-deployment.sh
```

## 🔧 Configuration

### Environment Variables
```bash
# SIEM Configuration
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=MyS3cr37P450r.*-
ELASTICSEARCH_PASSWORD=MyS3cr37P450r.*-

# Integration APIs
JIRA_URL=https://yourcompany.atlassian.net
JIRA_USERNAME=automation@company.com
JIRA_API_TOKEN=your-api-token

SLACK_BOT_TOKEN=xoxb-your-slack-bot-token
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...

# Threat Intelligence
VIRUSTOTAL_API_KEY=your-vt-api-key
ABUSEIPDB_API_KEY=your-abuseipdb-key

# Network Security
PFSENSE_HOST=192.168.1.1
PFSENSE_USERNAME=admin
PFSENSE_PASSWORD=pfsense-password
```

## 🧪 Testing

```bash
# Run unit tests
cd automation
python -m pytest tests/ -v

# Test detection rules
./scripts/test-detection-rules.sh

# Integration tests
./scripts/test-integrations.sh
```

## 📊 Monitoring & Metrics

- **Detection Coverage**: MITRE ATT&CK mapping
- **Alert Volume**: Daily/weekly trends
- **Response Times**: MTTR tracking
- **False Positive Rate**: Rule tuning metrics
- **Automation Success Rate**: Script execution stats

## 🛡️ Security Considerations

- All API keys stored in environment variables
- TLS encryption for all communications
- Role-based access control (RBAC)
- Audit logging for all automation actions
- Input validation and sanitization

## 📚 Documentation

- [Architecture Overview](docs/architecture.md)
- [Deployment Guide](docs/deployment.md)
- [API Reference](docs/api-reference.md)
- [Detection Rules Guide](docs/detection-rules.md)
- [Automation Scripts](docs/automation.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🏆 Portfolio Highlights

This project demonstrates:
- **Detection Engineering**: Custom rule development with MITRE ATT&CK mapping
- **Security Automation**: End-to-end incident response workflows
- **Integration Skills**: Multi-platform API integrations
- **DevOps Practices**: CI/CD, containerization, infrastructure as code
- **Documentation**: Comprehensive technical documentation
- **Testing**: Unit tests, integration tests, security scanning

---

**Built for Security Operations Centers seeking to automate threat detection and response workflows.**