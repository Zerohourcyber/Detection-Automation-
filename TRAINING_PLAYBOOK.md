# 🎯 Detection & Automation Lab Training Playbook

## Overview
This playbook provides hands-on training scenarios for security analysts, SOC engineers, and automation specialists. Each scenario includes step-by-step instructions, expected outcomes, and troubleshooting guidance.

---

## 📚 Table of Contents
1. [Lab Setup & Prerequisites](#lab-setup--prerequisites)
2. [Training Scenarios](#training-scenarios)
3. [Advanced Exercises](#advanced-exercises)
4. [Troubleshooting Guide](#troubleshooting-guide)
5. [Assessment Criteria](#assessment-criteria)

---

## 🚀 Lab Setup & Prerequisites

### Prerequisites
- Docker & Docker Compose installed
- Basic understanding of SIEM concepts
- Familiarity with command line operations
- Understanding of network security fundamentals

### Initial Setup
```bash
# Clone the repository
git clone <repository-url>
cd detection-automation-lab

# Start the lab environment
./scripts/setup.sh

# Verify all services are running
docker-compose ps
```

### Access Points
- **Wazuh Dashboard**: https://localhost:443 (admin/SecretPassword)
- **Automation API**: http://localhost:8000/docs
- **Kibana**: http://localhost:5601
- **Demo Data Generator**: `docker-compose exec log-generator python log_generator.py`

---

## 🎓 Training Scenarios

### Scenario 1: SSH Brute Force Attack Detection & Response
**Duration**: 30 minutes  
**Difficulty**: Beginner  
**MITRE ATT&CK**: T1110.001 (Password Guessing)

#### Objective
Learn to detect, analyze, and respond to SSH brute force attacks using automated workflows.

#### Step-by-Step Instructions

**Step 1: Generate Attack Traffic**
```bash
# Generate SSH brute force logs
docker-compose exec log-generator python log_generator.py ssh-bruteforce --count 20
```

**Step 2: Monitor Detection**
1. Open Wazuh Dashboard (https://localhost:443)
2. Navigate to **Security Events**
3. Filter for Rule ID: `5712` (SSH authentication failure)
4. Observe the pattern of failed login attempts

**Step 3: Trigger Automation**
```bash
# Check automation logs
docker-compose logs automation-engine

# Verify alert processing
curl -X GET "http://localhost:8000/alerts/recent" | jq
```

**Step 4: Review Automated Response**
1. Check Slack notifications (if configured)
2. Verify Jira ticket creation
3. Confirm IP blocking in pfSense logs

#### Expected Outcomes
- ✅ Detection rule triggers after 5 failed attempts
- ✅ Alert enrichment with geolocation data
- ✅ Automated ticket creation in Jira
- ✅ IP address blocked in firewall
- ✅ Notification sent to security team

#### Learning Points
- Understanding threshold-based detection
- Automated enrichment workflows
- Integration between SIEM and SOAR tools
- Network-level remediation

---

### Scenario 2: DNS Tunneling Detection
**Duration**: 45 minutes  
**Difficulty**: Intermediate  
**MITRE ATT&CK**: T1071.004 (DNS)

#### Objective
Detect and analyze DNS tunneling attempts used for data exfiltration or C2 communication.

#### Step-by-Step Instructions

**Step 1: Generate DNS Tunneling Traffic**
```bash
# Generate suspicious DNS queries
docker-compose exec log-generator python log_generator.py dns-tunneling --duration 300
```

**Step 2: Analyze Detection Logic**
1. Review the Sigma rule: `detection-rules/sigma/dns-tunneling.yml`
2. Understand the detection criteria:
   - Query length > 50 characters
   - Base64 encoded patterns
   - Unusual TXT record requests

**Step 3: Investigate Alerts**
1. Open Kibana (http://localhost:5601)
2. Search for DNS events: `event.dataset:dns`
3. Filter for suspicious patterns
4. Analyze query patterns and frequencies

**Step 4: Manual Analysis**
```bash
# Extract DNS queries for analysis
docker-compose exec automation-engine python -c "
from src.analysis.dns_analyzer import DNSAnalyzer
analyzer = DNSAnalyzer()
results = analyzer.analyze_recent_queries()
print(results)
"
```

#### Expected Outcomes
- ✅ Detection of abnormal DNS query patterns
- ✅ Identification of base64 encoded data
- ✅ Correlation of queries from same source
- ✅ Threat intelligence enrichment
- ✅ Automated containment recommendations

#### Learning Points
- Advanced pattern recognition in DNS traffic
- Statistical analysis for anomaly detection
- Data exfiltration techniques
- Network traffic analysis

---

### Scenario 3: PowerShell Attack Chain
**Duration**: 60 minutes  
**Difficulty**: Advanced  
**MITRE ATT&CK**: T1059.001 (PowerShell)

#### Objective
Detect and respond to a multi-stage PowerShell attack including obfuscation, execution, and persistence.

#### Step-by-Step Instructions

**Step 1: Simulate Attack Chain**
```bash
# Generate PowerShell attack sequence
docker-compose exec log-generator python log_generator.py powershell-attack --scenario advanced
```

**Step 2: Multi-Stage Detection**
1. **Stage 1**: Obfuscated command execution
2. **Stage 2**: AMSI bypass attempts  
3. **Stage 3**: Credential harvesting
4. **Stage 4**: Persistence mechanisms

**Step 3: Correlation Analysis**
```bash
# Run correlation engine
curl -X POST "http://localhost:8000/correlate" \
  -H "Content-Type: application/json" \
  -d '{"timeframe": "1h", "source_ip": "192.168.1.100"}'
```

**Step 4: Threat Hunting**
1. Use Kibana to create custom visualizations
2. Search for PowerShell process trees
3. Identify parent-child relationships
4. Map to MITRE ATT&CK framework

#### Expected Outcomes
- ✅ Detection of obfuscated PowerShell commands
- ✅ Correlation across multiple log sources
- ✅ Timeline reconstruction of attack
- ✅ Automated threat hunting queries
- ✅ Comprehensive incident report

#### Learning Points
- Advanced threat detection techniques
- Attack chain reconstruction
- Behavioral analysis
- Threat hunting methodologies

---

### Scenario 4: Web Shell Detection & Response
**Duration**: 40 minutes  
**Difficulty**: Intermediate  
**MITRE ATT&CK**: T1505.003 (Web Shell)

#### Objective
Detect web shell uploads and implement automated containment measures.

#### Step-by-Step Instructions

**Step 1: Simulate Web Shell Upload**
```bash
# Generate web shell activity
docker-compose exec log-generator python log_generator.py webshell --target "/var/www/html"
```

**Step 2: File Integrity Monitoring**
1. Monitor Wazuh FIM alerts
2. Analyze file creation events
3. Review file content analysis

**Step 3: Automated Response**
```bash
# Trigger automated response
curl -X POST "http://localhost:8000/respond/webshell" \
  -H "Content-Type: application/json" \
  -d '{"file_path": "/var/www/html/shell.php", "action": "quarantine"}'
```

#### Expected Outcomes
- ✅ Real-time file creation detection
- ✅ Malicious file content identification
- ✅ Automated file quarantine
- ✅ Web server isolation
- ✅ Forensic evidence preservation

---

## 🔬 Advanced Exercises

### Exercise 1: Custom Rule Development
**Objective**: Create a new detection rule for a specific attack technique.

**Tasks**:
1. Choose a MITRE ATT&CK technique not covered
2. Research attack patterns and indicators
3. Develop both Wazuh and Sigma rules
4. Test with custom log data
5. Integrate with automation framework

### Exercise 2: Threat Intelligence Integration
**Objective**: Enhance detection with external threat intelligence.

**Tasks**:
1. Integrate additional TI feeds (MISP, OTX, etc.)
2. Create IOC matching rules
3. Implement reputation scoring
4. Build threat context enrichment
5. Develop hunting queries based on TI

### Exercise 3: Machine Learning Detection
**Objective**: Implement ML-based anomaly detection.

**Tasks**:
1. Collect baseline behavioral data
2. Train anomaly detection models
3. Implement real-time scoring
4. Create adaptive thresholds
5. Build feedback mechanisms

---

## 🛠️ Troubleshooting Guide

### Common Issues

#### Services Not Starting
```bash
# Check service status
docker-compose ps

# View service logs
docker-compose logs [service-name]

# Restart specific service
docker-compose restart [service-name]
```

#### Detection Rules Not Triggering
1. Verify rule syntax: `docker-compose exec wazuh-manager /var/ossec/bin/ossec-logtest`
2. Check log ingestion: Monitor Wazuh agent logs
3. Validate rule conditions: Review rule logic and thresholds
4. Test with manual log injection

#### Automation Not Responding
```bash
# Check automation engine status
curl http://localhost:8000/health

# Review automation logs
docker-compose logs automation-engine

# Test individual components
python -m pytest automation/tests/ -v
```

#### Integration Failures
1. **Jira**: Verify API credentials and permissions
2. **Slack**: Check webhook URL and token validity
3. **VirusTotal**: Confirm API key and rate limits
4. **pfSense**: Validate API access and firewall rules

### Performance Optimization

#### High Memory Usage
```bash
# Adjust Elasticsearch heap size
echo "ES_JAVA_OPTS=-Xms2g -Xmx2g" >> .env

# Optimize Wazuh configuration
# Edit wazuh-manager configuration for log rotation
```

#### Slow Query Performance
```bash
# Create Elasticsearch indices
curl -X PUT "localhost:9200/wazuh-alerts-*/_settings" \
  -H 'Content-Type: application/json' \
  -d '{"index": {"number_of_replicas": 0}}'
```

---

## 📊 Assessment Criteria

### Beginner Level (Scenarios 1-2)
- [ ] Successfully deploy lab environment
- [ ] Generate and observe security events
- [ ] Understand basic detection logic
- [ ] Navigate SIEM interfaces
- [ ] Interpret alert data

### Intermediate Level (Scenarios 3-4)
- [ ] Perform correlation analysis
- [ ] Create custom queries and filters
- [ ] Understand attack chains
- [ ] Configure automated responses
- [ ] Analyze false positives

### Advanced Level (Custom Exercises)
- [ ] Develop custom detection rules
- [ ] Integrate external data sources
- [ ] Implement advanced analytics
- [ ] Optimize performance
- [ ] Design scalable architectures

---

## 🎯 Training Objectives & Outcomes

### Knowledge Areas Covered
1. **SIEM Operations**: Log analysis, rule creation, alert triage
2. **Threat Detection**: Pattern recognition, behavioral analysis, IOC matching
3. **Incident Response**: Automated workflows, containment, forensics
4. **Integration Skills**: API usage, webhook configuration, tool orchestration
5. **Threat Intelligence**: IOC enrichment, context analysis, hunting

### Skills Developed
- Security event analysis and correlation
- Detection rule development and tuning
- Automation workflow design
- Threat hunting techniques
- Incident response procedures
- Tool integration and orchestration

### Career Relevance
This training directly applies to roles such as:
- SOC Analyst (L1/L2/L3)
- Security Engineer
- Threat Hunter
- Incident Response Specialist
- Security Automation Engineer
- Detection Engineer

---

## 📝 Training Log Template

### Session Information
- **Date**: ___________
- **Participant**: ___________
- **Scenario**: ___________
- **Duration**: ___________

### Completion Checklist
- [ ] Environment setup completed
- [ ] All detection rules triggered
- [ ] Automation workflows executed
- [ ] Integration tests passed
- [ ] Documentation reviewed

### Notes & Observations
```
[Space for participant notes and observations]
```

### Next Steps
```
[Areas for improvement and additional training]
```

---

## 🔗 Additional Resources

### Documentation
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

### Training Materials
- [SANS SEC511: Continuous Monitoring and Security Operations](https://www.sans.org/cyber-security-courses/continuous-monitoring-security-operations/)
- [Splunk Fundamentals](https://www.splunk.com/en_us/training.html)
- [Elastic Security Training](https://www.elastic.co/training/)

### Community Resources
- [r/SecurityBlueTeam](https://www.reddit.com/r/SecurityBlueTeam/)
- [SANS Blue Team Blog](https://www.sans.org/blog/)
- [Detection Engineering Community](https://detectionengineering.net/)

---

*This playbook is designed to provide hands-on experience with modern security operations and automation techniques. Regular updates ensure alignment with current threat landscapes and industry best practices.*