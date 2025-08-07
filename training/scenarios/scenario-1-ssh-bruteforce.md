# Scenario 1: SSH Brute Force Attack Detection & Response

## 🎯 Learning Objectives
- Understand threshold-based detection mechanisms
- Learn automated enrichment workflows
- Practice incident response procedures
- Master SIEM-to-SOAR integration

## 📋 Prerequisites
- Basic understanding of SSH protocol
- Familiarity with log analysis
- Understanding of IP geolocation concepts

## ⏱️ Estimated Duration: 30 minutes

---

## 🚀 Scenario Setup

### Background
Your organization has been experiencing increased SSH brute force attempts against critical servers. The security team needs to implement automated detection and response capabilities to quickly identify and mitigate these attacks.

### Attack Simulation
We'll simulate a coordinated SSH brute force attack from multiple source IPs targeting your SSH servers.

---

## 📝 Step-by-Step Walkthrough

### Phase 1: Environment Preparation (5 minutes)

1. **Verify Lab Status**
   ```bash
   # Check all services are running
   docker-compose ps
   
   # Verify Wazuh is receiving logs
   curl -k -u admin:SecretPassword https://localhost:55000/agents
   ```

2. **Review Detection Rule**
   ```bash
   # Examine the SSH brute force detection rule
   cat detection-rules/wazuh/ssh-bruteforce.xml
   ```

3. **Understand Rule Logic**
   - Triggers on 5+ failed SSH attempts within 2 minutes
   - Correlates attempts from same source IP
   - Includes geographic analysis for anomaly detection

### Phase 2: Attack Generation (5 minutes)

1. **Generate Baseline Traffic**
   ```bash
   # Generate normal SSH activity
   docker-compose exec log-generator python log_generator.py ssh-normal --count 10
   ```

2. **Launch Brute Force Attack**
   ```bash
   # Simulate brute force from single IP
   docker-compose exec log-generator python log_generator.py ssh-bruteforce \
     --source-ip 192.168.1.100 \
     --target-user admin \
     --count 15 \
     --duration 120
   ```

3. **Multi-Source Attack**
   ```bash
   # Simulate distributed brute force
   docker-compose exec log-generator python log_generator.py ssh-bruteforce \
     --distributed \
     --count 25 \
     --duration 180
   ```

### Phase 3: Detection Analysis (10 minutes)

1. **Monitor Real-Time Alerts**
   ```bash
   # Watch for incoming alerts
   docker-compose logs -f automation-engine | grep "SSH_BRUTEFORCE"
   ```

2. **Wazuh Dashboard Investigation**
   - Navigate to https://localhost:443
   - Login: admin / SecretPassword
   - Go to **Security Events**
   - Filter by Rule ID: 5712 (SSH authentication failure)
   - Observe alert frequency and patterns

3. **Kibana Analysis**
   - Open http://localhost:5601
   - Create visualization for SSH events
   - Analyze source IP distribution
   - Review timeline of attacks

4. **API Query for Alerts**
   ```bash
   # Get recent SSH brute force alerts
   curl -X GET "http://localhost:8000/alerts/ssh-bruteforce" \
     -H "Accept: application/json" | jq '.'
   ```

### Phase 4: Automated Response (10 minutes)

1. **Enrichment Process**
   ```bash
   # Check IP enrichment results
   curl -X GET "http://localhost:8000/enrichment/ip/192.168.1.100" | jq '.'
   ```

2. **Review Automated Actions**
   ```bash
   # Check automation logs
   docker-compose logs automation-engine | grep -A 5 -B 5 "AUTOMATED_RESPONSE"
   ```

3. **Verify Integrations**
   - **Jira Ticket**: Check if incident ticket was created
   - **Slack Notification**: Verify alert was sent to security channel
   - **Firewall Block**: Confirm IP was added to block list

4. **Manual Response Simulation**
   ```bash
   # Trigger manual remediation
   curl -X POST "http://localhost:8000/remediate/block-ip" \
     -H "Content-Type: application/json" \
     -d '{"ip": "192.168.1.100", "duration": 3600, "reason": "SSH brute force"}'
   ```

---

## 🔍 Analysis Questions

### Detection Effectiveness
1. How many failed attempts triggered the initial alert?
2. What was the time window for correlation?
3. Were there any false positives in the detection?

### Enrichment Quality
1. What additional context was provided by IP geolocation?
2. How did threat intelligence enhance the alert?
3. What reputation data was available for the source IPs?

### Response Timeliness
1. How quickly did automated response activate?
2. What was the end-to-end response time?
3. Which response actions were most effective?

---

## 🎯 Expected Outcomes

### ✅ Detection Metrics
- **Alert Trigger Time**: < 2 minutes after threshold breach
- **False Positive Rate**: < 5%
- **Coverage**: 100% of brute force attempts detected

### ✅ Enrichment Results
- **IP Geolocation**: Country, city, ISP information
- **Threat Intelligence**: Reputation scores, known malicious indicators
- **Historical Context**: Previous attacks from same sources

### ✅ Response Actions
- **Firewall Block**: Automatic IP blocking within 30 seconds
- **Ticket Creation**: Jira incident ticket with full context
- **Team Notification**: Slack alert with actionable information
- **Evidence Collection**: Logs preserved for forensic analysis

---

## 🛠️ Troubleshooting

### Common Issues

**No Alerts Generated**
```bash
# Check log ingestion
docker-compose exec wazuh-manager tail -f /var/ossec/logs/ossec.log

# Verify rule syntax
docker-compose exec wazuh-manager /var/ossec/bin/ossec-logtest
```

**Automation Not Responding**
```bash
# Check automation service health
curl http://localhost:8000/health

# Review error logs
docker-compose logs automation-engine | grep ERROR
```

**Integration Failures**
```bash
# Test Jira connection
curl -X GET "http://localhost:8000/integrations/jira/test"

# Verify Slack webhook
curl -X POST "http://localhost:8000/integrations/slack/test"
```

---

## 📊 Performance Metrics

### Detection Performance
- **Mean Time to Detection (MTTD)**: Target < 2 minutes
- **Alert Accuracy**: Target > 95%
- **Resource Usage**: Monitor CPU/memory during high-volume attacks

### Response Performance  
- **Mean Time to Response (MTTR)**: Target < 5 minutes
- **Automation Success Rate**: Target > 98%
- **Integration Reliability**: Target > 99% uptime

---

## 🔄 Scenario Variations

### Advanced Scenarios

1. **Credential Stuffing**
   ```bash
   # Simulate credential stuffing with valid usernames
   docker-compose exec log-generator python log_generator.py credential-stuffing \
     --userlist /data/common-users.txt \
     --count 100
   ```

2. **Slow Brute Force**
   ```bash
   # Low-and-slow attack to evade detection
   docker-compose exec log-generator python log_generator.py ssh-bruteforce \
     --slow \
     --interval 300 \
     --count 50
   ```

3. **Geographic Anomaly**
   ```bash
   # Same user from impossible geographic locations
   docker-compose exec log-generator python log_generator.py geo-anomaly \
     --user admin \
     --locations "US,CN" \
     --timeframe 300
   ```

---

## 📚 Additional Learning

### Recommended Reading
- [NIST Cybersecurity Framework - Detect Function](https://www.nist.gov/cyberframework/detect)
- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
- [SSH Security Best Practices](https://www.ssh.com/academy/ssh/security)

### Hands-On Extensions
1. Create custom detection rules for SSH key-based attacks
2. Implement machine learning for behavioral analysis
3. Develop custom response playbooks
4. Integrate with additional security tools

---

## ✅ Completion Checklist

- [ ] Successfully generated SSH brute force traffic
- [ ] Observed real-time detection in Wazuh
- [ ] Analyzed alerts in Kibana dashboard
- [ ] Verified automated enrichment process
- [ ] Confirmed integration responses (Jira, Slack)
- [ ] Tested manual remediation capabilities
- [ ] Documented lessons learned
- [ ] Identified areas for improvement

---

*This scenario provides hands-on experience with one of the most common attack vectors in modern environments. The skills learned here directly apply to real-world SOC operations and incident response procedures.*