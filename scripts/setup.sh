#!/bin/bash

# Detection & Automation Lab Setup Script
# Automated deployment and configuration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="detection-automation-lab"
COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running. Please start Docker first."
        exit 1
    fi
    
    log_success "All dependencies are available"
}

setup_environment() {
    log_info "Setting up environment configuration..."
    
    if [ ! -f "$ENV_FILE" ]; then
        if [ -f ".env.example" ]; then
            cp .env.example "$ENV_FILE"
            log_success "Created $ENV_FILE from .env.example"
        else
            log_error ".env.example file not found"
            exit 1
        fi
    else
        log_warning "$ENV_FILE already exists, skipping creation"
    fi
    
    # Generate random passwords if they don't exist
    if grep -q "MyS3cr37P450r" "$ENV_FILE"; then
        log_info "Generating secure passwords..."
        
        # Generate random passwords
        WAZUH_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        ELASTICSEARCH_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        API_SECRET_KEY=$(openssl rand -base64 64 | tr -d "=+/" | cut -c1-50)
        
        # Replace default passwords
        sed -i "s/MyS3cr37P450r.*-/$WAZUH_PASSWORD/g" "$ENV_FILE"
        sed -i "s/your-super-secret-api-key-change-this-in-production/$API_SECRET_KEY/g" "$ENV_FILE"
        
        log_success "Generated secure passwords"
    fi
}

create_directories() {
    log_info "Creating necessary directories..."
    
    directories=(
        "infrastructure/wazuh/config"
        "infrastructure/elasticsearch/config"
        "infrastructure/kibana/config"
        "automation/logs"
        "automation/data"
        "demo-data/logs"
        "logs"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        log_info "Created directory: $dir"
    done
    
    log_success "All directories created"
}

generate_certificates() {
    log_info "Generating SSL certificates for Wazuh..."
    
    CERT_DIR="infrastructure/wazuh/config/wazuh_indexer_ssl_certs"
    mkdir -p "$CERT_DIR"
    
    if [ ! -f "$CERT_DIR/root-ca.pem" ]; then
        # Generate root CA
        openssl genrsa -out "$CERT_DIR/root-ca-key.pem" 2048
        openssl req -new -x509 -sha256 -key "$CERT_DIR/root-ca-key.pem" -out "$CERT_DIR/root-ca.pem" -days 365 -subj "/C=US/ST=CA/L=San Francisco/O=Detection Lab/OU=Security/CN=detection-lab-ca"
        
        # Generate certificates for each component
        components=("wazuh.manager" "wazuh.indexer" "wazuh.dashboard" "admin")
        
        for component in "${components[@]}"; do
            # Generate private key
            openssl genrsa -out "$CERT_DIR/${component}-key.pem" 2048
            
            # Generate certificate signing request
            openssl req -new -key "$CERT_DIR/${component}-key.pem" -out "$CERT_DIR/${component}.csr" -subj "/C=US/ST=CA/L=San Francisco/O=Detection Lab/OU=Security/CN=${component}"
            
            # Generate certificate
            openssl x509 -req -in "$CERT_DIR/${component}.csr" -CA "$CERT_DIR/root-ca.pem" -CAkey "$CERT_DIR/root-ca-key.pem" -CAcreateserial -out "$CERT_DIR/${component}.pem" -days 365 -sha256
            
            # Clean up CSR
            rm "$CERT_DIR/${component}.csr"
        done
        
        # Copy root CA for manager
        cp "$CERT_DIR/root-ca.pem" "$CERT_DIR/root-ca-manager.pem"
        
        log_success "SSL certificates generated"
    else
        log_warning "SSL certificates already exist, skipping generation"
    fi
}

create_wazuh_config() {
    log_info "Creating Wazuh configuration files..."
    
    # Create Wazuh manager configuration
    WAZUH_CONFIG_DIR="infrastructure/wazuh/config/wazuh_cluster"
    mkdir -p "$WAZUH_CONFIG_DIR"
    
    if [ ! -f "$WAZUH_CONFIG_DIR/wazuh_manager.conf" ]; then
        cat > "$WAZUH_CONFIG_DIR/wazuh_manager.conf" << 'EOF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>localhost</smtp_server>
    <email_from>wazuh@detection-lab.local</email_from>
    <email_to>admin@detection-lab.local</email_to>
    <hostname>wazuh-manager</hostname>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <logging>
    <log_format>plain</log_format>
  </logging>

  <remote>
    <connection>syslog</connection>
    <port>1514</port>
    <protocol>udp</protocol>
    <allowed-ips>0.0.0.0/0</allowed-ips>
  </remote>

  <remote>
    <connection>secure</connection>
    <port>1515</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>no</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <ssl_agent_ca>/var/ossec/etc/sslmanager.cert</ssl_agent_ca>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>master</node_name>
    <node_type>master</node_type>
    <key>c98b62a9b6169ac5f67dae55ae4a9088</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>wazuh.manager</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>

  <integration>
    <name>custom-webhook</name>
    <hook_url>http://automation-engine:8000/api/v1/webhook/wazuh</hook_url>
    <level>7</level>
    <alert_format>json</alert_format>
  </integration>

</ossec_config>
EOF
        log_success "Created Wazuh manager configuration"
    fi
    
    # Create indexer configuration
    INDEXER_CONFIG_DIR="infrastructure/wazuh/config/wazuh_indexer"
    mkdir -p "$INDEXER_CONFIG_DIR"
    
    if [ ! -f "$INDEXER_CONFIG_DIR/opensearch.yml" ]; then
        cat > "$INDEXER_CONFIG_DIR/opensearch.yml" << 'EOF'
network.host: 0.0.0.0
node.name: wazuh.indexer
cluster.initial_master_nodes:
- wazuh.indexer
cluster.name: wazuh-cluster
discovery.seed_hosts:
- wazuh.indexer
node.max_local_storage_nodes: 3

path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

plugins.security.ssl.transport.pemcert_filepath: certs/wazuh.indexer.pem
plugins.security.ssl.transport.pemkey_filepath: certs/wazuh.indexer.key
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: certs/wazuh.indexer.pem
plugins.security.ssl.http.pemkey_filepath: certs/wazuh.indexer.key
plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.allow_unsafe_democertificates: true
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
- CN=admin,OU=Security,O=Detection Lab,L=San Francisco,ST=CA,C=US
plugins.security.audit.type: internal_opensearch
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices:
- ".opendistro-alerting-config"
- ".opendistro-alerting-alert*"
- ".opendistro-anomaly-results*"
- ".opendistro-anomaly-detector*"
- ".opendistro-anomaly-checkpoints"
- ".opendistro-anomaly-detection-state"
- ".opendistro-reports-*"
- ".opendistro-notifications-*"
- ".opendistro-notebooks"
- ".opensearch-observability"
- ".opendistro-asynchronous-search-response*"
- ".replication-metadata-store"
cluster.routing.allocation.disk.threshold_enabled: false
node.roles:
- master
- ingest
- data
EOF
        log_success "Created Wazuh indexer configuration"
    fi
    
    # Create dashboard configuration
    DASHBOARD_CONFIG_DIR="infrastructure/wazuh/config/wazuh_dashboard"
    mkdir -p "$DASHBOARD_CONFIG_DIR"
    
    if [ ! -f "$DASHBOARD_CONFIG_DIR/opensearch_dashboards.yml" ]; then
        cat > "$DASHBOARD_CONFIG_DIR/opensearch_dashboards.yml" << 'EOF'
server.host: 0.0.0.0
server.port: 5601
opensearch.hosts: https://wazuh.indexer:9200
opensearch.ssl.verificationMode: certificate
opensearch.username: kibanaserver
opensearch.password: kibanaserver
opensearch.requestHeadersWhitelist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: true
server.ssl.key: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem"
server.ssl.certificate: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem"
server.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/root-ca.pem"]
opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wz-home
EOF
        log_success "Created Wazuh dashboard configuration"
    fi
}

pull_images() {
    log_info "Pulling Docker images..."
    
    if command -v docker-compose &> /dev/null; then
        docker-compose pull
    else
        docker compose pull
    fi
    
    log_success "Docker images pulled successfully"
}

start_services() {
    log_info "Starting services..."
    
    if command -v docker-compose &> /dev/null; then
        docker-compose up -d
    else
        docker compose up -d
    fi
    
    log_success "Services started successfully"
}

wait_for_services() {
    log_info "Waiting for services to be ready..."
    
    # Wait for Wazuh indexer
    log_info "Waiting for Wazuh indexer..."
    timeout=300
    counter=0
    while ! curl -k -s https://localhost:9200 > /dev/null 2>&1; do
        if [ $counter -ge $timeout ]; then
            log_error "Timeout waiting for Wazuh indexer"
            exit 1
        fi
        sleep 5
        counter=$((counter + 5))
        echo -n "."
    done
    echo ""
    log_success "Wazuh indexer is ready"
    
    # Wait for Wazuh dashboard
    log_info "Waiting for Wazuh dashboard..."
    counter=0
    while ! curl -k -s https://localhost:443 > /dev/null 2>&1; do
        if [ $counter -ge $timeout ]; then
            log_error "Timeout waiting for Wazuh dashboard"
            exit 1
        fi
        sleep 5
        counter=$((counter + 5))
        echo -n "."
    done
    echo ""
    log_success "Wazuh dashboard is ready"
    
    # Wait for automation engine
    log_info "Waiting for automation engine..."
    counter=0
    while ! curl -s http://localhost:8000/health > /dev/null 2>&1; do
        if [ $counter -ge $timeout ]; then
            log_error "Timeout waiting for automation engine"
            exit 1
        fi
        sleep 5
        counter=$((counter + 5))
        echo -n "."
    done
    echo ""
    log_success "Automation engine is ready"
}

show_access_info() {
    log_success "Detection & Automation Lab is ready!"
    echo ""
    echo "Access Information:"
    echo "=================="
    echo "🔍 Wazuh Dashboard: https://localhost:443"
    echo "   Username: admin"
    echo "   Password: admin"
    echo ""
    echo "🔧 Automation API: http://localhost:8000"
    echo "   Health Check: http://localhost:8000/health"
    echo "   API Docs: http://localhost:8000/docs"
    echo ""
    echo "📊 Elasticsearch: https://localhost:9200"
    echo "   Username: admin"
    echo "   Password: admin"
    echo ""
    echo "🔄 Redis: localhost:6379"
    echo ""
    echo "Useful Commands:"
    echo "==============="
    echo "📋 View logs: docker-compose logs -f [service_name]"
    echo "🔄 Restart services: docker-compose restart"
    echo "🛑 Stop services: docker-compose down"
    echo "🧹 Clean up: docker-compose down -v"
    echo ""
    echo "📖 For more information, see the README.md file"
}

generate_demo_data() {
    log_info "Generating demo security events..."
    
    # Wait a bit more for services to stabilize
    sleep 30
    
    # Generate demo data
    if command -v docker-compose &> /dev/null; then
        docker-compose exec -T log-generator python log_generator.py single
    else
        docker compose exec -T log-generator python log_generator.py single
    fi
    
    log_success "Demo security events generated"
}

# Main execution
main() {
    echo "🚀 Detection & Automation Lab Setup"
    echo "===================================="
    echo ""
    
    # Parse command line arguments
    SKIP_DEMO=false
    QUICK_START=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-demo)
                SKIP_DEMO=true
                shift
                ;;
            --quick)
                QUICK_START=true
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --skip-demo    Skip demo data generation"
                echo "  --quick        Quick start (skip certificate generation)"
                echo "  --help         Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Execute setup steps
    check_dependencies
    setup_environment
    create_directories
    
    if [ "$QUICK_START" = false ]; then
        generate_certificates
    fi
    
    create_wazuh_config
    pull_images
    start_services
    wait_for_services
    
    if [ "$SKIP_DEMO" = false ]; then
        generate_demo_data
    fi
    
    show_access_info
}

# Run main function
main "$@"