"""
Jira Integration Module
Automated security incident ticket creation and management
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum

import httpx
import structlog
from jira import JIRA
from tenacity import retry, stop_after_attempt, wait_exponential

from core.config import get_settings
from models.incident import SecurityIncident, IncidentSeverity, IncidentStatus

settings = get_settings()
logger = structlog.get_logger()


class JiraTicketPriority(Enum):
    """Jira ticket priority levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class JiraSecurityClient:
    """Jira client for security incident management"""
    
    def __init__(self):
        self.jira_url = settings.JIRA_URL
        self.username = settings.JIRA_USERNAME
        self.api_token = settings.JIRA_API_TOKEN
        self.project_key = settings.JIRA_PROJECT_KEY
        self.issue_type = settings.JIRA_ISSUE_TYPE
        
        self.client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Jira client"""
        if not all([self.jira_url, self.username, self.api_token]):
            logger.warning("Jira credentials not fully configured")
            return
        
        try:
            self.client = JIRA(
                server=self.jira_url,
                basic_auth=(self.username, self.api_token),
                options={'verify': settings.VERIFY_SSL}
            )
            logger.info("Jira client initialized successfully")
        except Exception as e:
            logger.error("Failed to initialize Jira client", error=str(e))
    
    async def create_security_incident(
        self,
        alert_data: Dict[str, Any],
        enrichment_data: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """
        Create a security incident ticket in Jira
        
        Args:
            alert_data: Original alert data from SIEM
            enrichment_data: Additional threat intelligence data
            
        Returns:
            Jira ticket key if successful, None otherwise
        """
        if not self.client:
            logger.error("Jira client not initialized")
            return None
        
        try:
            # Extract incident details
            incident = self._parse_alert_to_incident(alert_data, enrichment_data)
            
            # Create Jira issue
            issue_dict = self._build_jira_issue(incident)
            
            # Create the issue
            new_issue = await asyncio.to_thread(
                self.client.create_issue,
                fields=issue_dict
            )
            
            ticket_key = new_issue.key
            logger.info(
                "Security incident ticket created",
                ticket_key=ticket_key,
                alert_id=alert_data.get("id"),
                severity=incident.severity.value
            )
            
            # Add enrichment data as comments if available
            if enrichment_data:
                await self._add_enrichment_comment(ticket_key, enrichment_data)
            
            # Set appropriate labels and components
            await self._set_security_metadata(ticket_key, incident)
            
            return ticket_key
            
        except Exception as e:
            logger.error("Failed to create Jira security incident", error=str(e))
            return None
    
    def _parse_alert_to_incident(
        self,
        alert_data: Dict[str, Any],
        enrichment_data: Optional[Dict[str, Any]] = None
    ) -> SecurityIncident:
        """Parse alert data into SecurityIncident object"""
        
        # Extract basic alert information
        rule_id = alert_data.get("rule", {}).get("id", "unknown")
        rule_description = alert_data.get("rule", {}).get("description", "Security Alert")
        timestamp = alert_data.get("timestamp", datetime.utcnow().isoformat())
        
        # Determine severity based on rule level and enrichment
        severity = self._determine_severity(alert_data, enrichment_data)
        
        # Extract MITRE ATT&CK information
        mitre_tactics = alert_data.get("rule", {}).get("mitre", {}).get("tactic", [])
        mitre_techniques = alert_data.get("rule", {}).get("mitre", {}).get("technique", [])
        
        # Extract affected assets
        src_ip = alert_data.get("data", {}).get("srcip")
        dst_ip = alert_data.get("data", {}).get("dstip")
        hostname = alert_data.get("agent", {}).get("name")
        
        affected_assets = []
        if src_ip:
            affected_assets.append(f"Source IP: {src_ip}")
        if dst_ip:
            affected_assets.append(f"Destination IP: {dst_ip}")
        if hostname:
            affected_assets.append(f"Host: {hostname}")
        
        return SecurityIncident(
            title=f"Security Alert: {rule_description}",
            description=self._build_incident_description(alert_data, enrichment_data),
            severity=severity,
            status=IncidentStatus.NEW,
            rule_id=rule_id,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            affected_assets=affected_assets,
            alert_timestamp=timestamp,
            raw_alert_data=alert_data
        )
    
    def _determine_severity(
        self,
        alert_data: Dict[str, Any],
        enrichment_data: Optional[Dict[str, Any]] = None
    ) -> IncidentSeverity:
        """Determine incident severity based on alert and enrichment data"""
        
        # Base severity from rule level
        rule_level = alert_data.get("rule", {}).get("level", 0)
        
        # Check for high-risk indicators
        high_risk_indicators = [
            "brute force",
            "malware",
            "ransomware",
            "data exfiltration",
            "privilege escalation",
            "lateral movement"
        ]
        
        rule_description = alert_data.get("rule", {}).get("description", "").lower()
        has_high_risk = any(indicator in rule_description for indicator in high_risk_indicators)
        
        # Check enrichment data for threat intelligence
        threat_score = 0
        if enrichment_data:
            vt_data = enrichment_data.get("virustotal", {})
            threat_score = vt_data.get("max_threat_score", 0)
        
        # Determine severity
        if rule_level >= 12 or threat_score >= 5 or has_high_risk:
            return IncidentSeverity.CRITICAL
        elif rule_level >= 10 or threat_score >= 3:
            return IncidentSeverity.HIGH
        elif rule_level >= 7 or threat_score >= 1:
            return IncidentSeverity.MEDIUM
        else:
            return IncidentSeverity.LOW
    
    def _build_incident_description(
        self,
        alert_data: Dict[str, Any],
        enrichment_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build detailed incident description"""
        
        description_parts = []
        
        # Alert summary
        rule_desc = alert_data.get("rule", {}).get("description", "Security alert triggered")
        description_parts.append(f"*Alert Summary:*\n{rule_desc}\n")
        
        # Alert details
        description_parts.append("*Alert Details:*")
        description_parts.append(f"• Rule ID: {alert_data.get('rule', {}).get('id', 'N/A')}")
        description_parts.append(f"• Rule Level: {alert_data.get('rule', {}).get('level', 'N/A')}")
        description_parts.append(f"• Timestamp: {alert_data.get('timestamp', 'N/A')}")
        
        # Agent information
        agent = alert_data.get("agent", {})
        if agent:
            description_parts.append(f"• Agent: {agent.get('name', 'N/A')} ({agent.get('ip', 'N/A')})")
        
        # Network information
        data = alert_data.get("data", {})
        if data.get("srcip"):
            description_parts.append(f"• Source IP: {data['srcip']}")
        if data.get("dstip"):
            description_parts.append(f"• Destination IP: {data['dstip']}")
        if data.get("srcport"):
            description_parts.append(f"• Source Port: {data['srcport']}")
        if data.get("dstport"):
            description_parts.append(f"• Destination Port: {data['dstport']}")
        
        # MITRE ATT&CK mapping
        mitre = alert_data.get("rule", {}).get("mitre", {})
        if mitre:
            description_parts.append("\n*MITRE ATT&CK Mapping:*")
            if mitre.get("tactic"):
                description_parts.append(f"• Tactics: {', '.join(mitre['tactic'])}")
            if mitre.get("technique"):
                description_parts.append(f"• Techniques: {', '.join(mitre['technique'])}")
        
        # Enrichment summary
        if enrichment_data:
            description_parts.append("\n*Threat Intelligence:*")
            
            vt_data = enrichment_data.get("virustotal", {})
            if vt_data:
                successful = vt_data.get("successful_enrichments", 0)
                total = vt_data.get("total_iocs", 0)
                max_score = vt_data.get("max_threat_score", 0)
                
                description_parts.append(f"• VirusTotal: {successful}/{total} IoCs enriched")
                description_parts.append(f"• Max Threat Score: {max_score}")
        
        # Raw log data (truncated)
        full_log = alert_data.get("full_log", "")
        if full_log:
            truncated_log = full_log[:500] + "..." if len(full_log) > 500 else full_log
            description_parts.append(f"\n*Raw Log Data:*\n{{code}}{truncated_log}{{code}}")
        
        return "\n".join(description_parts)
    
    def _build_jira_issue(self, incident: SecurityIncident) -> Dict[str, Any]:
        """Build Jira issue dictionary"""
        
        # Map severity to Jira priority
        priority_mapping = {
            IncidentSeverity.CRITICAL: JiraTicketPriority.CRITICAL,
            IncidentSeverity.HIGH: JiraTicketPriority.HIGH,
            IncidentSeverity.MEDIUM: JiraTicketPriority.MEDIUM,
            IncidentSeverity.LOW: JiraTicketPriority.LOW
        }
        
        priority = priority_mapping.get(incident.severity, JiraTicketPriority.MEDIUM)
        
        issue_dict = {
            'project': {'key': self.project_key},
            'summary': incident.title,
            'description': incident.description,
            'issuetype': {'name': self.issue_type},
            'priority': {'name': priority.value},
            'labels': self._generate_labels(incident)
        }
        
        # Add custom fields if configured
        custom_fields = self._get_custom_fields(incident)
        issue_dict.update(custom_fields)
        
        return issue_dict
    
    def _generate_labels(self, incident: SecurityIncident) -> List[str]:
        """Generate appropriate labels for the incident"""
        labels = ['security-automation', 'siem-alert']
        
        # Add severity label
        labels.append(f"severity-{incident.severity.value.lower()}")
        
        # Add MITRE technique labels
        for technique in incident.mitre_techniques:
            labels.append(f"mitre-{technique.lower().replace('.', '-')}")
        
        # Add rule-based labels
        if 'brute' in incident.title.lower():
            labels.append('brute-force')
        if 'dns' in incident.title.lower():
            labels.append('dns-security')
        if 'malware' in incident.title.lower():
            labels.append('malware')
        
        return labels
    
    def _get_custom_fields(self, incident: SecurityIncident) -> Dict[str, Any]:
        """Get custom field mappings for security incidents"""
        custom_fields = {}
        
        # Add MITRE ATT&CK fields if custom fields are configured
        # This would need to be customized based on your Jira setup
        
        return custom_fields
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def _add_enrichment_comment(self, ticket_key: str, enrichment_data: Dict[str, Any]):
        """Add enrichment data as a comment to the ticket"""
        try:
            comment_text = self._format_enrichment_comment(enrichment_data)
            
            await asyncio.to_thread(
                self.client.add_comment,
                ticket_key,
                comment_text
            )
            
            logger.info("Enrichment comment added to ticket", ticket_key=ticket_key)
            
        except Exception as e:
            logger.error("Failed to add enrichment comment", ticket_key=ticket_key, error=str(e))
    
    def _format_enrichment_comment(self, enrichment_data: Dict[str, Any]) -> str:
        """Format enrichment data as Jira comment"""
        comment_parts = ["*Threat Intelligence Enrichment:*\n"]
        
        # VirusTotal data
        vt_data = enrichment_data.get("virustotal", {})
        if vt_data:
            comment_parts.append("*VirusTotal Results:*")
            
            for result in vt_data.get("results", []):
                if result.get("success"):
                    ioc = result.get("ioc")
                    ioc_type = result.get("ioc_type")
                    threat_intel = result.get("threat_intelligence", {})
                    reputation = threat_intel.get("reputation", "unknown")
                    malicious_score = threat_intel.get("malicious_score", 0)
                    
                    comment_parts.append(f"• {ioc_type.upper()}: {ioc}")
                    comment_parts.append(f"  - Reputation: {reputation}")
                    comment_parts.append(f"  - Malicious Score: {malicious_score}")
        
        return "\n".join(comment_parts)
    
    async def _set_security_metadata(self, ticket_key: str, incident: SecurityIncident):
        """Set security-specific metadata on the ticket"""
        try:
            # This could include setting components, fix versions, etc.
            # based on the type of security incident
            pass
            
        except Exception as e:
            logger.error("Failed to set security metadata", ticket_key=ticket_key, error=str(e))
    
    async def update_ticket_status(self, ticket_key: str, status: str, comment: Optional[str] = None):
        """Update ticket status"""
        if not self.client:
            return False
        
        try:
            # Get available transitions
            transitions = await asyncio.to_thread(
                self.client.transitions,
                ticket_key
            )
            
            # Find the transition that matches the desired status
            transition_id = None
            for transition in transitions:
                if transition['name'].lower() == status.lower():
                    transition_id = transition['id']
                    break
            
            if not transition_id:
                logger.warning("Transition not found", ticket_key=ticket_key, status=status)
                return False
            
            # Perform the transition
            await asyncio.to_thread(
                self.client.transition_issue,
                ticket_key,
                transition_id,
                comment=comment
            )
            
            logger.info("Ticket status updated", ticket_key=ticket_key, status=status)
            return True
            
        except Exception as e:
            logger.error("Failed to update ticket status", ticket_key=ticket_key, error=str(e))
            return False
    
    async def add_comment(self, ticket_key: str, comment: str):
        """Add a comment to an existing ticket"""
        if not self.client:
            return False
        
        try:
            await asyncio.to_thread(
                self.client.add_comment,
                ticket_key,
                comment
            )
            
            logger.info("Comment added to ticket", ticket_key=ticket_key)
            return True
            
        except Exception as e:
            logger.error("Failed to add comment", ticket_key=ticket_key, error=str(e))
            return False
    
    async def get_ticket_info(self, ticket_key: str) -> Optional[Dict[str, Any]]:
        """Get ticket information"""
        if not self.client:
            return None
        
        try:
            issue = await asyncio.to_thread(
                self.client.issue,
                ticket_key
            )
            
            return {
                "key": issue.key,
                "summary": issue.fields.summary,
                "status": issue.fields.status.name,
                "priority": issue.fields.priority.name if issue.fields.priority else None,
                "assignee": issue.fields.assignee.displayName if issue.fields.assignee else None,
                "created": issue.fields.created,
                "updated": issue.fields.updated
            }
            
        except Exception as e:
            logger.error("Failed to get ticket info", ticket_key=ticket_key, error=str(e))
            return None


async def create_security_incident_ticket(
    alert_data: Dict[str, Any],
    enrichment_data: Optional[Dict[str, Any]] = None
) -> Optional[str]:
    """
    Convenience function to create a security incident ticket
    
    Args:
        alert_data: Alert data from SIEM
        enrichment_data: Optional enrichment data
        
    Returns:
        Jira ticket key if successful
    """
    jira_client = JiraSecurityClient()
    return await jira_client.create_security_incident(alert_data, enrichment_data)