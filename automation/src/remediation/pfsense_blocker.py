"""
pfSense Firewall Integration Module
Automated IP blocking and network-level remediation
"""

import asyncio
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from enum import Enum

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from core.config import get_settings
from core.redis_client import get_redis
from models.remediation import RemediationAction, RemediationResult, RemediationStatus

settings = get_settings()
logger = structlog.get_logger()


class BlockDuration(Enum):
    """Predefined block durations"""
    TEMPORARY = 3600  # 1 hour
    SHORT = 86400     # 24 hours
    MEDIUM = 604800   # 7 days
    LONG = 2592000    # 30 days
    PERMANENT = 0     # Permanent block


class pfSenseClient:
    """pfSense firewall client for automated blocking"""
    
    def __init__(self):
        self.host = settings.PFSENSE_HOST
        self.username = settings.PFSENSE_USERNAME
        self.password = settings.PFSENSE_PASSWORD
        self.api_key = getattr(settings, 'PFSENSE_API_KEY', None)
        self.base_url = f"https://{self.host}"
        self.verify_ssl = settings.VERIFY_SSL
        
        # pfSense API endpoints
        self.endpoints = {
            'auth': '/api/v1/access_token',
            'firewall_rules': '/api/v1/firewall/rule',
            'firewall_aliases': '/api/v1/firewall/alias',
            'system_status': '/api/v1/status/system'
        }
        
        self._session_token = None
        
        if not all([self.host, self.username, self.password]):
            logger.warning("pfSense credentials not fully configured")
    
    async def _authenticate(self) -> bool:
        """Authenticate with pfSense and get session token"""
        try:
            auth_data = {
                'client-id': self.username,
                'client-token': self.password
            }
            
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
                response = await client.post(
                    f"{self.base_url}{self.endpoints['auth']}",
                    json=auth_data
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self._session_token = data.get('data', {}).get('token')
                    logger.info("pfSense authentication successful")
                    return True
                else:
                    logger.error("pfSense authentication failed", status_code=response.status_code)
                    return False
                    
        except Exception as e:
            logger.error("pfSense authentication error", error=str(e))
            return False
    
    async def _make_api_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None
    ) -> Optional[Dict[str, Any]]:
        """Make authenticated API request to pfSense"""
        
        if not self._session_token:
            if not await self._authenticate():
                return None
        
        headers = {
            'Authorization': f'Bearer {self._session_token}',
            'Content-Type': 'application/json'
        }
        
        url = f"{self.base_url}{endpoint}"
        
        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30.0) as client:
                if method.upper() == 'GET':
                    response = await client.get(url, headers=headers)
                elif method.upper() == 'POST':
                    response = await client.post(url, headers=headers, json=data)
                elif method.upper() == 'PUT':
                    response = await client.put(url, headers=headers, json=data)
                elif method.upper() == 'DELETE':
                    response = await client.delete(url, headers=headers)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                
                # Handle authentication expiry
                if response.status_code == 401:
                    logger.info("pfSense token expired, re-authenticating")
                    self._session_token = None
                    if await self._authenticate():
                        headers['Authorization'] = f'Bearer {self._session_token}'
                        # Retry the request
                        if method.upper() == 'GET':
                            response = await client.get(url, headers=headers)
                        elif method.upper() == 'POST':
                            response = await client.post(url, headers=headers, json=data)
                        elif method.upper() == 'PUT':
                            response = await client.put(url, headers=headers, json=data)
                        elif method.upper() == 'DELETE':
                            response = await client.delete(url, headers=headers)
                
                response.raise_for_status()
                return response.json()
                
        except Exception as e:
            logger.error("pfSense API request failed", method=method, endpoint=endpoint, error=str(e))
            return None
    
    async def block_ip(
        self,
        ip_address: str,
        duration: BlockDuration = BlockDuration.TEMPORARY,
        reason: str = "Automated security block",
        alert_id: Optional[str] = None
    ) -> RemediationResult:
        """
        Block an IP address on pfSense firewall
        
        Args:
            ip_address: IP address to block
            duration: How long to block (BlockDuration enum)
            reason: Reason for blocking
            alert_id: Associated alert ID
            
        Returns:
            RemediationResult with operation status
        """
        try:
            # Validate IP address
            ip_obj = ipaddress.ip_address(ip_address)
            
            # Check if IP is in whitelist
            if await self._is_whitelisted(ip_address):
                return RemediationResult(
                    action_type="ip_block",
                    target=ip_address,
                    status=RemediationStatus.FAILED,
                    message="IP address is whitelisted",
                    alert_id=alert_id
                )
            
            # Check if IP is already blocked
            if await self._is_already_blocked(ip_address):
                return RemediationResult(
                    action_type="ip_block",
                    target=ip_address,
                    status=RemediationStatus.SKIPPED,
                    message="IP address is already blocked",
                    alert_id=alert_id
                )
            
            # Create firewall rule to block the IP
            rule_data = self._build_block_rule(ip_address, reason)
            
            # Add the rule
            result = await self._make_api_request('POST', self.endpoints['firewall_rules'], rule_data)
            
            if result and result.get('status') == 'ok':
                rule_id = result.get('data', {}).get('id')
                
                # Cache the block for tracking
                await self._cache_block(ip_address, rule_id, duration, reason, alert_id)
                
                # Schedule unblock if temporary
                if duration != BlockDuration.PERMANENT:
                    await self._schedule_unblock(ip_address, rule_id, duration.value)
                
                logger.info(
                    "IP address blocked successfully",
                    ip=ip_address,
                    rule_id=rule_id,
                    duration=duration.name,
                    reason=reason
                )
                
                return RemediationResult(
                    action_type="ip_block",
                    target=ip_address,
                    status=RemediationStatus.SUCCESS,
                    message=f"IP blocked with rule ID {rule_id}",
                    details={
                        "rule_id": rule_id,
                        "duration": duration.name,
                        "expires_at": (
                            datetime.utcnow() + timedelta(seconds=duration.value)
                        ).isoformat() if duration != BlockDuration.PERMANENT else None
                    },
                    alert_id=alert_id
                )
            else:
                return RemediationResult(
                    action_type="ip_block",
                    target=ip_address,
                    status=RemediationStatus.FAILED,
                    message="Failed to create firewall rule",
                    alert_id=alert_id
                )
                
        except Exception as e:
            logger.error("IP blocking failed", ip=ip_address, error=str(e))
            return RemediationResult(
                action_type="ip_block",
                target=ip_address,
                status=RemediationStatus.FAILED,
                message=f"Error: {str(e)}",
                alert_id=alert_id
            )
    
    async def unblock_ip(self, ip_address: str, rule_id: Optional[str] = None) -> RemediationResult:
        """
        Unblock an IP address by removing the firewall rule
        
        Args:
            ip_address: IP address to unblock
            rule_id: Specific rule ID to remove (if known)
            
        Returns:
            RemediationResult with operation status
        """
        try:
            # If rule_id not provided, try to find it
            if not rule_id:
                rule_id = await self._find_block_rule(ip_address)
            
            if not rule_id:
                return RemediationResult(
                    action_type="ip_unblock",
                    target=ip_address,
                    status=RemediationStatus.FAILED,
                    message="Block rule not found for IP address"
                )
            
            # Remove the firewall rule
            result = await self._make_api_request('DELETE', f"{self.endpoints['firewall_rules']}/{rule_id}")
            
            if result and result.get('status') == 'ok':
                # Remove from cache
                await self._remove_cached_block(ip_address)
                
                logger.info("IP address unblocked successfully", ip=ip_address, rule_id=rule_id)
                
                return RemediationResult(
                    action_type="ip_unblock",
                    target=ip_address,
                    status=RemediationStatus.SUCCESS,
                    message=f"IP unblocked, rule {rule_id} removed",
                    details={"rule_id": rule_id}
                )
            else:
                return RemediationResult(
                    action_type="ip_unblock",
                    target=ip_address,
                    status=RemediationStatus.FAILED,
                    message="Failed to remove firewall rule"
                )
                
        except Exception as e:
            logger.error("IP unblocking failed", ip=ip_address, error=str(e))
            return RemediationResult(
                action_type="ip_unblock",
                target=ip_address,
                status=RemediationStatus.FAILED,
                message=f"Error: {str(e)}"
            )
    
    async def bulk_block_ips(
        self,
        ip_addresses: List[str],
        duration: BlockDuration = BlockDuration.TEMPORARY,
        reason: str = "Bulk automated security block"
    ) -> List[RemediationResult]:
        """Block multiple IP addresses"""
        results = []
        
        for ip in ip_addresses:
            result = await self.block_ip(ip, duration, reason)
            results.append(result)
            
            # Rate limiting to avoid overwhelming pfSense
            await asyncio.sleep(1)
        
        return results
    
    async def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Get list of currently blocked IP addresses"""
        try:
            # Get all firewall rules
            result = await self._make_api_request('GET', self.endpoints['firewall_rules'])
            
            if not result or result.get('status') != 'ok':
                return []
            
            blocked_ips = []
            rules = result.get('data', [])
            
            for rule in rules:
                if (rule.get('descr', '').startswith('AUTO_BLOCK') and 
                    rule.get('type') == 'block'):
                    
                    blocked_ips.append({
                        'ip': rule.get('source', {}).get('address'),
                        'rule_id': rule.get('id'),
                        'description': rule.get('descr'),
                        'created': rule.get('created_time'),
                        'interface': rule.get('interface')
                    })
            
            return blocked_ips
            
        except Exception as e:
            logger.error("Failed to get blocked IPs", error=str(e))
            return []
    
    def _build_block_rule(self, ip_address: str, reason: str) -> Dict[str, Any]:
        """Build firewall rule data for blocking an IP"""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
        return {
            'type': 'block',
            'interface': 'wan',
            'ipprotocol': 'inet',
            'protocol': 'any',
            'source': {
                'address': ip_address,
                'port': ''
            },
            'destination': {
                'address': 'any',
                'port': ''
            },
            'descr': f'AUTO_BLOCK_{timestamp}_{reason}',
            'log': True,
            'disabled': False
        }
    
    async def _is_whitelisted(self, ip_address: str) -> bool:
        """Check if IP is in whitelist"""
        try:
            redis = await get_redis()
            whitelist = await redis.smembers("pfsense:whitelist")
            
            # Check exact match and subnet matches
            ip_obj = ipaddress.ip_address(ip_address)
            
            for whitelisted in whitelist:
                try:
                    if '/' in whitelisted:
                        # Subnet check
                        network = ipaddress.ip_network(whitelisted, strict=False)
                        if ip_obj in network:
                            return True
                    else:
                        # Exact IP check
                        if ip_address == whitelisted:
                            return True
                except ValueError:
                    continue
            
            return False
            
        except Exception as e:
            logger.warning("Failed to check whitelist", error=str(e))
            return False
    
    async def _is_already_blocked(self, ip_address: str) -> bool:
        """Check if IP is already blocked"""
        try:
            redis = await get_redis()
            return await redis.exists(f"pfsense:blocked:{ip_address}")
        except Exception:
            return False
    
    async def _find_block_rule(self, ip_address: str) -> Optional[str]:
        """Find the rule ID for a blocked IP"""
        try:
            redis = await get_redis()
            cached_data = await redis.get(f"pfsense:blocked:{ip_address}")
            
            if cached_data:
                import json
                data = json.loads(cached_data)
                return data.get('rule_id')
            
            # Fallback: search through firewall rules
            blocked_ips = await self.get_blocked_ips()
            for blocked in blocked_ips:
                if blocked['ip'] == ip_address:
                    return blocked['rule_id']
            
            return None
            
        except Exception as e:
            logger.error("Failed to find block rule", ip=ip_address, error=str(e))
            return None
    
    async def _cache_block(
        self,
        ip_address: str,
        rule_id: str,
        duration: BlockDuration,
        reason: str,
        alert_id: Optional[str]
    ):
        """Cache block information for tracking"""
        try:
            redis = await get_redis()
            
            block_data = {
                'ip': ip_address,
                'rule_id': rule_id,
                'duration': duration.name,
                'reason': reason,
                'alert_id': alert_id,
                'blocked_at': datetime.utcnow().isoformat(),
                'expires_at': (
                    datetime.utcnow() + timedelta(seconds=duration.value)
                ).isoformat() if duration != BlockDuration.PERMANENT else None
            }
            
            import json
            await redis.setex(
                f"pfsense:blocked:{ip_address}",
                duration.value if duration != BlockDuration.PERMANENT else 86400 * 365,  # 1 year for permanent
                json.dumps(block_data)
            )
            
        except Exception as e:
            logger.warning("Failed to cache block", error=str(e))
    
    async def _remove_cached_block(self, ip_address: str):
        """Remove cached block information"""
        try:
            redis = await get_redis()
            await redis.delete(f"pfsense:blocked:{ip_address}")
        except Exception as e:
            logger.warning("Failed to remove cached block", error=str(e))
    
    async def _schedule_unblock(self, ip_address: str, rule_id: str, duration_seconds: int):
        """Schedule automatic unblock after duration"""
        try:
            redis = await get_redis()
            
            unblock_data = {
                'ip': ip_address,
                'rule_id': rule_id,
                'scheduled_at': datetime.utcnow().isoformat()
            }
            
            import json
            await redis.setex(
                f"pfsense:unblock_queue:{ip_address}",
                duration_seconds,
                json.dumps(unblock_data)
            )
            
            logger.info(
                "Unblock scheduled",
                ip=ip_address,
                rule_id=rule_id,
                duration_seconds=duration_seconds
            )
            
        except Exception as e:
            logger.warning("Failed to schedule unblock", error=str(e))
    
    async def process_unblock_queue(self):
        """Process scheduled unblocks (called by background task)"""
        try:
            redis = await get_redis()
            
            # Get all scheduled unblocks
            pattern = "pfsense:unblock_queue:*"
            keys = await redis.keys(pattern)
            
            for key in keys:
                try:
                    # Check if key still exists (TTL not expired)
                    if not await redis.exists(key):
                        continue
                    
                    # Get the data
                    data = await redis.get(key)
                    if not data:
                        continue
                    
                    import json
                    unblock_data = json.loads(data)
                    
                    ip_address = unblock_data['ip']
                    rule_id = unblock_data['rule_id']
                    
                    # Perform the unblock
                    result = await self.unblock_ip(ip_address, rule_id)
                    
                    if result.status == RemediationStatus.SUCCESS:
                        # Remove from queue
                        await redis.delete(key)
                        logger.info("Scheduled unblock completed", ip=ip_address)
                    else:
                        logger.error("Scheduled unblock failed", ip=ip_address, error=result.message)
                
                except Exception as e:
                    logger.error("Error processing unblock queue item", key=key, error=str(e))
            
        except Exception as e:
            logger.error("Error processing unblock queue", error=str(e))
    
    async def health_check(self) -> bool:
        """Check pfSense connectivity and authentication"""
        try:
            result = await self._make_api_request('GET', self.endpoints['system_status'])
            return result is not None and result.get('status') == 'ok'
        except Exception:
            return False


# Convenience functions
async def block_malicious_ip(
    ip_address: str,
    alert_data: Dict[str, Any],
    duration: BlockDuration = BlockDuration.TEMPORARY
) -> RemediationResult:
    """
    Block a malicious IP address based on alert data
    
    Args:
        ip_address: IP to block
        alert_data: Original alert data
        duration: Block duration
        
    Returns:
        RemediationResult
    """
    client = pfSenseClient()
    
    # Build reason from alert data
    rule_desc = alert_data.get('rule', {}).get('description', 'Security alert')
    alert_id = alert_data.get('id', 'unknown')
    reason = f"Alert {alert_id}: {rule_desc}"
    
    return await client.block_ip(ip_address, duration, reason, alert_id)


async def bulk_block_threat_ips(
    ip_addresses: List[str],
    threat_type: str = "Multiple threats detected"
) -> List[RemediationResult]:
    """
    Block multiple threat IPs
    
    Args:
        ip_addresses: List of IPs to block
        threat_type: Type of threat detected
        
    Returns:
        List of RemediationResult
    """
    client = pfSenseClient()
    return await client.bulk_block_ips(ip_addresses, BlockDuration.MEDIUM, threat_type)


async def emergency_block_ip(ip_address: str, reason: str = "Emergency block") -> RemediationResult:
    """Emergency IP block with long duration"""
    client = pfSenseClient()
    return await client.block_ip(ip_address, BlockDuration.LONG, reason)