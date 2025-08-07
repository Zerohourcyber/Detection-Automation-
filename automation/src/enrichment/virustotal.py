"""
VirusTotal Enrichment Module
Provides threat intelligence enrichment using VirusTotal API
"""

import asyncio
import hashlib
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urlparse

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from core.config import get_settings
from core.redis_client import get_redis
from models.enrichment import EnrichmentResult, ThreatIntelligence

settings = get_settings()
logger = structlog.get_logger()


class VirusTotalEnricher:
    """VirusTotal API client for threat intelligence enrichment"""
    
    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.rate_limit_delay = 15  # seconds between requests for free tier
        self.cache_ttl = 3600  # 1 hour cache
        
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
    
    async def enrich_ioc(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        """
        Enrich an Indicator of Compromise (IoC)
        
        Args:
            ioc: The indicator to enrich (IP, domain, hash, URL)
            ioc_type: Type of indicator (ip, domain, hash, url)
            
        Returns:
            EnrichmentResult with threat intelligence data
        """
        if not self.api_key:
            return EnrichmentResult(
                ioc=ioc,
                ioc_type=ioc_type,
                source="virustotal",
                success=False,
                error="VirusTotal API key not configured"
            )
        
        # Check cache first
        cached_result = await self._get_cached_result(ioc)
        if cached_result:
            logger.info("Using cached VirusTotal result", ioc=ioc)
            return cached_result
        
        try:
            # Determine enrichment method based on IoC type
            if ioc_type == "ip":
                result = await self._enrich_ip(ioc)
            elif ioc_type == "domain":
                result = await self._enrich_domain(ioc)
            elif ioc_type == "hash":
                result = await self._enrich_hash(ioc)
            elif ioc_type == "url":
                result = await self._enrich_url(ioc)
            else:
                return EnrichmentResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    source="virustotal",
                    success=False,
                    error=f"Unsupported IoC type: {ioc_type}"
                )
            
            # Cache successful results
            if result.success:
                await self._cache_result(ioc, result)
            
            return result
            
        except Exception as e:
            logger.error("VirusTotal enrichment failed", ioc=ioc, error=str(e))
            return EnrichmentResult(
                ioc=ioc,
                ioc_type=ioc_type,
                source="virustotal",
                success=False,
                error=str(e)
            )
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def _make_api_request(self, endpoint: str) -> Dict[str, Any]:
        """Make authenticated API request to VirusTotal"""
        headers = {
            "X-Apikey": self.api_key,
            "Accept": "application/json"
        }
        
        url = f"{self.base_url}/{endpoint}"
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers)
            
            # Handle rate limiting
            if response.status_code == 429:
                logger.warning("VirusTotal rate limit hit, waiting", delay=self.rate_limit_delay)
                await asyncio.sleep(self.rate_limit_delay)
                raise httpx.HTTPStatusError("Rate limited", request=response.request, response=response)
            
            response.raise_for_status()
            return response.json()
    
    async def _enrich_ip(self, ip: str) -> EnrichmentResult:
        """Enrich IP address"""
        try:
            # Validate IP address
            ipaddress.ip_address(ip)
            
            data = await self._make_api_request(f"ip_addresses/{ip}")
            attributes = data.get("data", {}).get("attributes", {})
            
            # Extract threat intelligence
            threat_intel = ThreatIntelligence(
                malicious_score=attributes.get("last_analysis_stats", {}).get("malicious", 0),
                suspicious_score=attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                harmless_score=attributes.get("last_analysis_stats", {}).get("harmless", 0),
                undetected_score=attributes.get("last_analysis_stats", {}).get("undetected", 0),
                reputation=self._calculate_reputation(attributes.get("last_analysis_stats", {})),
                categories=attributes.get("categories", {}),
                country=attributes.get("country"),
                asn=attributes.get("asn"),
                as_owner=attributes.get("as_owner")
            )
            
            return EnrichmentResult(
                ioc=ip,
                ioc_type="ip",
                source="virustotal",
                success=True,
                threat_intelligence=threat_intel,
                raw_data=attributes,
                enriched_at=datetime.utcnow()
            )
            
        except Exception as e:
            logger.error("IP enrichment failed", ip=ip, error=str(e))
            raise
    
    async def _enrich_domain(self, domain: str) -> EnrichmentResult:
        """Enrich domain name"""
        try:
            data = await self._make_api_request(f"domains/{domain}")
            attributes = data.get("data", {}).get("attributes", {})
            
            threat_intel = ThreatIntelligence(
                malicious_score=attributes.get("last_analysis_stats", {}).get("malicious", 0),
                suspicious_score=attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                harmless_score=attributes.get("last_analysis_stats", {}).get("harmless", 0),
                undetected_score=attributes.get("last_analysis_stats", {}).get("undetected", 0),
                reputation=self._calculate_reputation(attributes.get("last_analysis_stats", {})),
                categories=attributes.get("categories", {}),
                creation_date=attributes.get("creation_date"),
                registrar=attributes.get("registrar"),
                whois=attributes.get("whois")
            )
            
            return EnrichmentResult(
                ioc=domain,
                ioc_type="domain",
                source="virustotal",
                success=True,
                threat_intelligence=threat_intel,
                raw_data=attributes,
                enriched_at=datetime.utcnow()
            )
            
        except Exception as e:
            logger.error("Domain enrichment failed", domain=domain, error=str(e))
            raise
    
    async def _enrich_hash(self, file_hash: str) -> EnrichmentResult:
        """Enrich file hash"""
        try:
            # Normalize hash (remove any whitespace/newlines)
            file_hash = file_hash.strip().lower()
            
            data = await self._make_api_request(f"files/{file_hash}")
            attributes = data.get("data", {}).get("attributes", {})
            
            threat_intel = ThreatIntelligence(
                malicious_score=attributes.get("last_analysis_stats", {}).get("malicious", 0),
                suspicious_score=attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                harmless_score=attributes.get("last_analysis_stats", {}).get("harmless", 0),
                undetected_score=attributes.get("last_analysis_stats", {}).get("undetected", 0),
                reputation=self._calculate_reputation(attributes.get("last_analysis_stats", {})),
                file_type=attributes.get("type_description"),
                file_size=attributes.get("size"),
                first_seen=attributes.get("first_submission_date"),
                last_seen=attributes.get("last_submission_date"),
                names=attributes.get("names", [])
            )
            
            return EnrichmentResult(
                ioc=file_hash,
                ioc_type="hash",
                source="virustotal",
                success=True,
                threat_intelligence=threat_intel,
                raw_data=attributes,
                enriched_at=datetime.utcnow()
            )
            
        except Exception as e:
            logger.error("Hash enrichment failed", hash=file_hash, error=str(e))
            raise
    
    async def _enrich_url(self, url: str) -> EnrichmentResult:
        """Enrich URL"""
        try:
            # URL needs to be base64 encoded for VT API
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            data = await self._make_api_request(f"urls/{url_id}")
            attributes = data.get("data", {}).get("attributes", {})
            
            threat_intel = ThreatIntelligence(
                malicious_score=attributes.get("last_analysis_stats", {}).get("malicious", 0),
                suspicious_score=attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                harmless_score=attributes.get("last_analysis_stats", {}).get("harmless", 0),
                undetected_score=attributes.get("last_analysis_stats", {}).get("undetected", 0),
                reputation=self._calculate_reputation(attributes.get("last_analysis_stats", {})),
                categories=attributes.get("categories", {}),
                first_seen=attributes.get("first_submission_date"),
                last_seen=attributes.get("last_submission_date")
            )
            
            return EnrichmentResult(
                ioc=url,
                ioc_type="url",
                source="virustotal",
                success=True,
                threat_intelligence=threat_intel,
                raw_data=attributes,
                enriched_at=datetime.utcnow()
            )
            
        except Exception as e:
            logger.error("URL enrichment failed", url=url, error=str(e))
            raise
    
    def _calculate_reputation(self, analysis_stats: Dict[str, int]) -> str:
        """Calculate reputation based on analysis statistics"""
        malicious = analysis_stats.get("malicious", 0)
        suspicious = analysis_stats.get("suspicious", 0)
        harmless = analysis_stats.get("harmless", 0)
        undetected = analysis_stats.get("undetected", 0)
        
        total = malicious + suspicious + harmless + undetected
        
        if total == 0:
            return "unknown"
        
        malicious_ratio = malicious / total
        suspicious_ratio = suspicious / total
        
        if malicious_ratio > 0.1:  # More than 10% malicious
            return "malicious"
        elif malicious_ratio > 0.05 or suspicious_ratio > 0.2:  # 5% malicious or 20% suspicious
            return "suspicious"
        elif harmless / total > 0.8:  # More than 80% harmless
            return "clean"
        else:
            return "unknown"
    
    async def _get_cached_result(self, ioc: str) -> Optional[EnrichmentResult]:
        """Get cached enrichment result"""
        try:
            redis = await get_redis()
            cache_key = f"vt_enrichment:{hashlib.md5(ioc.encode()).hexdigest()}"
            
            cached_data = await redis.get(cache_key)
            if cached_data:
                import json
                data = json.loads(cached_data)
                return EnrichmentResult(**data)
                
        except Exception as e:
            logger.warning("Failed to get cached result", error=str(e))
        
        return None
    
    async def _cache_result(self, ioc: str, result: EnrichmentResult):
        """Cache enrichment result"""
        try:
            redis = await get_redis()
            cache_key = f"vt_enrichment:{hashlib.md5(ioc.encode()).hexdigest()}"
            
            # Convert to dict for JSON serialization
            result_dict = result.dict()
            result_dict["enriched_at"] = result_dict["enriched_at"].isoformat()
            
            import json
            await redis.setex(
                cache_key,
                self.cache_ttl,
                json.dumps(result_dict, default=str)
            )
            
        except Exception as e:
            logger.warning("Failed to cache result", error=str(e))
    
    async def bulk_enrich(self, iocs: List[Dict[str, str]]) -> List[EnrichmentResult]:
        """
        Bulk enrich multiple IoCs
        
        Args:
            iocs: List of dicts with 'value' and 'type' keys
            
        Returns:
            List of EnrichmentResult objects
        """
        results = []
        
        for ioc_data in iocs:
            ioc = ioc_data.get("value")
            ioc_type = ioc_data.get("type")
            
            if not ioc or not ioc_type:
                continue
            
            try:
                result = await self.enrich_ioc(ioc, ioc_type)
                results.append(result)
                
                # Rate limiting for bulk operations
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error("Bulk enrichment failed for IoC", ioc=ioc, error=str(e))
                results.append(EnrichmentResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    source="virustotal",
                    success=False,
                    error=str(e)
                ))
        
        return results


# Utility functions for IoC extraction
def extract_iocs_from_alert(alert_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extract IoCs from alert data"""
    iocs = []
    
    # Extract IP addresses
    src_ip = alert_data.get("data", {}).get("srcip")
    if src_ip and src_ip != "127.0.0.1":
        iocs.append({"value": src_ip, "type": "ip"})
    
    dst_ip = alert_data.get("data", {}).get("dstip")
    if dst_ip and dst_ip != "127.0.0.1":
        iocs.append({"value": dst_ip, "type": "ip"})
    
    # Extract domains from DNS queries
    dns_query = alert_data.get("data", {}).get("dns", {}).get("question", {}).get("name")
    if dns_query:
        iocs.append({"value": dns_query, "type": "domain"})
    
    # Extract file hashes
    for hash_type in ["md5", "sha1", "sha256"]:
        file_hash = alert_data.get("data", {}).get(hash_type)
        if file_hash:
            iocs.append({"value": file_hash, "type": "hash"})
    
    # Extract URLs
    url = alert_data.get("data", {}).get("url")
    if url:
        iocs.append({"value": url, "type": "url"})
    
    return iocs


async def enrich_alert_with_virustotal(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich alert data with VirusTotal intelligence
    
    Args:
        alert_data: Original alert data
        
    Returns:
        Enhanced alert data with VirusTotal enrichment
    """
    enricher = VirusTotalEnricher()
    
    # Extract IoCs from alert
    iocs = extract_iocs_from_alert(alert_data)
    
    if not iocs:
        logger.info("No IoCs found in alert for VirusTotal enrichment")
        return alert_data
    
    # Enrich IoCs
    enrichment_results = await enricher.bulk_enrich(iocs)
    
    # Add enrichment data to alert
    alert_data["enrichment"] = alert_data.get("enrichment", {})
    alert_data["enrichment"]["virustotal"] = {
        "results": [result.dict() for result in enrichment_results],
        "enriched_at": datetime.utcnow().isoformat(),
        "total_iocs": len(iocs),
        "successful_enrichments": sum(1 for r in enrichment_results if r.success)
    }
    
    # Calculate overall threat score
    threat_scores = [
        r.threat_intelligence.malicious_score 
        for r in enrichment_results 
        if r.success and r.threat_intelligence
    ]
    
    if threat_scores:
        alert_data["enrichment"]["virustotal"]["max_threat_score"] = max(threat_scores)
        alert_data["enrichment"]["virustotal"]["avg_threat_score"] = sum(threat_scores) / len(threat_scores)
    
    logger.info(
        "VirusTotal enrichment completed",
        alert_id=alert_data.get("id"),
        iocs_enriched=len(enrichment_results),
        successful=sum(1 for r in enrichment_results if r.success)
    )
    
    return alert_data