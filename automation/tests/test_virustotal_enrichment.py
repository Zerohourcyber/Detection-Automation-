"""
Unit tests for VirusTotal enrichment module
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from enrichment.virustotal import (
    VirusTotalEnricher,
    extract_iocs_from_alert,
    enrich_alert_with_virustotal
)
from models.enrichment import EnrichmentResult, ThreatIntelligence


class TestVirusTotalEnricher:
    """Test cases for VirusTotalEnricher class"""
    
    @pytest.fixture
    def enricher(self):
        """Create VirusTotalEnricher instance for testing"""
        with patch('enrichment.virustotal.get_settings') as mock_settings:
            mock_settings.return_value.VIRUSTOTAL_API_KEY = "test-api-key"
            return VirusTotalEnricher()
    
    @pytest.fixture
    def sample_vt_ip_response(self):
        """Sample VirusTotal IP response"""
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "harmless": 80,
                        "undetected": 3
                    },
                    "country": "US",
                    "asn": 15169,
                    "as_owner": "Google LLC",
                    "categories": {"webmail": 1}
                }
            }
        }
    
    @pytest.fixture
    def sample_alert_data(self):
        """Sample alert data for testing"""
        return {
            "id": "test-alert-123",
            "data": {
                "srcip": "192.168.1.100",
                "dstip": "8.8.8.8",
                "dns": {
                    "question": {
                        "name": "malicious.example.com"
                    }
                },
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "url": "http://malicious.example.com/payload"
            }
        }
    
    @pytest.mark.asyncio
    async def test_enrich_ip_success(self, enricher, sample_vt_ip_response):
        """Test successful IP enrichment"""
        with patch.object(enricher, '_make_api_request', return_value=sample_vt_ip_response):
            with patch.object(enricher, '_get_cached_result', return_value=None):
                with patch.object(enricher, '_cache_result', return_value=None):
                    
                    result = await enricher.enrich_ioc("8.8.8.8", "ip")
                    
                    assert result.success is True
                    assert result.ioc == "8.8.8.8"
                    assert result.ioc_type == "ip"
                    assert result.source == "virustotal"
                    assert result.threat_intelligence is not None
                    assert result.threat_intelligence.malicious_score == 5
                    assert result.threat_intelligence.country == "US"
    
    @pytest.mark.asyncio
    async def test_enrich_ip_cached_result(self, enricher):
        """Test IP enrichment with cached result"""
        cached_result = EnrichmentResult(
            ioc="8.8.8.8",
            ioc_type="ip",
            source="virustotal",
            success=True,
            threat_intelligence=ThreatIntelligence(
                malicious_score=0,
                reputation="clean"
            )
        )
        
        with patch.object(enricher, '_get_cached_result', return_value=cached_result):
            result = await enricher.enrich_ioc("8.8.8.8", "ip")
            
            assert result.success is True
            assert result.ioc == "8.8.8.8"
            assert result.threat_intelligence.reputation == "clean"
    
    @pytest.mark.asyncio
    async def test_enrich_invalid_ip(self, enricher):
        """Test enrichment with invalid IP address"""
        result = await enricher.enrich_ioc("invalid-ip", "ip")
        
        assert result.success is False
        assert "invalid literal for int()" in result.error or "does not appear to be an IPv4 or IPv6 address" in result.error
    
    @pytest.mark.asyncio
    async def test_enrich_unsupported_ioc_type(self, enricher):
        """Test enrichment with unsupported IoC type"""
        result = await enricher.enrich_ioc("test", "unsupported")
        
        assert result.success is False
        assert "Unsupported IoC type" in result.error
    
    @pytest.mark.asyncio
    async def test_enrich_no_api_key(self):
        """Test enrichment without API key"""
        with patch('enrichment.virustotal.get_settings') as mock_settings:
            mock_settings.return_value.VIRUSTOTAL_API_KEY = None
            enricher = VirusTotalEnricher()
            
            result = await enricher.enrich_ioc("8.8.8.8", "ip")
            
            assert result.success is False
            assert "VirusTotal API key not configured" in result.error
    
    @pytest.mark.asyncio
    async def test_bulk_enrich(self, enricher, sample_vt_ip_response):
        """Test bulk enrichment of multiple IoCs"""
        iocs = [
            {"value": "8.8.8.8", "type": "ip"},
            {"value": "malicious.com", "type": "domain"},
            {"value": "d41d8cd98f00b204e9800998ecf8427e", "type": "hash"}
        ]
        
        with patch.object(enricher, 'enrich_ioc') as mock_enrich:
            mock_enrich.return_value = EnrichmentResult(
                ioc="test",
                ioc_type="test",
                source="virustotal",
                success=True
            )
            
            results = await enricher.bulk_enrich(iocs)
            
            assert len(results) == 3
            assert all(result.success for result in results)
            assert mock_enrich.call_count == 3
    
    def test_calculate_reputation(self, enricher):
        """Test reputation calculation logic"""
        # Malicious
        stats = {"malicious": 10, "suspicious": 0, "harmless": 0, "undetected": 0}
        assert enricher._calculate_reputation(stats) == "malicious"
        
        # Suspicious
        stats = {"malicious": 1, "suspicious": 5, "harmless": 10, "undetected": 4}
        assert enricher._calculate_reputation(stats) == "suspicious"
        
        # Clean
        stats = {"malicious": 0, "suspicious": 0, "harmless": 80, "undetected": 20}
        assert enricher._calculate_reputation(stats) == "clean"
        
        # Unknown
        stats = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
        assert enricher._calculate_reputation(stats) == "unknown"


class TestIoCExtraction:
    """Test cases for IoC extraction functions"""
    
    def test_extract_iocs_from_alert(self):
        """Test IoC extraction from alert data"""
        alert_data = {
            "data": {
                "srcip": "192.168.1.100",
                "dstip": "8.8.8.8",
                "dns": {
                    "question": {
                        "name": "malicious.example.com"
                    }
                },
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "url": "http://malicious.example.com/payload"
            }
        }
        
        iocs = extract_iocs_from_alert(alert_data)
        
        # Should extract 5 IoCs: 2 IPs, 1 domain, 2 hashes, 1 URL
        assert len(iocs) == 5
        
        ioc_types = [ioc["type"] for ioc in iocs]
        assert "ip" in ioc_types
        assert "domain" in ioc_types
        assert "hash" in ioc_types
        assert "url" in ioc_types
        
        # Check specific values
        ip_iocs = [ioc for ioc in iocs if ioc["type"] == "ip"]
        assert len(ip_iocs) == 2
        assert any(ioc["value"] == "192.168.1.100" for ioc in ip_iocs)
        assert any(ioc["value"] == "8.8.8.8" for ioc in ip_iocs)
    
    def test_extract_iocs_empty_alert(self):
        """Test IoC extraction from empty alert data"""
        alert_data = {"data": {}}
        iocs = extract_iocs_from_alert(alert_data)
        assert len(iocs) == 0
    
    def test_extract_iocs_localhost_filtered(self):
        """Test that localhost IPs are filtered out"""
        alert_data = {
            "data": {
                "srcip": "127.0.0.1",
                "dstip": "8.8.8.8"
            }
        }
        
        iocs = extract_iocs_from_alert(alert_data)
        
        # Should only extract the non-localhost IP
        assert len(iocs) == 1
        assert iocs[0]["value"] == "8.8.8.8"


class TestAlertEnrichment:
    """Test cases for alert enrichment functions"""
    
    @pytest.mark.asyncio
    async def test_enrich_alert_with_virustotal(self):
        """Test full alert enrichment with VirusTotal"""
        alert_data = {
            "id": "test-alert-123",
            "data": {
                "srcip": "8.8.8.8"
            }
        }
        
        mock_result = EnrichmentResult(
            ioc="8.8.8.8",
            ioc_type="ip",
            source="virustotal",
            success=True,
            threat_intelligence=ThreatIntelligence(
                malicious_score=5,
                reputation="suspicious"
            )
        )
        
        with patch('enrichment.virustotal.VirusTotalEnricher') as mock_enricher_class:
            mock_enricher = AsyncMock()
            mock_enricher.bulk_enrich.return_value = [mock_result]
            mock_enricher_class.return_value = mock_enricher
            
            enriched_alert = await enrich_alert_with_virustotal(alert_data)
            
            assert "enrichment" in enriched_alert
            assert "virustotal" in enriched_alert["enrichment"]
            
            vt_data = enriched_alert["enrichment"]["virustotal"]
            assert vt_data["total_iocs"] == 1
            assert vt_data["successful_enrichments"] == 1
            assert vt_data["max_threat_score"] == 5
            assert vt_data["avg_threat_score"] == 5.0
    
    @pytest.mark.asyncio
    async def test_enrich_alert_no_iocs(self):
        """Test alert enrichment with no extractable IoCs"""
        alert_data = {
            "id": "test-alert-123",
            "data": {}
        }
        
        enriched_alert = await enrich_alert_with_virustotal(alert_data)
        
        # Should return original alert unchanged
        assert enriched_alert == alert_data


class TestCaching:
    """Test cases for caching functionality"""
    
    @pytest.fixture
    def enricher(self):
        """Create VirusTotalEnricher instance for testing"""
        with patch('enrichment.virustotal.get_settings') as mock_settings:
            mock_settings.return_value.VIRUSTOTAL_API_KEY = "test-api-key"
            return VirusTotalEnricher()
    
    @pytest.mark.asyncio
    async def test_cache_result(self, enricher):
        """Test caching of enrichment results"""
        result = EnrichmentResult(
            ioc="8.8.8.8",
            ioc_type="ip",
            source="virustotal",
            success=True,
            enriched_at=datetime.utcnow()
        )
        
        with patch('enrichment.virustotal.get_redis') as mock_get_redis:
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis
            
            await enricher._cache_result("8.8.8.8", result)
            
            mock_redis.setex.assert_called_once()
            args = mock_redis.setex.call_args[0]
            assert args[0].startswith("vt_enrichment:")
            assert args[1] == enricher.cache_ttl
    
    @pytest.mark.asyncio
    async def test_get_cached_result(self, enricher):
        """Test retrieval of cached results"""
        cached_data = {
            "ioc": "8.8.8.8",
            "ioc_type": "ip",
            "source": "virustotal",
            "success": True,
            "enriched_at": "2024-01-01T00:00:00"
        }
        
        with patch('enrichment.virustotal.get_redis') as mock_get_redis:
            mock_redis = AsyncMock()
            mock_redis.get.return_value = '{"ioc": "8.8.8.8", "ioc_type": "ip", "source": "virustotal", "success": true, "enriched_at": "2024-01-01T00:00:00"}'
            mock_get_redis.return_value = mock_redis
            
            result = await enricher._get_cached_result("8.8.8.8")
            
            assert result is not None
            assert result.ioc == "8.8.8.8"
            assert result.success is True


@pytest.mark.integration
class TestVirusTotalIntegration:
    """Integration tests for VirusTotal API (requires real API key)"""
    
    @pytest.mark.skipif(
        not pytest.config.getoption("--integration"),
        reason="Integration tests require --integration flag"
    )
    @pytest.mark.asyncio
    async def test_real_api_call(self):
        """Test real API call to VirusTotal (requires valid API key)"""
        import os
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        
        if not api_key:
            pytest.skip("VIRUSTOTAL_API_KEY environment variable not set")
        
        with patch('enrichment.virustotal.get_settings') as mock_settings:
            mock_settings.return_value.VIRUSTOTAL_API_KEY = api_key
            enricher = VirusTotalEnricher()
            
            # Test with Google DNS (should be clean)
            result = await enricher.enrich_ioc("8.8.8.8", "ip")
            
            assert result.success is True
            assert result.threat_intelligence is not None
            assert result.threat_intelligence.reputation in ["clean", "unknown"]


# Pytest configuration
def pytest_addoption(parser):
    """Add command line options for pytest"""
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="Run integration tests"
    )


def pytest_configure(config):
    """Configure pytest"""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )


# Test fixtures for async testing
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()