"""
Unit Tests for Normalization Engine
"""

from app.engines.normalization import NormalizationEngine, NormalizationResultType


class TestNormalizationEngine:
    """Tests for Normalization Engine"""
    
    def setup_method(self):
        self.engine = NormalizationEngine()
    
    def test_cisco_hostname_normalization(self):
        config = {"raw_lines": ["hostname EdgeRouter"]}
        result = self.engine.normalize(config, "cisco", "ios")
        assert result.result_type == NormalizationResultType.SUCCESS
        assert result.universal_config.get("device", {}).get("hostname") == "EdgeRouter"
    
    def test_cisco_http_disabled(self):
        config = {"raw_lines": ["no ip http server"]}
        result = self.engine.normalize(config, "cisco", "ios")
        assert result.result_type == NormalizationResultType.SUCCESS
        assert result.universal_config.get("management", {}).get("http", {}).get("enabled") is False
    
    def test_cisco_ssh_enabled(self):
        config = {"raw_lines": ["line vty 0 4", " transport input ssh"]}
        result = self.engine.normalize(config, "cisco", "ios")
        assert result.result_type == NormalizationResultType.SUCCESS
        assert result.universal_config.get("management", {}).get("ssh", {}).get("enabled") is True
    
    def test_cisco_ssh_version(self):
        config = {"raw_lines": ["ip ssh version 2"]}
        result = self.engine.normalize(config, "cisco", "ios")
        assert result.universal_config.get("management", {}).get("ssh", {}).get("version") == 2
    
    def test_cisco_aaa_enabled(self):
        config = {"raw_lines": ["aaa authentication login default local", "aaa authorization exec default local"]}
        result = self.engine.normalize(config, "cisco", "ios")
        assert result.universal_config.get("aaa", {}).get("authentication_enabled") is True
        assert result.universal_config.get("aaa", {}).get("authorization_enabled") is True
    
    def test_cisco_logging_enabled(self):
        config = {"raw_lines": ["logging buffered 64000", "logging host 10.0.0.100"]}
        result = self.engine.normalize(config, "cisco", "ios")
        assert result.universal_config.get("logging", {}).get("enabled") is True
        assert result.universal_config.get("logging", {}).get("remote_enabled") is True
    
    def test_cisco_ntp_configured(self):
        config = {"raw_lines": ["ntp server 10.0.0.1", "ntp authentication-key 1 md5 secret"]}
        result = self.engine.normalize(config, "cisco", "ios")
        assert result.universal_config.get("ntp", {}).get("configured") is True
    
    def test_cisco_snmp_version(self):
        config = {"raw_lines": ["snmp-server group admin v3 auth"]}
        result = self.engine.normalize(config, "cisco", "ios")
        assert result.universal_config.get("services", {}).get("snmp", {}).get("version") == 3
    
    def test_unknown_vendor_returns_failed(self):
        config = {"raw_lines": ["some config"]}
        result = self.engine.normalize(config, "unknown", "unknown")
        assert result.result_type == NormalizationResultType.FAILED
    
    def test_mappings_tracked(self):
        config = {"raw_lines": ["hostname TestRouter", "ip ssh version 2"]}
        result = self.engine.normalize(config, "cisco", "ios")
        assert len(result.mappings) > 0
        assert result.mappings[0].model_path is not None
    
    def test_fortinet_hostname(self):
        config = {"raw_lines": ['config system global', 'set hostname "FortiGate-60E"', 'end']}
        result = self.engine.normalize(config, "fortinet", "fortios")
        assert result.universal_config.get("device", {}).get("hostname") == "FortiGate-60E"

    def test_juniper_hostname(self):
        config = {"raw_lines": ["set system host-name EdgeRouter-Juniper"]}
        result = self.engine.normalize(config, "juniper", "junos")
        assert result.universal_config.get("device", {}).get("hostname") == "EdgeRouter-Juniper"
