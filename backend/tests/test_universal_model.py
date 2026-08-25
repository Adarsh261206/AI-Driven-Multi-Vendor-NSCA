"""
Unit Tests for Universal Security Model
"""

import pytest
from app.engines.universal_model import UniversalSecurityModel, SecurityRelevance


class TestUniversalSecurityModel:
    """Tests for Universal Security Model"""
    
    def setup_method(self):
        self.model = UniversalSecurityModel()
    
    def test_model_initialization(self):
        assert len(self.model.concepts) > 0
    
    def test_device_concepts(self):
        assert "device" in self.model.concepts
        assert "device.hostname" in self.model.concepts
        assert "device.vendor" in self.model.concepts
        assert "device.platform" in self.model.concepts
        assert "device.firmware_version" in self.model.concepts
    
    def test_management_concepts(self):
        assert "management" in self.model.concepts
        assert "management.http" in self.model.concepts
        assert "management.http.enabled" in self.model.concepts
        assert "management.ssh" in self.model.concepts
        assert "management.ssh.enabled" in self.model.concepts
        assert "management.ssh.version" in self.model.concepts
        assert "management.telnet" in self.model.concepts
        assert "management.telnet.enabled" in self.model.concepts
    
    def test_authentication_concepts(self):
        assert "authentication" in self.model.concepts
        assert "authentication.password_policy" in self.model.concepts
        assert "authentication.password_policy.min_length" in self.model.concepts
        assert "authentication.password_policy.complexity" in self.model.concepts
        assert "authentication.mfa_enabled" in self.model.concepts
    
    def test_aaa_concepts(self):
        assert "aaa" in self.model.concepts
        assert "aaa.authentication_enabled" in self.model.concepts
        assert "aaa.authorization_enabled" in self.model.concepts
        assert "aaa.accounting_enabled" in self.model.concepts
    
    def test_logging_concepts(self):
        assert "logging" in self.model.concepts
        assert "logging.enabled" in self.model.concepts
        assert "logging.level" in self.model.concepts
        assert "logging.remote_enabled" in self.model.concepts
    
    def test_crypto_concepts(self):
        assert "crypto" in self.model.concepts
        assert "crypto.ssh_key_size" in self.model.concepts
        assert "crypto.https_cert_valid" in self.model.concepts
    
    def test_services_concepts(self):
        assert "services" in self.model.concepts
        assert "services.snmp" in self.model.concepts
        assert "services.snmp.enabled" in self.model.concepts
        assert "services.snmp.version" in self.model.concepts
    
    def test_get_concept(self):
        concept = self.model.get_concept("management.ssh.version")
        assert concept is not None
        assert concept.name == "SSH Version"
        assert concept.relevance == SecurityRelevance.HIGH
    
    def test_get_children(self):
        children = self.model.get_children("management")
        assert len(children) > 0
        child_paths = [c.path for c in children]
        assert "management.http" in child_paths
        assert "management.ssh" in child_paths
    
    def test_get_all_paths(self):
        paths = self.model.get_all_paths()
        assert len(paths) > 0
        assert "device" in paths
        assert "management" in paths
    
    def test_get_high_relevance_paths(self):
        paths = self.model.get_high_relevance_paths()
        assert len(paths) > 0
        assert "management.ssh.version" in paths
        assert "authentication.password_policy.min_length" in paths
    
    def test_concept_to_dict(self):
        concept = self.model.get_concept("management.ssh.version")
        d = concept.to_dict()
        assert d["path"] == "management.ssh.version"
        assert d["relevance"] == "high"
        assert d["data_type"] == "integer"
    
    def test_parent_child_relationship(self):
        parent = self.model.get_concept("management")
        assert parent is not None
        assert "management.http" in parent.children
        assert "management.ssh" in parent.children
        assert "management.telnet" in parent.children
