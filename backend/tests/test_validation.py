"""
Unit Tests for Validation Engine
"""

import pytest
from app.engines.validation import ConfigurationValidator, ValidationSeverity


class TestConfigurationValidator:
    """Tests for Configuration Validator"""
    
    def setup_method(self):
        self.validator = ConfigurationValidator()
    
    def test_valid_config(self):
        config = """hostname Router1
interface GigabitEthernet0/0
 description WAN"""
        result = self.validator.validate(config)
        assert result.is_valid is True
        assert result.error_count == 0
    
    def test_empty_config_warning(self):
        config = ""
        result = self.validator.validate(config)
        assert result.warning_count > 0
    
    def test_binary_content_detected(self):
        config = "hostname Router1\x00extra"
        result = self.validator.validate(config)
        assert result.is_valid is False
        assert result.error_count > 0
    
    def test_sensitive_data_warning(self):
        config = "enable secret MyPassword123"
        result = self.validator.validate(config, check_sensitive=True)
        assert result.warning_count > 0
    
    def test_insecure_config_warning(self):
        config = "line vty 0 4\n transport input telnet"
        result = self.validator.validate(config, check_insecure=True)
        assert result.warning_count > 0
    
    def test_null_byte_error(self):
        config = "hostname Router\x001"
        result = self.validator.validate(config)
        assert result.is_valid is False
    
    def test_long_line_warning(self):
        config = "description " + "x" * 15000
        result = self.validator.validate(config)
        assert result.warning_count > 0
    
    def test_skip_comments(self):
        config = "! This is a comment\npassword secret123"
        result = self.validator.validate(config, check_sensitive=True)
        # Comments should not trigger sensitive data warnings
        assert result.warning_count == 0
    
    def test_skip_disabled_checks(self):
        config = "enable secret MyPassword123"
        result = self.validator.validate(config, check_sensitive=False, check_insecure=False)
        assert result.warning_count == 0
    
    def test_result_add_error(self):
        result = self.validator.validate("test")
        result.add_error("TEST_ERROR", "Test error message")
        assert result.is_valid is False
        assert result.error_count == 1
    
    def test_result_add_warning(self):
        result = self.validator.validate("test")
        result.add_warning("TEST_WARNING", "Test warning message")
        assert result.warning_count == 1
    
    def test_result_add_info(self):
        result = self.validator.validate("test")
        result.add_info("TEST_INFO", "Test info message")
        assert len(result.issues) == 1
