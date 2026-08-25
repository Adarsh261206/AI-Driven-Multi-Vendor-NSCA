"""
Vertical Slice Integration Test

Tests the complete flow: UPLOAD → VALIDATE → DETECT → PARSE → NORMALIZE → API RESPONSE
"""

import pytest
from app.engines.validation import ConfigurationValidator
from app.engines.detection import VendorDetector
from app.engines.parsing.cisco import CiscoIOSParser
from app.engines.normalization import NormalizationEngine


class TestVerticalSlice:
    """End-to-end test of the configuration audit pipeline"""
    
    def setup_method(self):
        self.validator = ConfigurationValidator()
        self.detector = VendorDetector()
        self.parser = CiscoIOSParser()
        self.normalizer = NormalizationEngine()
    
    def test_cisco_ios_full_pipeline(self):
        """Test complete pipeline with Cisco IOS configuration"""
        config_content = """hostname EdgeRouter
!
boot-start-marker
boot-end-marker
!
enable secret 5 $1$xxxx$xxxxxxxxxxxx
!
no aaa new-model
!
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
!
interface GigabitEthernet0/0
 description ISP Link
 ip address 203.0.113.1 255.255.255.252
 ip access-group WAN_IN in
 no ip proxy-arp
 no ip redirects
 no ip unreachables
 duplex auto
 speed auto
!
interface GigabitEthernet0/1
 description LAN Gateway
 ip address 192.168.1.1 255.255.255.0
!
interface Vlan1
 no ip address
 shutdown
!
ip access-list extended WAN_IN
 permit tcp any host 203.0.113.10 eq 443
 deny ip any any
!
logging buffered 64000 informational
logging trap informational
logging host 10.0.0.100
!
ntp server 10.0.0.1
!
snmp-server community public RO
snmp-server host 10.0.0.100 version 2c public
!
banner motd ^*** Unauthorized Access Prohibited ***^
!
line con 0
 logging synchronous
 exec-timeout 5 0
 login local
line vty 0 4
 login local
 transport input ssh
 exec-timeout 5 0
!
end"""
        
        # Step 1: Ingest
        assert config_content is not None
        assert len(config_content) > 0
        
        # Step 2: Validate
        validation_result = self.validator.validate(config_content)
        assert validation_result.is_valid is True
        print(f"✓ Validation passed with {validation_result.warning_count} warnings")
        
        # Step 3: Detect vendor
        detection_result = self.detector.detect(config_content)
        assert detection_result.vendor == "cisco"
        assert detection_result.platform == "ios"
        assert detection_result.confidence > 0.5
        print(f"✓ Detected vendor: {detection_result.vendor}/{detection_result.platform} (confidence: {detection_result.confidence:.2f})")
        
        # Step 4: Parse
        parse_result = self.parser.parse(config_content)
        assert len(parse_result.parse_tree) > 0
        print(f"✓ Parsed {len(parse_result.parse_tree)} top-level sections")
        
        # Step 5: Normalize
        config_dict = {"raw_lines": config_content.splitlines()}
        normalization_result = self.normalizer.normalize(
            config_dict,
            detection_result.vendor,
            detection_result.platform,
        )
        assert normalization_result.result_type.value in ["success", "partial"]
        print(f"✓ Normalized to {len(normalization_result.mappings)} universal paths")
        
        # Step 6: Verify universal config
        universal_config = normalization_result.universal_config
        assert universal_config is not None
        
        # Check key fields
        if "hostname" in universal_config:
            print(f"  Hostname: {universal_config['hostname']}")
        if "management" in universal_config:
            ssh = universal_config["management"].get("ssh", {})
            print(f"  SSH enabled: {ssh.get('enabled')}")
            print(f"  SSH version: {ssh.get('version')}")
        
        print("\n✓ Vertical slice complete: UPLOAD → VALIDATE → DETECT → PARSE → NORMALIZE")
    
    def test_fortinet_full_pipeline(self):
        """Test complete pipeline with Fortinet configuration"""
        config_content = """#config-global
#config system global
#  set hostname "FortiGate-60E"
#end
#
#config system interface
#  edit "wan1"
#    set mode static
#    set ip 203.0.113.2 255.255.255.252
#  next
#  edit "lan"
#    set ip 192.168.1.1 255.255.255.0
#  next
#end
#
#config firewall policy
#  edit 1
#    set srcintf "lan"
#    set dstintf "wan1"
#    set srcaddr "all"
#    set dstaddr "all"
#    set action accept
#    set schedule "always"
#    set service "HTTP" "HTTPS"
#  next
#end
#
#config system ntp
#  set type custom
#  set ntpserver "10.0.0.1"
#end
#
#config log setting
#  set status enable
#end
#
#config system snmp-community
#  edit 1
#    set query-v2c-status enable
#  next
#end"""
        
        # Step 1: Validate
        validation_result = self.validator.validate(config_content)
        assert validation_result.is_valid is True
        print(f"✓ Validation passed")
        
        # Step 2: Detect vendor
        detection_result = self.detector.detect(config_content)
        assert detection_result.vendor == "fortinet"
        print(f"✓ Detected vendor: {detection_result.vendor}/{detection_result.platform}")
        
        # Step 3: Normalize
        config_dict = {"raw_lines": config_content.splitlines()}
        normalization_result = self.normalizer.normalize(
            config_dict,
            detection_result.vendor,
            detection_result.platform,
        )
        print(f"✓ Normalized to {len(normalization_result.mappings)} universal paths")
        
        print("\n✓ Fortinet pipeline complete")
    
    def test_juniper_full_pipeline(self):
        """Test complete pipeline with Juniper configuration"""
        config_content = """## system {
##     host-name EdgeRouter-Juniper;
##     services {
##         ssh;
##         telnet;
##     }
##     syslog {
##         user * {
##             interactive-commands any;
##         }
##     }
## }
## interfaces {
##     ge-0/0/0 {
##         unit 0 {
##             family inet {
##                 address 203.0.113.3/30;
##             }
##         }
##     }
##     ge-0/0/1 {
##         unit 0 {
##             family inet {
##                 address 192.168.1.1/24;
##             }
##         }
##     }
## }
## protocols {
##     ntp {
##         server 10.0.0.1;
##         server 10.0.0.2;
##     }
##     ssh {
##         root-login deny;
##     }
## }
## snmp {
##     community public {
##         authorization read-only;
##     }
## }"""
        
        # Step 1: Validate
        validation_result = self.validator.validate(config_content)
        assert validation_result.is_valid is True
        
        # Step 2: Detect vendor
        detection_result = self.detector.detect(config_content)
        assert detection_result.vendor == "juniper"
        print(f"✓ Detected vendor: {detection_result.vendor}/{detection_result.platform}")
        
        # Step 3: Normalize
        config_dict = {"raw_lines": config_content.splitlines()}
        normalization_result = self.normalizer.normalize(
            config_dict,
            detection_result.vendor,
            detection_result.platform,
        )
        print(f"✓ Normalized to {len(normalization_result.mappings)} universal paths")
        
        print("\n✓ Juniper pipeline complete")
    
    def test_validation_rejects_binary(self):
        """Test that validation rejects binary content"""
        binary_content = "hostname Router\x00extra"
        validation_result = self.validator.validate(binary_content)
        assert validation_result.is_valid is False
    
    def test_detection_fallback_to_unknown(self):
        """Test detection falls back to unknown for unrecognized configs"""
        unknown_config = """some-random-command value
another-command"""
        detection_result = self.detector.detect(unknown_config)
        assert detection_result.vendor == "unknown"
        assert detection_result.confidence < 0.3
