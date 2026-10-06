"""
Unit Tests for Parsing Engines
"""

from app.engines.parsing.cisco import CiscoIOSParser


class TestCiscoIOSParser:
    """Tests for Cisco IOS Parser"""
    
    def setup_method(self):
        self.parser = CiscoIOSParser()
    
    def test_simple_hostname(self):
        config = """hostname Router1"""
        result = self.parser.parse(config)
        assert len(result.parse_tree) == 1
        assert result.parse_tree[0].key == "hostname"
        assert result.parse_tree[0].value == "Router1"
    
    def test_interface_section(self):
        config = """interface GigabitEthernet0/0
 description WAN Interface
 ip address 192.168.1.1 255.255.255.0
 no shutdown"""
        result = self.parser.parse(config)
        assert len(result.parse_tree) == 1
        assert result.parse_tree[0].key == "interface"
        assert result.parse_tree[0].value == "GigabitEthernet0/0"
        assert len(result.parse_tree[0].children) == 3
    
    def test_line_section(self):
        config = """line vty 0 4
 login local
 transport input ssh
 exec-timeout 5 0"""
        result = self.parser.parse(config)
        assert len(result.parse_tree) == 1
        assert result.parse_tree[0].key == "line"
        assert "vty" in result.parse_tree[0].value
        assert len(result.parse_tree[0].children) == 3
    
    def test_access_list(self):
        config = """access-list 10 permit 192.168.1.0 0.0.0.255
access-list 10 deny any"""
        result = self.parser.parse(config)
        assert len(result.parse_tree) == 2
        assert result.parse_tree[0].key == "acl"
    
    def test_snmp_config(self):
        config = """snmp-server community public RO
snmp-server community private RW
snmp-server host 192.168.1.100 version 2c community"""
        result = self.parser.parse(config)
        assert len(result.parse_tree) == 3
    
    def test_comments_ignored(self):
        config = """! This is a comment
hostname Router1
! Another comment
interface GigabitEthernet0/0
 description Test"""
        result = self.parser.parse(config)
        assert len(result.parse_tree) == 2
    
    def test_empty_lines_ignored(self):
        config = """hostname Router1


interface GigabitEthernet0/0"""
        result = self.parser.parse(config)
        assert len(result.parse_tree) == 2
    
    def test_empty_config(self):
        config = ""
        result = self.parser.parse(config)
        assert len(result.parse_tree) == 0
    
    def test_only_comments(self):
        config = """! This is a comment
! Another comment"""
        result = self.parser.parse(config)
        assert len(result.parse_tree) == 0
    
    def test_get_section_value(self):
        config = """hostname Router1
interface GigabitEthernet0/0
 description WAN"""
        result = self.parser.parse(config)
        value = self.parser.get_section_value(result.parse_tree, "hostname")
        assert value == "Router1"
    
    def test_find_all(self):
        config = """interface GigabitEthernet0/0
 description WAN
interface GigabitEthernet0/1
 description LAN"""
        result = self.parser.parse(config)
        interfaces = self.parser.find_all(result.parse_tree, r"^interface")
        assert len(interfaces) == 2
    
    def test_unknown_sections_tracked(self):
        config = """hostname Router1
some-unknown-command value"""
        result = self.parser.parse(config)
        # E04 F2: unrecognised commands are flagged as unknown sections,
        # not silently accepted as tree nodes.
        assert len(result.parse_tree) == 1
        assert len(result.unknown_sections) == 1
        assert result.unknown_sections[0].raw_text == "some-unknown-command value"
    
    def test_parse_errors_empty(self):
        config = """hostname Router1"""
        result = self.parser.parse(config)
        assert len(result.parse_errors) == 0


class TestCiscoIOSParserComplex:
    """Complex parsing scenarios"""
    
    def setup_method(self):
        self.parser = CiscoIOSParser()
    
    def test_full_router_config(self):
        config = """hostname EdgeRouter
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
 no ip mask-reply
 no ip mroute-cache
 duplex auto
 speed auto
 no cdp enable
 no mop enabled
!
interface GigabitEthernet0/1
 description LAN Gateway
 ip address 192.168.1.1 255.255.255.0
 no ip proxy-arp
!
interface GigabitEthernet0/2
 description Management
 ip address 10.0.0.1 255.255.255.0
!
interface Vlan1
 no ip address
 shutdown
!
ip access-list extended WAN_IN
 permit tcp any host 203.0.113.10 eq 443
 permit tcp any host 203.0.113.10 eq 8443
 deny ip any any
!
logging buffered 64000 informational
logging trap informational
logging host 10.0.0.100
logging source-interface GigabitEthernet0/2
!
ntp server 10.0.0.1
ntp server 10.0.0.2
!
snmp-server community public RO
snmp-server community private RW
snmp-server host 10.0.0.100 version 2c public
snmp-server enable traps
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
        result = self.parser.parse(config)
        
        # Check that key sections are parsed
        assert len(result.parse_tree) > 0
        
        # Check hostname
        hostname = self.parser.get_section_value(result.parse_tree, "hostname")
        assert hostname == "EdgeRouter"
        
        # Check interfaces
        interfaces = self.parser.find_all(result.parse_tree, r"^interface")
        assert len(interfaces) >= 4
        
        # Check access list
        acls = self.parser.find_all(result.parse_tree, r"access-list")
        assert len(acls) >= 1
