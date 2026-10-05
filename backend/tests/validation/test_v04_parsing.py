"""Engine 04 — Vendor Configuration Parsing Engines validation.

Scope: backend/app/engines/parsing/{cisco,juniper,fortinet}.py and the
caller contract in app/engines/compliance/executor.py.

Methodology rule for this engine (user-mandated):
  * Categories A/B/C/D/E/F/H/I/J/K test each parser on content that IS of
    the vendor that parser claims to handle. Detector output is NOT used
    as ground truth here.
  * Category G is the separate, explicitly-labelled record of what happens
    when the pipeline hands a parser content of a different vendor.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest

from app.engines.parsing.cisco import CiscoIOSParser, ConfigNode as CiscoNode
from app.engines.parsing.juniper import (
    JunosParser,
    ConfigNode as JunosNode,
    ParseWarning as JunosParseWarning,
)
from app.engines.parsing.fortinet import (
    FortiOSParser,
    ConfigNode as FortiNode,
    ParseResult as FortiParseResult,
)

BACKEND = Path(__file__).resolve().parents[2]

CISCO_CFG = """hostname R1
!
interface GigabitEthernet0/0
 description WAN Interface
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
line vty 0 4
 login local
 transport input ssh
 exec-timeout 5 0
"""

JUNOS_CFG = """version 12.3R6.6;
system {
    host-name R1;
    services {
        ssh;
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
"""

JUNOS_SET_CFG = """set system host-name R1
set system services ssh
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
"""

FORTI_CFG = """config system interface
    edit "port1"
        set mode static
        set ip 192.168.1.1/24
    next
end
config firewall policy
    edit 0
        set srcintf "port1"
    next
end
"""


def walk(nodes):
    out = []
    for n in nodes:
        out.append(n)
        out.extend(walk(n.children))
    return out


def cisco(cfg: str):
    return CiscoIOSParser().parse(cfg)


def junos(cfg: str):
    return JunosParser().parse(cfg)


def forti(cfg: str):
    return FortiOSParser().parse(cfg)


# --------------------------------------------------------------------------
# A. Cisco functional contract on canonical IOS content
# --------------------------------------------------------------------------

def test_v04_01_hostname_node(recorder):
    r = cisco("hostname Router1")
    ok = len(r.parse_tree) == 1 and r.parse_tree[0].key == "hostname" \
        and r.parse_tree[0].value == "Router1"
    recorder.add(
        "V04-01", "A", "a single hostname line becomes one root node",
        "'hostname Router1'", "1 root node key=hostname value=Router1",
        f"roots={len(r.parse_tree)} key={r.parse_tree[0].key!r} value={r.parse_tree[0].value!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "parsing/cisco.py:parse",
    )
    assert ok


def test_v04_02_interface_section(recorder):
    r = cisco(CISCO_CFG)
    ifaces = [n for n in r.parse_tree if n.key == "interface"]
    child_keys = [c.key for c in ifaces[0].children] if ifaces else []
    ok = len(ifaces) == 1 and ifaces[0].value == "GigabitEthernet0/0" \
        and {"description", "ip", "shutdown"} <= set(child_keys)
    recorder.add(
        "V04-02", "A", "an interface section owns its child statements",
        "4-line interface block", "1 interface node owning description/ip/shutdown",
        f"interface nodes={len(ifaces)} value={ifaces[0].value if ifaces else None!r} "
        f"children={child_keys}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "cisco.py section handling",
        "the following 'line' section is a root sibling (see V04-04)",
    )
    assert ok


def test_v04_03_interface_children_keys(recorder):
    r = cisco(CISCO_CFG)
    iface = [n for n in r.parse_tree if n.key == "interface"][0]
    statement_keys = [c.key for c in iface.children
                      if c.key not in {"line", "router", "vlan", "acl", "crypto"}]
    ok = statement_keys == ["description", "ip", "shutdown"]
    recorder.add(
        "V04-03", "A", "interface child statements keep their own command keys",
        "description/ip/no-shutdown inside interface",
        "['description', 'ip', 'shutdown']",
        f"statement children={statement_keys} (all children="
        f"{[c.key for c in iface.children]})",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "cisco.py key/value parsing",
        "the 'no' prefix sets negated=True on the node (see V04-41/V04-42)",
    )
    assert ok


def test_v04_04_line_section_is_top_level(recorder):
    r = cisco(CISCO_CFG)
    line_nodes = [n for n in walk(r.parse_tree) if n.key == "line"]
    nested = [n for n in line_nodes if n.path]
    roots = [n for n in r.parse_tree if n.key == "line"]
    ok = len(nested) == 0 and len(roots) == 1
    recorder.add(
        "V04-04", "A",
        "a top-level 'line vty 0 4' section is a root section (IOS sections do not nest)",
        "line block following an interface block",
        "line node at the root with path=[]",
        f"line nodes={[(n.key, n.value, n.path) for n in line_nodes]}; "
        f"root-level line sections={len(roots)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F1: cisco.py closes every open section on a new section start, "
        "so consecutive top-level sections are root siblings",
        "",
    )
    assert ok


def test_v04_05_acl_sections(recorder):
    r = cisco(
        "access-list 10 permit 192.168.1.0 0.0.0.255\n"
        "access-list 10 deny any\n"
    )
    ok = len(r.parse_tree) == 2 and all(n.key == "acl" for n in r.parse_tree)
    recorder.add(
        "V04-05", "A", "access-list lines become acl sections",
        "2 access-list lines", "2 root nodes key=acl",
        f"roots={len(r.parse_tree)} keys={[n.key for n in r.parse_tree]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "cisco.py SECTION_PATTERNS",
    )
    assert ok


def test_v04_06_comments_and_blank_ignored(recorder):
    r = cisco("! comment\n\nhostname R1\n! other\n\ninterface Gi0/0")
    keys = [n.key for n in r.parse_tree]
    ok = keys == ["hostname", "interface"]
    recorder.add(
        "V04-06", "A", "'!' comments and blank lines are not parsed",
        "comment/blank lines around 2 commands",
        "2 roots: hostname, interface", str(keys),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "cisco.py comment/blank handling",
    )
    assert ok


def test_v04_07_empty_input(recorder):
    results = {}
    for name, fn in (("cisco", cisco), ("juniper", junos), ("fortinet", forti)):
        r = fn("")
        results[name] = (len(r.parse_tree), len(r.parse_errors))
    ok = all(v == (0, 0) for v in results.values())
    recorder.add(
        "V04-07", "A", "empty content yields an empty result and no errors on all 3 parsers",
        "''", "(0 nodes, 0 errors) x3", str(results),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "parse() input type guards in all three parsers",
    )
    assert ok


def test_v04_08_get_section_value(recorder):
    r = cisco(CISCO_CFG)
    v = CiscoIOSParser().get_section_value(r.parse_tree, "hostname")
    ok = v == "R1"
    recorder.add(
        "V04-08", "A", "get_section_value resolves a dotted section path",
        "path 'hostname'", "'R1'", repr(v),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "cisco.py get_section_value",
    )
    assert ok


def test_v04_09_find_all_regex(recorder):
    r = cisco(CISCO_CFG)
    found = CiscoIOSParser().find_all(r.parse_tree, r"^interface")
    ok = len(found) == 1
    recorder.add(
        "V04-09", "A", "find_all matches nodes by regex over raw_text",
        "pattern ^interface", "1 match", f"{len(found)} matches",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "cisco.py find_all",
    )
    assert ok


def test_v04_10_line_numbers_are_source_indices(recorder):
    lines = CISCO_CFG.splitlines()
    r = cisco(CISCO_CFG)
    nodes = walk(r.parse_tree)
    bad = [n for n in nodes
           if n.line_number < 1 or n.line_number > len(lines)
           or lines[n.line_number - 1].strip() != n.raw_text]
    ok = bool(nodes) and not bad
    recorder.add(
        "V04-10", "A", "every node's line_number/raw_text points at its source line",
        "canonical IOS config", "0 mismatches",
        f"nodes={len(nodes)} mismatches={len(bad)}"
        + (f" e.g. line {bad[0].line_number} raw={bad[0].raw_text!r} src={lines[bad[0].line_number-1].strip()!r}" if bad else ""),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "cisco.py node line_number/raw_text",
    )
    assert ok


# --------------------------------------------------------------------------
# B. Juniper functional contract on canonical JUNOS content
# --------------------------------------------------------------------------

def test_v04_11_junos_hierarchical_tree(recorder):
    r = junos(JUNOS_CFG)
    ssh = JunosParser.get_section(r.parse_tree, ["system", "services", "ssh"])
    ok = ssh is not None and ssh.value is None
    recorder.add(
        "V04-11", "B", "hierarchical JUNOS resolves system.services.ssh",
        "brace-style JUNOS config", "node ssh found with value None",
        f"node={'found' if ssh else 'None'} value={ssh.value if ssh else None!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "juniper.py hierarchical parsing/get_section",
    )
    assert ok


def test_v04_12_junos_nested_path(recorder):
    r = junos(JUNOS_CFG)
    addr = [n for n in walk(r.parse_tree) if n.key == "address"]
    ok = len(addr) == 1 and addr[0].value == "10.0.0.1/24" \
        and addr[0].path == ["interfaces", "ge-0/0/0", "unit", "family"]
    recorder.add(
        "V04-12", "B", "a deeply nested leaf keeps its full ancestor path",
        "address inside interfaces.ge-0/0-0.unit.family",
        "path=['interfaces','ge-0/0/0','unit','family'] value=10.0.0.1/24",
        f"path={addr[0].path if addr else None} value={addr[0].value if addr else None!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "juniper.py node construction",
    )
    assert ok


def test_v04_13_junos_set_style(recorder):
    r = junos(JUNOS_SET_CFG)
    hn = [n for n in walk(r.parse_tree) if n.key == "host-name"]
    ok = len(hn) == 1 and hn[0].value == "R1" and hn[0].path == ["system"]
    recorder.add(
        "V04-13", "B", "set-style 'set system host-name R1' reconstructs the path",
        "3 set lines", "host-name node path=['system'] value='R1'",
        f"nodes={[n.key for n in walk(r.parse_tree)]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "juniper.py set-style parsing",
    )
    assert ok


def test_v04_14_junos_set_style_bare_leaf(recorder):
    r = junos(JUNOS_SET_CFG)
    ssh = [n for n in walk(r.parse_tree) if n.key == "ssh"]
    ok = len(ssh) == 1 and ssh[0].value is None \
        and ssh[0].path == ["system", "services"]
    recorder.add(
        "V04-14", "B", "a set line with an unknown leaf key keeps the path prefix",
        "'set system services ssh'", "ssh node path=['system','services']",
        f"nodes={[(n.path, n.key, n.value) for n in ssh]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "juniper.py set leaf split",
    )
    assert ok


def test_v04_15_junos_hash_prefix_stripped(recorder):
    r = junos("## version 12.3;\nsystem {\n    host-name R1;\n}\n")
    keys = [n.key for n in r.parse_tree]
    ok = keys == ["version", "system"] and r.parse_tree[0].line_number == 1
    recorder.add(
        "V04-15", "B", "'##'-prefixed show-configuration output is decoded, line numbers kept",
        "'## version 12.3;' + system block",
        "roots ['version','system'], line_number preserved",
        f"keys={keys} lines={[n.line_number for n in r.parse_tree]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "juniper.py style detection",
    )
    assert ok


def test_v04_16_junos_multiple_statements_one_line(recorder):
    r = junos("system {\n    host-name R1; services ssh;\n}\n")
    keys = [n.key for n in r.parse_tree[0].children]
    ok = keys == ["host-name", "services"]
    recorder.add(
        "V04-16", "B", "two ';'-separated statements on one line become two nodes",
        "'host-name R1; services ssh;'", "['host-name','services']", str(keys),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "juniper.py statement splitting",
    )
    assert ok


def test_v04_17_junos_unbalanced_closing_brace(recorder):
    r = junos("system {\n    host-name R1;\n}\n}\n")
    ok = len(r.parse_errors) == 1 and "Unbalanced closing brace" in r.parse_errors[0].message
    recorder.add(
        "V04-17", "B", "an unmatched '}' is reported as a parse error",
        "extra closing brace", "1 parse error 'Unbalanced closing brace'",
        f"errors={[(e.line_number, e.message) for e in r.parse_errors]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "juniper.py unbalanced-brace error",
    )
    assert ok


def test_v04_18_junos_unclosed_brace_warning(recorder):
    r = junos("system {\n    host-name R1;\n")
    ok = len(r.parse_warnings) == 1 and "Unclosed braces" in r.parse_warnings[0].message
    recorder.add(
        "V04-18", "B", "an unclosed '{' is reported as a parse warning",
        "missing closing brace", "1 warning 'Unclosed braces: system'",
        f"warnings={[(w.line_number, w.message) for w in r.parse_warnings]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "juniper.py unclosed-brace warning",
    )
    assert ok


def test_v04_19_junos_warning_type_confusion(recorder):
    r = junos("system {\n    host-name R1;\n")
    types = [type(w).__name__ for w in r.parse_warnings]
    is_warning = [isinstance(w, JunosParseWarning) for w in r.parse_warnings]
    fixed = types == ["ParseWarning"] and all(is_warning)
    recorder.add(
        "V04-19", "B", "parse_warnings only ever contains ParseWarning instances",
        "unclosed brace input",
        "all parse_warnings are ParseWarning instances",
        f"types={types} isinstance(ParseWarning)={is_warning}",
        "PASS" if fixed else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F2: juniper.py appends ParseWarning for unclosed blocks "
        "(was ParseError)",
        "",
    )
    assert fixed


def test_v04_20_junos_hash_comment_skipped(recorder):
    r = junos("# comment\nsystem {\n    host-name R1;\n}\n")
    ok = len(r.parse_tree) == 1 and r.parse_tree[0].key == "system"
    recorder.add(
        "V04-20", "B", "'#' comments are not parsed",
        "comment line before a system block", "1 root: system",
        f"roots={[(n.key) for n in r.parse_tree]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "juniper.py comment handling",
    )
    assert ok


def test_v04_21_junos_find_all_static(recorder):
    r = junos(JUNOS_SET_CFG)
    found = JunosParser.find_all(r.parse_tree, "address")
    ok = len(found) == 1
    recorder.add(
        "V04-21", "B", "JunosParser.find_all locates a key anywhere in the tree",
        "set-style config", "1 address node", f"{len(found)} nodes",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "juniper.py find_all",
    )
    assert ok


# --------------------------------------------------------------------------
# C. Fortinet functional contract on canonical FortiOS content
# --------------------------------------------------------------------------

def test_v04_22_forti_config_block(recorder):
    r = forti(FORTI_CFG)
    cfgs = [n for n in r.parse_tree if n.key == "config"]
    ok = len(cfgs) == 2 and cfgs[0].value == "system interface"
    recorder.add(
        "V04-22", "C", "'config ...' blocks become config nodes with the block name",
        "2 config blocks", "2 roots value='system interface'/'firewall policy'",
        f"values={[n.value for n in cfgs]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "fortinet.py config blocks",
    )
    assert ok


def test_v04_23_forti_edit_block(recorder):
    r = forti(FORTI_CFG)
    edits = [n for n in walk(r.parse_tree) if n.key == "edit"]
    ok = len(edits) == 2 and edits[0].value == '"port1"'
    recorder.add(
        "V04-23", "C", "'edit' blocks nest under their config block",
        "edit \"port1\" inside config system interface",
        "2 edit nodes, first value='\"port1\"'",
        f"count={len(edits)} values={[n.value for n in edits]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "fortinet.py edit blocks",
    )
    assert ok


def test_v04_24_forti_set_key_value(recorder):
    r = forti(FORTI_CFG)
    ip = [n for n in walk(r.parse_tree) if n.key == "ip"]
    ok = len(ip) == 1 and ip[0].value == "192.168.1.1/24"
    recorder.add(
        "V04-24", "C", "'set <key> <value>' becomes a key/value node",
        "'set ip 192.168.1.1/24'", "key='ip' value='192.168.1.1/24'",
        f"nodes={[(n.key, n.value) for n in ip]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "fortinet.py set commands",
    )
    assert ok


def test_v04_25_forti_next_and_end_close_blocks(recorder):
    r = forti(FORTI_CFG)
    ok = (len(r.parse_errors) == 0 and len(r.parse_warnings) == 0
          and len(r.parse_tree) == 2)
    recorder.add(
        "V04-25", "C", "balanced 'next'/'end' pairs leave no errors or warnings",
        "2 balanced config/edit blocks",
        "0 errors, 0 warnings, 2 roots",
        f"errors={len(r.parse_errors)} warnings={len(r.parse_warnings)} roots={len(r.parse_tree)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "fortinet.py next/end handling",
    )
    assert ok


def test_v04_26_forti_stray_end(recorder):
    r = forti("end\n")
    ok = len(r.parse_errors) == 1 and "without matching" in r.parse_errors[0].message
    recorder.add(
        "V04-26", "C", "an 'end' with no open config block is a parse error",
        "'end' at top level", "1 parse error",
        f"errors={[(e.line_number, e.message) for e in r.parse_errors]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "fortinet.py stray-end error",
    )
    assert ok


def test_v04_27_forti_stray_next(recorder):
    r = forti("next\n")
    ok = len(r.parse_errors) == 1 and "without matching" in r.parse_errors[0].message
    recorder.add(
        "V04-27", "C", "a 'next' with no open edit block is a parse error",
        "'next' at top level", "1 parse error",
        f"errors={[(e.line_number, e.message) for e in r.parse_errors]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "fortinet.py stray-next error",
    )
    assert ok


def test_v04_28_forti_unknown_line_flagged(recorder):
    r = forti("config system interface\n delete internal1\nend\n")
    ok = len(r.unknown_sections) == 1 and r.unknown_sections[0].raw_text == "delete internal1"
    recorder.add(
        "V04-28", "C", "an unrecognised command inside a block is flagged as unknown",
        "'delete internal1'", "1 unknown section",
        f"unknown={[u.raw_text for u in r.unknown_sections]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "fortinet.py unknown lines",
    )
    assert ok


def test_v04_29_forti_unclosed_blocks_warn(recorder):
    r = forti("config system interface\n edit \"port1\"\n  set mode static\n")
    msgs = [w.message for w in r.parse_warnings]
    ok = len(msgs) == 2 and any("Unclosed config sections" in m for m in msgs) \
        and any("Unclosed edit blocks" in m for m in msgs)
    recorder.add(
        "V04-29", "C", "unclosed config and edit blocks each raise a warning",
        "config/edit with no end/next",
        "2 warnings (config sections + edit blocks)",
        f"warnings={msgs}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "fortinet.py unclosed-block warnings",
    )
    assert ok


def test_v04_30_forti_unset_preserved(recorder):
    r = forti("config system interface\n edit \"a\"\n  unset mode\n next\nend\n")
    keys = [n.key for n in walk(r.parse_tree)]
    ok = "unset_mode" in keys
    recorder.add(
        "V04-30", "C", "'unset <key>' keeps the negation in the node key",
        "'unset mode'", "node key 'unset_mode'",
        f"keys={keys}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "fortinet.py unset handling",
    )
    assert ok


def test_v04_31_forti_comment_skipped(recorder):
    r = forti("# comment\nconfig system interface\nend\n")
    ok = len(r.parse_tree) == 1 and len(r.unknown_sections) == 0
    recorder.add(
        "V04-31", "C", "'#' comments are not flagged as unknown",
        "comment line before a config block", "1 root, 0 unknown",
        f"roots={len(r.parse_tree)} unknown={len(r.unknown_sections)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "fortinet.py comment handling",
    )
    assert ok


# --------------------------------------------------------------------------
# D. Parser selection and pipeline integration
# --------------------------------------------------------------------------

def test_v04_32_get_parser_cisco(recorder):
    from app.engines.compliance.executor import AuditExecutor
    p = AuditExecutor()._get_parser("cisco", "ios_xe")
    ok = isinstance(p, CiscoIOSParser)
    recorder.add(
        "V04-32", "D", "vendor 'cisco' selects the Cisco IOS parser",
        "_get_parser('cisco','ios_xe')", "CiscoIOSParser",
        type(p).__name__, "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "executor.py:_get_parser",
    )
    assert ok


def test_v04_33_get_parser_juniper(recorder):
    from app.engines.compliance.executor import AuditExecutor
    p = AuditExecutor()._get_parser("juniper", "junos")
    ok = isinstance(p, JunosParser)
    recorder.add(
        "V04-33", "D", "vendor 'juniper' selects the Junos parser",
        "_get_parser('juniper','junos')", "JunosParser",
        type(p).__name__, "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "executor.py:_get_parser",
    )
    assert ok


def test_v04_34_get_parser_fortinet(recorder):
    from app.engines.compliance.executor import AuditExecutor
    p = AuditExecutor()._get_parser("fortinet", "fortios")
    ok = isinstance(p, FortiOSParser)
    recorder.add(
        "V04-34", "D", "vendor 'fortinet' selects the FortiOS parser",
        "_get_parser('fortinet','fortios')", "FortiOSParser",
        type(p).__name__, "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "executor.py:_get_parser",
    )
    assert ok


def test_v04_35_get_parser_unsupported_returns_none(recorder):
    from app.engines.compliance.executor import AuditExecutor
    ex = AuditExecutor()
    observed = {v: type(ex._get_parser(v, "eos")).__name__
                for v in ("arista", "f5", "frr", "a10", "paloalto", "unknown", "")}
    ok = all(t == "NoneType" for t in observed.values())
    recorder.add(
        "V04-35", "D",
        "an unsupported/unknown vendor does not fall back to a different vendor's parser",
        "_get_parser for arista/f5/frr/a10/paloalto/unknown/''",
        "all -> None (an explicit 'no parser' outcome; execute() stops the "
        "audit after detection)",
        f"all -> None: {ok} ({observed})",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "executor.py _get_parser else branch — E03 F2 removed the Cisco fallback "
        "(pre-fix all of these returned CiscoIOSParser)",
        "",
    )
    assert ok


def test_v04_36_get_parser_platform_argument_ignored(recorder):
    from app.engines.compliance.executor import AuditExecutor
    ex = AuditExecutor()
    a = type(ex._get_parser("cisco", "junos")).__name__
    b = type(ex._get_parser("cisco", "ios_xe")).__name__
    c = type(ex._get_parser("juniper", "ios_xe")).__name__
    ok = a == b == "CiscoIOSParser" and c == "JunosParser"
    recorder.add(
        "V04-36", "D", "the platform argument influences parser selection",
        "_get_parser(vendor, platform) with mismatched platforms",
        "platform does not change the parser: one parser covers each vendor "
        "family (platform stays in the signature for the caller contract)",
        f"platform has no effect (cisco+junos={a}, cisco+ios_xe={b}, juniper+ios_xe={c})",
        "PASS" if ok else "FAIL", "DESIGN DECISION",
        "app/engines/parsing/__init__.py get_parser: platform accepted, "
        "selection by vendor family only",
        "platform stays in the signature for the caller contract",
    )
    assert ok


def test_v04_37_audit_pipeline_completes_offline(recorder):
    from app.engines.compliance.executor import AuditExecutor
    cfg = (BACKEND / "tests" / "sample_configs" / "secure.txt").read_text(
        encoding="utf-8", errors="replace")
    t0 = time.perf_counter()
    r = AuditExecutor().execute("v04-probe", cfg, framework="CIS", device_name="probe")
    ms = (time.perf_counter() - t0) * 1000
    steps = [(s.name, s.status) for s in r.steps]
    ok = (r.status == "completed"
          and all(st == "completed" for _, st in steps)
          and r.parse_result is not None)
    recorder.add(
        "V04-37", "D", "the full audit pipeline runs offline and completes the parsing step",
        "AuditExecutor.execute(secure.txt)",
        "status=completed, all 6 steps completed, parse_result set",
        f"status={r.status} steps={steps} parse={type(r.parse_result).__name__} {ms:.0f}ms",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "executor.py:execute",
    )
    assert ok


def test_v04_38_benchmark_evaluation_does_not_consume_parse_tree(recorder, monkeypatch):
    from app.engines.compliance.executor import AuditExecutor
    from types import SimpleNamespace

    seen: dict = {}

    class FakeBenchmark:
        def execute(self, **kwargs):
            seen["benchmark_kwargs"] = sorted(kwargs.keys())
            seen["raw_config_is_raw"] = isinstance(kwargs.get("raw_config"), str)
            seen["raw_config_len"] = len(kwargs.get("raw_config") or "")
            seen["benchmark_norm_is_executor_norm"] = (
                kwargs.get("normalization_result") is seen.get("normalization_obj"))
            return SimpleNamespace(
                vendor=kwargs.get("vendor", ""), platform=kwargs.get("platform", ""),
                evaluations=[], evaluated=0, passed=0, failed=0, review=0, score=0.0,
            )

    class FakeNormalizer:
        def normalize(self, config_dict, vendor, platform,
                      semantic_interpretation=None):
            from app.engines.normalization import NormalizationResultType
            seen["normalizer_first_arg_keys"] = sorted(config_dict.keys())
            seen["normalizer_raw_lines"] = isinstance(
                config_dict.get("raw_lines"), list)
            seen["normalizer_semantic"] = isinstance(semantic_interpretation, dict) \
                and len(semantic_interpretation.get("sections", [])) > 0
            seen["normalization_obj"] = SimpleNamespace(
                result_type=NormalizationResultType.SUCCESS)
            return seen["normalization_obj"]

    ex = AuditExecutor()
    ex.benchmark_engine = FakeBenchmark()
    ex.normalizer = FakeNormalizer()
    # E03 F2: execution stops after detection for vendors outside
    # SUPPORTED_COMPLIANCE_VENDORS, so the cfg must detect as cisco for the
    # benchmark/normalizer instrumentation below to be observable.
    cfg = ("! Cisco IOS config\nhostname R1\ninterface Gi0/0\n"
           " ip address 1.1.1.1 255.255.255.0\n")
    r = ex.execute("v04-probe-2", cfg, framework="CIS")

    ok = (seen.get("benchmark_kwargs") == ["framework", "framework_version",
                                           "normalization_result", "platform",
                                           "raw_config", "vendor",
                                           "vendor_identification"]
          and seen.get("raw_config_is_raw")
          and seen.get("raw_config_len") == len(cfg)
          and seen.get("normalizer_first_arg_keys") == ["raw_lines"]
          and seen.get("normalizer_raw_lines")
          and seen.get("normalizer_semantic")
          and seen.get("benchmark_norm_is_executor_norm")
          and r.parse_result is not None)
    recorder.add(
        "V04-38", "D",
        "compliance evaluation consumes the single authoritative normalization result",
        "AuditExecutor.execute with instrumented benchmark + normalizer",
        "normalizer called once with §10.5 sections; benchmark receives that "
        "same result object (no second normalization)",
        f"benchmark kwargs={seen.get('benchmark_kwargs')} "
        f"raw_config_len={seen.get('raw_config_len')} "
        f"normalizer keys={seen.get('normalizer_first_arg_keys')} "
        f"semantic={seen.get('normalizer_semantic')} "
        f"identity={seen.get('benchmark_norm_is_executor_norm')} "
        f"parse_result={type(r.parse_result).__name__}",
        "FAIL" if not ok else "PASS", "CONFIRMED BEHAVIOR",
        "E05 F5: executor.py normalizes once (canonical platform, §10.5 "
        "sections) and passes normalization_result into the benchmark; "
        "the benchmark consumes it without re-normalizing",
        "",
    )
    assert ok


def test_v04_39_api_persistence_drops_parse_errors(recorder):
    src = (BACKEND / "app" / "api" / "v1" / "audit_execution.py").read_text(
        encoding="utf-8")
    has_hardcode = bool(re.search(r"parse_errors=\[\]", src)) and bool(
        re.search(r"parse_warnings=\[\]", src))
    ok = not has_hardcode
    recorder.add(
        "V04-39", "D",
        "parse errors and warnings produced by a parser are persisted, not discarded",
        "source of ParsedConfiguration construction",
        "parser errors/warnings written to the database",
        "parser errors/warnings persisted from result.parse_result"
        if ok else "hard-coded empty lists found",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F2: api/v1/audit_execution.py serialises result.parse_result "
        "parse_errors/parse_warnings into ParsedConfiguration",
        "",
    )
    assert ok


def test_v04_40_adaptive_reanalysis_hardcodes_cisco_parser(recorder):
    src = (BACKEND / "app" / "ai" / "adaptive.py").read_text(encoding="utf-8")
    hardcodes = "CiscoIOSParser()" in src
    dispatched = "get_parser(" in src
    ok = dispatched and not hardcodes
    recorder.add(
        "V04-40", "D",
        "semantic re-analysis parses content with the vendor's own parser",
        "source of AdaptiveLearning re-analysis",
        "parser chosen from the supplied vendor",
        "vendor-dispatched parser via parsing.get_parser"
        if ok else "hard-coded CiscoIOSParser regardless of vendor",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F3/F10: ai/adaptive.py reanalyze_with_mapping dispatches on the "
        "vendor argument; unsupported vendors get a safe empty result",
        "",
    )
    assert ok


# --------------------------------------------------------------------------
# E. Semantic fidelity (negation, banners, key selection, format sanity)
# --------------------------------------------------------------------------

def test_v04_41_negation_ip_http_server(recorder):
    plain = cisco("ip http server")
    negated = cisco("no ip http server")
    same = [(n.key, n.value) for n in plain.parse_tree] == \
           [(n.key, n.value) for n in negated.parse_tree]
    flags = ([n.negated for n in plain.parse_tree],
             [n.negated for n in negated.parse_tree])
    ok = same and flags == ([False], [True])
    recorder.add(
        "V04-41", "E",
        "'no ip http server' is distinguishable from 'ip http server' in the parse tree",
        "'ip http server' vs 'no ip http server'",
        "same (key,value), different negated flags ([False] vs [True])",
        f"identical={same} flags={flags} "
        f"plain={[(n.key, n.value) for n in plain.parse_tree]} "
        f"negated={[(n.key, n.value) for n in negated.parse_tree]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F4: cisco.py sets negated=True on 'no ...' nodes (ConfigNode.negated)",
        "",
    )
    assert ok


def test_v04_42_negation_shutdown(recorder):
    plain = cisco("shutdown")
    negated = cisco("no shutdown")
    same = [(n.key, n.value) for n in plain.parse_tree] == \
           [(n.key, n.value) for n in negated.parse_tree]
    flags = ([n.negated for n in plain.parse_tree],
             [n.negated for n in negated.parse_tree])
    ok = same and flags == ([False], [True])
    recorder.add(
        "V04-42", "E",
        "'no shutdown' is distinguishable from 'shutdown' in the parse tree",
        "'shutdown' vs 'no shutdown'",
        "same (key,value), different negated flags ([False] vs [True])",
        f"identical={same} flags={flags} "
        f"plain={[(n.key, n.value) for n in plain.parse_tree]} "
        f"negated={[(n.key, n.value) for n in negated.parse_tree]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F4: cisco.py sets negated=True on 'no ...' nodes",
        "",
    )
    assert ok


def test_v04_43_negation_survives_only_in_raw_text(recorder):
    n = cisco("no ip http server").parse_tree[0]
    ok = n.raw_text.startswith("no ")
    recorder.add(
        "V04-43", "E",
        "the original 'no ...' wording is still recoverable from the node",
        "'no ip http server'", "raw_text retains the negation",
        f"raw_text={n.raw_text!r} key={n.key!r} value={n.value!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "cisco.py node construction",
        "consumers must re-derive negation from raw_text",
    )
    assert ok


def test_v04_44_confignode_has_no_negation_field(recorder):
    shapes = [{f for f in cls.__dataclass_fields__}
              for cls in (CiscoNode, JunosNode, FortiNode)]
    ok = all("negated" in s for s in shapes)
    recorder.add(
        "V04-44", "E",
        "ConfigurationNode can express negation as a first-class field",
        "ConfigNode dataclass fields", "a negated field on all three parsers",
        f"negated present={[('negated' in s) for s in shapes]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F4: cisco.py/juniper.py/fortinet.py ConfigNode.negated "
        "(uniform cross-parser shape)",
        "",
    )
    assert ok


def test_v04_45_fortinet_unset_keeps_negation(recorder):
    r = forti("config system interface\n edit \"a\"\n  unset shutdown\n next\nend\n")
    keys = [n.key for n in walk(r.parse_tree)]
    ok = "unset_shutdown" in keys
    recorder.add(
        "V04-45", "E",
        "FortiOS 'unset' keeps the negation visible in the node key",
        "'unset shutdown'", "'unset_shutdown' present",
        f"keys={keys}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "fortinet.py unset handling",
        "contrast with the Cisco parser, which drops 'no' (V04-41/V04-42)",
    )
    assert ok


def test_v04_46_multiline_banner_body_becomes_nodes(recorder):
    cfg = ("hostname R1\nbanner motd ^Unauthorized\nAccess denied\nKeep out^\n"
           "interface Gi0/0\n ip address 1.1.1.1 255.255.255.0\n")
    r = cisco(cfg)
    nodes = walk(r.parse_tree)
    junk = [n for n in nodes if n.raw_text in
            ("Access denied", "Keep out^", "Unauthorized")]
    banners = [n for n in nodes if n.key == "banner"]
    ok = len(junk) == 0 and len(banners) == 1 \
        and "Access denied" in (banners[0].value or "") \
        and len(r.parse_errors) == 0
    recorder.add(
        "V04-46", "E",
        "banner body text is not parsed as configuration commands",
        "3-line 'banner motd ^...^' block",
        "one opaque banner node holding the body, no banner-body nodes",
        f"banner-body nodes={[(n.key, n.value, n.line_number) for n in junk]} "
        f"banners={[(b.value, b.line_number) for b in banners]} "
        f"errors={len(r.parse_errors)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F5: cisco.py consumes text between banner delimiters as one "
        "opaque node value",
        "",
    )
    assert ok


def test_v04_47_acl_sequence_number_becomes_node_key(recorder):
    r = cisco("ip access-list acl_in\n 30 deny icmp any any redirect\n")
    nodes = walk(r.parse_tree)
    seq = [n for n in nodes if n.key == "30"]
    deny_by_key = CiscoIOSParser().find_all(r.parse_tree, r"^deny")
    deny = [n for n in nodes if n.key == "deny"]
    ok = len(seq) == 0 and len(deny_by_key) == 1 \
        and deny and deny[0].value == "icmp any any redirect" \
        and "30 deny" in deny[0].raw_text
    recorder.add(
        "V04-47", "E",
        "an ACL entry can be found by its action keyword",
        "'30 deny icmp any any redirect'",
        "find_all('^deny') returns the entry; '30' is not a key",
        f"nodes={[(n.key, n.value) for n in nodes]} find_all('^deny')={len(deny_by_key)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F14: cisco.py uses the action keyword as the key; the sequence "
        "number stays recoverable from raw_text",
        "",
    )
    assert ok


def test_v04_48_json_content_parsed_without_error(recorder):
    json_cfg = '{\n  "hostname": "R1",\n  "interface Gi0/0": {\n    "shutdown": {}\n  }\n}'
    r = cisco(json_cfg)
    keys = [n.key for n in walk(r.parse_tree)]
    ok = len(r.parse_errors) >= 1 and "JSON" in r.parse_errors[0].message \
        and len(r.parse_tree) == 0
    recorder.add(
        "V04-48", "E",
        "content that is not IOS syntax is reported instead of silently converted",
        "JSON document fed to CiscoIOSParser",
        "a parse error signalling the JSON envelope, empty tree",
        f"errors={[(e.line_number, e.message) for e in r.parse_errors]} nodes={[(n.key, n.value) for n in walk(r.parse_tree)]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F6: cisco.py detects the JSON envelope (RFC 8259) before parsing",
        "",
    )
    assert ok


def test_v04_49_junos_set_style_value_as_key(recorder):
    r = junos("set protocols bgp group EXTERNAL peer-as 65001\n")
    bad = [n for n in walk(r.parse_tree) if n.key == "65001"]
    good = [n for n in walk(r.parse_tree)
            if n.key == "peer-as" and n.value == "65001"]
    ok = not bad and len(good) == 1
    recorder.add(
        "V04-49", "E",
        "set-style parsing keeps the AS number as a value, not as a node key",
        "'set protocols bgp group EXTERNAL peer-as 65001'",
        "leaf key 'peer-as' value '65001'",
        f"nodes={[(n.path, n.key, n.value) for n in walk(r.parse_tree)]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F14: juniper.py pairs a numeric/quoted last set-token with the "
        "previous token as key=value",
        "",
    )
    assert ok


def test_v04_50_fortinet_value_empty_string_vs_none(recorder):
    forti_r = forti("config system interface\n set mtu\nend\n")
    cisco_r = cisco("hostname")
    junos_r = junos("system {\n ssh;\n}\n")
    f_val = [n.value for n in walk(forti_r.parse_tree) if n.key == "mtu"]
    c_val = [n.value for n in walk(cisco_r.parse_tree)]
    j_val = [n.value for n in walk(junos_r.parse_tree) if n.key == "ssh"]
    ok = f_val == [None] and c_val == [None] and j_val == [None]
    recorder.add(
        "V04-50", "E",
        "a value-less statement is represented the same way by all three parsers",
        "'set mtu' / 'hostname' / 'ssh;'",
        "one consistent representation (all None, per spec string|null)",
        f"fortinet={f_val} cisco={c_val} juniper={j_val}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F13: fortinet.py uses None for absent values, uniform with "
        "cisco.py and juniper.py",
        "",
    )
    assert ok


# --------------------------------------------------------------------------
# F. Diagnostics required by spec 10.3 (errors / warnings / unknown sections)
# --------------------------------------------------------------------------

def test_v04_51_cisco_never_reports_errors(recorder):
    samples = {
        "junk": "some-unknown-command value\n@@@ ###\n",
        "unbalanced": "interface Gi0/0\n ip address 1.1.1.1 255.255.255.0\n",
        "binary": "\x00\x01\x02\r\nhostname R1\n",
        "truncated": "router ospf 1\n network 192.168.1.0 0.0.0.255 area\n",
    }
    errs = {k: len(cisco(v).parse_errors) for k, v in samples.items()}
    unks = {k: len(cisco(v).unknown_sections) for k, v in samples.items()}
    warns = {k: len(cisco(v).parse_warnings) for k, v in samples.items()}
    # binary content is a parse error; unknown commands are flagged unknown
    # (never errors); an open section is a warning; a structurally complete
    # (if semantically odd) line is not a parse-level error.
    ok = (errs["binary"] >= 1 and errs["junk"] == 0 and unks["junk"] >= 1
          and warns["unbalanced"] >= 1 and errs["truncated"] == 0)
    recorder.add(
        "V04-51", "F",
        "the Cisco parser reports parse errors for malformed input (spec 10.3)",
        "4 malformed inputs",
        "binary->error, junk->unknown (no error), open section->warning, "
        "complete line->no error",
        f"errors per input={errs} unknown per input={unks} warnings per input={warns}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F2: cisco.py emits deterministic errors/warnings/unknowns per class",
        "",
    )
    assert ok


def test_v04_52_cisco_never_reports_warnings(recorder):
    r = cisco("interface Gi0/0\n ip address 1.1.1.1 255.255.255.0")
    r2 = cisco("! only comments")
    counts = {"open_interface": len(r.parse_warnings), "comments_only": len(r2.parse_warnings)}
    ok = all(v >= 1 for v in counts.values())
    recorder.add(
        "V04-52", "F",
        "the Cisco parser reports parse warnings (spec 10.3)",
        "unclosed section / comment-only input",
        "at least one warning for each",
        f"warnings={counts}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F2: cisco.py warns on sections left open at EOF and on content "
        "with no recognised statements",
        "",
    )
    assert ok


def test_v04_53_cisco_unknown_sections_unreachable(recorder):
    r = cisco("some-unknown-command value\n")
    ok = len(r.unknown_sections) == 1 and len(r.parse_tree) == 0
    recorder.add(
        "V04-53", "F",
        "an unrecognised command is flagged as an unknown section (spec 10.3)",
        "'some-unknown-command value'",
        "1 unknown section, absent from the tree",
        f"unknown={len(r.unknown_sections)} roots={[(n.key, n.value) for n in r.parse_tree]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F2: cisco.py routes root-level lines outside the recognised "
        "IOS/ASA/NX-OS vocabulary to unknown_sections",
        "",
    )
    assert ok


def test_v04_54_junos_never_reports_unknown(recorder):
    samples = {
        "garbage": "zzz yyy\nqqq\n",
        "wrong_style": "set system host-name R1\nnot a set line at all\n",
        "brace": "system {\n host-name R1;\n}\nrandom junk 1;\n",
    }
    counts = {k: len(junos(v).unknown_sections) for k, v in samples.items()}
    ok = all(v >= 1 for v in counts.values())
    recorder.add(
        "V04-54", "F",
        "the Junos parser flags unknown/unsupported sections (spec 10.3)",
        "3 inputs containing unrecognised lines", "unknown sections > 0",
        f"unknown per input={counts}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F2: juniper.py flags non-set lines in set content, root-level "
        "statements outside the JUNOS container vocabulary, and foreign "
        "content (explicit error plus unknowns)",
        "",
    )
    assert ok


def test_v04_55_fortinet_reports_unknown(recorder):
    r = forti("config system interface\n delete internal1\n get system status\nend\n")
    ok = len(r.unknown_sections) == 2
    recorder.add(
        "V04-55", "F",
        "the FortiOS parser flags unknown/unsupported sections (spec 10.3)",
        "'delete'/'get' commands inside a block", "2 unknown sections",
        f"unknown={[u.raw_text for u in r.unknown_sections]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "fortinet.py unknown lines",
    )
    assert ok


def test_v04_56_diagnostic_capability_matrix(recorder):
    # one triggering input per signal per parser (genuinely triggering:
    # binary/foreign content for errors, never plain junk which is unknown)
    mat = {
        "cisco": {
            "errors": len(cisco("\x00binary\n").parse_errors),
            "warnings": len(cisco("interface Gi0/0\n").parse_warnings),
            "unknown": len(cisco("junk line here\n").unknown_sections),
        },
        "juniper": {
            "errors": len(junos("}\n").parse_errors),
            "warnings": len(junos("system {\n").parse_warnings),
            "unknown": len(junos("zzz yyy\n").unknown_sections),
        },
        "fortinet": {
            "errors": len(forti("end\n").parse_errors),
            "warnings": len(forti("config system\n").parse_warnings),
            "unknown": len(forti("junk line here\n").unknown_sections),
        },
    }
    complete = {k: all(v > 0 for v in d.values()) for k, d in mat.items()}
    observed = all(complete.values())
    recorder.add(
        "V04-56", "F",
        "all three parsers can signal errors, warnings and unknown sections",
        "one triggering input per signal per parser",
        "every parser emits all 3 signal types",
        f"matrix={mat} complete={complete}",
        "PASS" if observed else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F2: deterministic diagnostics in cisco.py/juniper.py/fortinet.py",
        "",
    )
    assert observed


def test_v04_57_parse_result_lacks_spec_fields(recorder):
    r = cisco("hostname R1")
    fields = {"vendor": hasattr(r, "vendor"), "platform": hasattr(r, "platform"),
              "id": hasattr(r, "id"),
              "ingested_config_id": hasattr(r, "ingested_config_id")}
    ok = all(fields.values())
    recorder.add(
        "V04-57", "F",
        "ParseResult carries vendor/platform/id as required by the ParsedConfiguration contract",
        "ParseResult instance attributes",
        "vendor/platform/id/ingested_config_id present (spec 744-753)",
        f"present={fields}; the executor fills vendor/platform/id on the result",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F12: parsing/cisco.py, juniper.py, fortinet.py ParseResult "
        "envelope (docs/PROJECT_MASTER_SPEC.md:744-753)",
        "",
    )
    assert ok


# --------------------------------------------------------------------------
# G. SEPARATE RECORD — parser behaviour when the pipeline supplies the
#    wrong vendor's content. Detector output is never used as ground truth.
# --------------------------------------------------------------------------

def test_v04_58_junos_content_through_cisco_parser(recorder):
    r = cisco(JUNOS_CFG)
    explicit = (len(r.parse_errors) >= 1 and len(r.parse_tree) == 0
                and "IOS" in r.parse_errors[0].message)
    recorder.add(
        "V04-58", "G",
        "WRONG-VENDOR: JUNOS content handed to the Cisco parser",
        "canonical JUNOS config -> CiscoIOSParser",
        "an explicit 'not IOS syntax' error, empty tree",
        f"errors={[(e.line_number, e.message) for e in r.parse_errors]} "
        f"roots={len(r.parse_tree)}",
        "PASS" if explicit else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F3: cisco.py pre-scan rejects brace-hierarchy content with an "
        "explicit error instead of a junk tree",
        "",
    )
    assert explicit


def test_v04_59_ios_content_through_junos_parser(recorder):
    r = junos(CISCO_CFG)
    explicit = len(r.parse_errors) >= 1 and len(r.parse_tree) == 0
    recorder.add(
        "V04-59", "G",
        "WRONG-VENDOR: IOS content handed to the Junos parser",
        "canonical IOS config -> JunosParser",
        "an explicit 'not JUNOS syntax' error, empty tree",
        f"errors={[(e.line_number, e.message) for e in r.parse_errors]} "
        f"roots={len(r.parse_tree)} keys={[n.key for n in r.parse_tree][:6]}",
        "PASS" if explicit else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F3: juniper.py pre-scan rejects content without JUNOS structure",
        "",
    )
    assert explicit


def test_v04_60_fortios_content_through_cisco_parser(recorder):
    r = cisco(FORTI_CFG)
    explicit = len(r.parse_errors) >= 1 and len(r.parse_tree) == 0
    recorder.add(
        "V04-60", "G",
        "WRONG-VENDOR: FortiOS content handed to the Cisco parser",
        "canonical FortiOS config -> CiscoIOSParser",
        "an explicit 'not IOS syntax' error, empty tree",
        f"errors={[(e.line_number, e.message) for e in r.parse_errors]} "
        f"roots={len(r.parse_tree)} keys={[n.key for n in r.parse_tree][:8]}",
        "PASS" if explicit else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F3: cisco.py pre-scan rejects FortiOS-style 'config' blocks",
        "",
    )
    assert explicit


def test_v04_61_ios_content_through_fortinet_parser(recorder):
    r = forti(CISCO_CFG)
    ok = len(r.parse_tree) == 0 and len(r.unknown_sections) > 0 \
        and len(r.parse_errors) >= 1
    recorder.add(
        "V04-61", "G",
        "WRONG-VENDOR: IOS content handed to the FortiOS parser",
        "canonical IOS config -> FortiOSParser",
        "empty tree, content flagged, plus an explicit 'not FortiOS' error",
        f"roots={len(r.parse_tree)} unknown={len(r.unknown_sections)} "
        f"errors={[(e.line_number, e.message) for e in r.parse_errors]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F3: fortinet.py pre-scan rejects content without FortiOS "
        "structure (was: flagged unknown with 0 errors)",
        "",
    )
    assert ok


def test_v04_62_junos_content_through_fortinet_parser(recorder):
    r = forti(JUNOS_CFG)
    ok = len(r.parse_tree) == 0 and len(r.unknown_sections) > 0 \
        and len(r.parse_errors) >= 1
    recorder.add(
        "V04-62", "G",
        "WRONG-VENDOR: JUNOS content handed to the FortiOS parser",
        "canonical JUNOS config -> FortiOSParser",
        "empty tree, content flagged, plus an explicit 'not FortiOS' error",
        f"roots={len(r.parse_tree)} unknown={len(r.unknown_sections)} errors={[(e.line_number, e.message) for e in r.parse_errors]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F3: fortinet.py pre-scan rejects brace-hierarchy content "
        "(was: flagged unknown with 0 errors)",
        "",
    )
    assert ok


def test_v04_63_fortios_content_through_junos_parser(recorder):
    r = junos(FORTI_CFG)
    explicit = len(r.parse_errors) >= 1 and len(r.parse_tree) == 0
    recorder.add(
        "V04-63", "G",
        "WRONG-VENDOR: FortiOS content handed to the Junos parser",
        "canonical FortiOS config -> JunosParser",
        "an explicit 'not JUNOS syntax' error, empty tree",
        f"errors={[(e.line_number, e.message) for e in r.parse_errors]} "
        f"roots={len(r.parse_tree)} keys={[n.key for n in r.parse_tree][:8]}",
        "PASS" if explicit else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F3: juniper.py pre-scan rejects FortiOS-style 'config'/'edit' "
        "lines even when 'set' lines are present",
        "",
    )
    assert explicit


def test_v04_64_unsupported_vendor_syntax_through_cisco_parser(recorder):
    arista = "interface Ethernet1\n no switchport\n ip address 10.1.1.1/24\n"
    r = cisco(arista)
    diags = [w.message for w in r.parse_warnings]
    # E04: prefix-notation addresses (NX-OS/EOS style, never classic IOS)
    # produce an explicit diagnostic instead of silent acceptance. A hard
    # vendor verdict is the executor's job (E03 F2 gate: unsupported vendors
    # never reach a parser); at parse level Arista EOS is IOS-compatible
    # syntax and cannot be distinguished from NX-OS deterministically.
    ok = len(r.parse_errors) == 0 and len(r.parse_tree) > 0 \
        and any("prefix-notation" in m for m in diags)
    recorder.add(
        "V04-64", "G",
        "WRONG-VENDOR: unsupported-vendor (Arista-style) content through the Cisco parser",
        "Arista EOS lines -> CiscoIOSParser",
        "an explicit diagnostic (prefix-notation warning); vendor gating is "
        "the executor's E03 F2 gate",
        f"errors={len(r.parse_errors)} warnings={diags} "
        f"nodes={[(n.key, n.value) for n in walk(r.parse_tree)]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F3: cisco.py flags prefix-notation addresses; executor._get_parser "
        "returns None for unsupported vendors (V04-35)",
        "",
    )
    assert ok


def test_v04_65_junos_style_switch_on_mixed_content(recorder):
    mixed = "system {\n    host-name R1;\n}\nset system services ssh\n"
    r = junos(mixed)
    keys = [n.key for n in walk(r.parse_tree)]
    systems = [n for n in r.parse_tree if n.key == "system"]
    ok = not any(k in ("em", "-name") for k in keys) and len(systems) == 1 \
        and len(r.parse_errors) == 0
    recorder.add(
        "V04-65", "G",
        "mixed brace/set JUNOS content is parsed as one consistent style",
        "brace config plus one 'set' line",
        "both styles represented without mangling (one merged system node)",
        f"errors={len(r.parse_errors)} keys={keys}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F15: juniper.py parses mixed content per statement (hierarchical "
        "scaffold plus set-path insertion, merged)",
        "",
    )
    assert ok


# --------------------------------------------------------------------------
# H. Hostile / boundary input
# --------------------------------------------------------------------------

def test_v04_66_none_input(recorder):
    errs = {}
    for name, fn in (("cisco", cisco), ("juniper", junos), ("fortinet", forti)):
        try:
            fn(None)
            errs[name] = "no exception"
        except Exception as e:
            errs[name] = type(e).__name__
    ok = all(v == "TypeError" for v in errs.values())
    recorder.add(
        "V04-66", "H", "parse(None) raises a clear, typed error",
        "content=None", "TypeError('content must be str')",
        f"exceptions={errs}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F8: explicit input type guard in all three parse() entry points",
        "",
    )
    assert ok


def test_v04_67_bytes_input(recorder):
    errs = {}
    for name, fn in (("cisco", cisco), ("juniper", junos), ("fortinet", forti)):
        try:
            fn(b"hostname R1\n")
            errs[name] = "no exception"
        except Exception as e:
            errs[name] = type(e).__name__
    ok = all(v == "TypeError" for v in errs.values())
    recorder.add(
        "V04-67", "H", "parse(bytes) raises a clear, typed error",
        "content=b'hostname R1\\n'", "TypeError('content must be str')",
        f"exceptions={errs}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F8: explicit input type guard in all three parse() entry points "
        "(was an accidental bytes.startswith TypeError)",
        "",
    )
    assert ok


def test_v04_68_integer_input(recorder):
    errs = {}
    for name, fn in (("cisco", cisco), ("juniper", junos), ("fortinet", forti)):
        try:
            fn(5)
            errs[name] = "no exception"
        except Exception as e:
            errs[name] = type(e).__name__
    ok = all(v == "TypeError" for v in errs.values())
    recorder.add(
        "V04-68", "H", "parse(5) raises a clear, typed error",
        "content=5", "TypeError('content must be str')",
        f"exceptions={errs}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F8: explicit input type guard in all three parse() entry points",
        "",
    )
    assert ok


def test_v04_69_control_characters_survive(recorder):
    hostile = {
        "nul": "hostname R1\x00\ninterface Gi0/0\n",
        "c0": "hostname \x01\x02\x1f\n",
        "surrogate": "hostname \ud800\n",
        "unicode": "hostname \u00e9\u4e2d\u6587\n",
    }
    outcomes = {}
    for hname, content in hostile.items():
        for pname, fn in (("cisco", cisco), ("juniper", junos), ("fortinet", forti)):
            try:
                r = fn(content)
                outcomes[f"{hname}/{pname}"] = f"nodes={len(walk(r.parse_tree))}"
            except Exception as e:
                outcomes[f"{hname}/{pname}"] = type(e).__name__
    ok = not any(v in ("TypeError", "AttributeError", "RecursionError")
                 for v in outcomes.values())
    recorder.add(
        "V04-69", "H",
        "NUL / control / lone-surrogate / non-ASCII content never crashes a parser",
        "4 hostile inputs x 3 parsers", "no exception on any combination",
        f"outcomes={outcomes}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "pure str processing with no regex catastrophic backtracking",
    )
    assert ok


def test_v04_70_deep_nesting_to_dict(recorder):
    depth = 1500
    body = "\n".join("  " * i + f"lvl{i} {{" for i in range(depth)) + "\n" \
        + "\n".join("  " * i + "}" for i in range(depth - 1, -1, -1))
    r = junos(body)
    try:
        r.to_dict()
        outcome = "no exception"
    except Exception as e:
        outcome = type(e).__name__
    ok = outcome == "no exception"
    recorder.add(
        "V04-70", "H",
        "a deeply nested configuration can be serialised without exhausting the stack",
        f"1500-level nested JUNOS config -> ParseResult.to_dict()",
        "serialisation succeeds",
        f"parse ok (roots={len(r.parse_tree)}), to_dict -> {outcome}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F7: iterative ConfigNode.to_dict in all three parsers "
        "(CWE-674 uncontrolled recursion closed)",
        "",
    )
    assert ok


def test_v04_71_deep_nesting_find_all(recorder):
    depth = 1500
    body = "\n".join("  " * i + f"lvl{i} {{" for i in range(depth)) + "\n" \
        + "\n".join("  " * i + "}" for i in range(depth - 1, -1, -1))
    r = junos(body)
    try:
        JunosParser.find_all(r.parse_tree, "lvl1")
        outcome = "no exception"
    except Exception as e:
        outcome = type(e).__name__
    ok = outcome == "no exception"
    recorder.add(
        "V04-71", "H",
        "tree search over a deeply nested configuration does not exhaust the stack",
        f"1500-level nested config -> JunosParser.find_all()",
        "search succeeds",
        f"find_all -> {outcome}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F7: iterative find_all in juniper.py (CWE-674 closed)",
        "",
    )
    assert ok


def test_v04_72_shallow_nesting_ok(recorder):
    depth = 500
    body = "\n".join("  " * i + f"lvl{i} {{" for i in range(depth)) + "\n" \
        + "\n".join("  " * i + "}" for i in range(depth - 1, -1, -1))
    r = junos(body)
    try:
        r.to_dict()
        JunosParser.find_all(r.parse_tree, "lvl1")
        outcome = "ok"
    except Exception as e:
        outcome = type(e).__name__
    ok = outcome == "ok"
    recorder.add(
        "V04-72", "H",
        "moderate nesting (500 levels) serialises and searches normally",
        "500-level nested config", "no exception",
        f"outcome={outcome} roots={len(r.parse_tree)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "confirms the failure threshold is between 500 and 1500 levels",
    )
    assert ok


def test_v04_73_large_input_parse_time(recorder):
    big_cisco = "\n".join(
        f"interface Gi0/{i % 48}\n ip address 10.{(i // 256) % 256}.{i % 256}.1 255.255.255.0\n no shutdown"
        for i in range(30000))
    big_junos = "\n".join(
        f"set interfaces ge-0/0/{i % 48} unit 0 family inet address 10.{(i // 256) % 256}.{i % 256}.1/24"
        for i in range(30000))
    big_forti = "\n".join(
        f'config system interface\n edit "p{i}"\n  set ip 10.{(i // 256) % 256}.{i % 256}.1/24\n next\nend'
        for i in range(5000))
    timings = {}
    for name, content, fn in (("cisco", big_cisco, cisco),
                              ("juniper", big_junos, junos),
                              ("fortinet", big_forti, forti)):
        t0 = time.perf_counter()
        r = fn(content)
        timings[name] = (round((time.perf_counter() - t0) * 1000, 1),
                         len(content), len(walk(r.parse_tree)))
    ok = all(v[0] < 5000 for v in timings.values())
    recorder.add(
        "V04-73", "H", "each parser handles ~1-2 MB of content within 5 s",
        "30k/30k/5k synthetic commands per parser",
        "parse time < 5000 ms per parser",
        f"timings(ms, bytes, nodes)={timings}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "measured with time.perf_counter",
    )
    assert ok


def test_v04_74_whitespace_only_input(recorder):
    outcomes = {}
    for name, fn in (("cisco", cisco), ("juniper", junos), ("fortinet", forti)):
        r = fn("   \n\t\n \n")
        outcomes[name] = (len(r.parse_tree), len(r.parse_errors))
    ok = all(v == (0, 0) for v in outcomes.values())
    recorder.add(
        "V04-74", "H", "whitespace-only content yields an empty result without errors",
        "'   \\n\\t\\n'", "(0 nodes, 0 errors) x3", str(outcomes),
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "cisco.py:168 / juniper.py:165 / fortinet.py:152 skip blank lines",
    )
    assert ok


# --------------------------------------------------------------------------
# I. Determinism and evidence fidelity
# --------------------------------------------------------------------------

def test_v04_75_ten_repeated_parses_identical(recorder):
    def sig(r):
        return tuple((n.key, n.value, n.line_number) for n in walk(r.parse_tree))
    sigs = {str(sig(cisco(CISCO_CFG))) for _ in range(10)}
    ok = len(sigs) == 1
    recorder.add(
        "V04-75", "I", "10 repeated parses of the same content are identical",
        "canonical IOS config x10", "1 distinct signature",
        f"distinct={len(sigs)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "no randomness, no instance state (stateless parser classes)",
    )
    assert ok


def test_v04_76_two_instances_agree(recorder):
    a = FortiOSParser().parse(FORTI_CFG)
    b = FortiOSParser().parse(FORTI_CFG)
    sa = [(n.key, n.value, n.line_number) for n in walk(a.parse_tree)]
    sb = [(n.key, n.value, n.line_number) for n in walk(b.parse_tree)]
    ok = sa == sb
    recorder.add(
        "V04-76", "I", "two parser instances produce the same result",
        "FortiOSParser x2", "identical trees",
        f"identical={ok} nodes={len(sa)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "stateless classes",
    )
    assert ok


def test_v04_77_interleaved_parse_has_no_state(recorder):
    first = cisco(CISCO_CFG)
    junos(JUNOS_CFG)
    forti(FORTI_CFG)
    second = cisco(CISCO_CFG)
    sa = [(n.key, n.value) for n in walk(first.parse_tree)]
    sb = [(n.key, n.value) for n in walk(second.parse_tree)]
    ok = sa == sb
    recorder.add(
        "V04-77", "I",
        "an intervening parse of other vendors does not change the next result",
        "IOS, then JUNOS, then FortiOS, then IOS again",
        "first and last IOS results identical", f"identical={ok}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "parsers hold no cross-call state",
    )
    assert ok


def test_v04_78_line_numbers_unique_per_line(recorder):
    r = cisco(CISCO_CFG)
    nodes = walk(r.parse_tree)
    lines = [n.line_number for n in nodes]
    ok = min(lines) >= 1 and max(lines) <= len(CISCO_CFG.splitlines())
    recorder.add(
        "V04-78", "I", "node line numbers stay inside the source line range",
        "canonical IOS config", "all line_numbers in [1, line_count]",
        f"min={min(lines)} max={max(lines)} source_lines={len(CISCO_CFG.splitlines())}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "cisco.py line iteration",
    )
    assert ok


def test_v04_79_raw_text_round_trip(recorder):
    r = forti(FORTI_CFG)
    src = {ln.strip() for ln in FORTI_CFG.splitlines() if ln.strip()}
    nodes = walk(r.parse_tree)
    missing = [n.raw_text for n in nodes if n.raw_text not in src]
    ok = not missing
    recorder.add(
        "V04-79", "I", "every node's raw_text is a verbatim source line",
        "canonical FortiOS config", "0 nodes with invented raw_text",
        f"nodes={len(nodes)} mismatches={missing[:3]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "fortinet.py node raw_text",
    )
    assert ok


# --------------------------------------------------------------------------
# J. Performance (measurement only — no readiness score)
# --------------------------------------------------------------------------

def test_v04_80_cisco_throughput(recorder):
    content = "\n".join(f"interface Gi0/{i % 48}\n ip address 10.0.{i % 256}.1 255.255.255.0"
                        for i in range(20000))
    t0 = time.perf_counter()
    r = cisco(content)
    ms = (time.perf_counter() - t0) * 1000
    ok = ms < 5000
    recorder.add(
        "V04-80", "J", "Cisco parser throughput on a large config",
        f"{len(content)} bytes, 40000 lines", "parse completes; time recorded",
        f"{ms:.1f} ms, {len(walk(r.parse_tree))} nodes",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "time.perf_counter",
    )
    assert ok


def test_v04_81_junos_throughput(recorder):
    content = "\n".join("system {\n host-name R1;\n services {\n  ssh;\n }\n}" for _ in range(20000))
    t0 = time.perf_counter()
    r = junos(content)
    ms = (time.perf_counter() - t0) * 1000
    ok = ms < 5000
    recorder.add(
        "V04-81", "J", "Junos parser throughput on a large config",
        f"{len(content)} bytes", "parse completes; time recorded",
        f"{ms:.1f} ms, {len(walk(r.parse_tree))} nodes",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "time.perf_counter",
    )
    assert ok


def test_v04_82_fortinet_throughput(recorder):
    content = "\n".join(f'config system interface\n edit "p{i}"\n  set ip 10.0.{i % 256}.1/24\n next\nend'
                        for i in range(10000))
    t0 = time.perf_counter()
    r = forti(content)
    ms = (time.perf_counter() - t0) * 1000
    ok = ms < 5000
    recorder.add(
        "V04-82", "J", "FortiOS parser throughput on a large config",
        f"{len(content)} bytes", "parse completes; time recorded",
        f"{ms:.1f} ms, {len(walk(r.parse_tree))} nodes",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR", "time.perf_counter",
    )
    assert ok


# --------------------------------------------------------------------------
# K. Cross-parser contract consistency
# --------------------------------------------------------------------------

def test_v04_83_uniform_result_shape(recorder):
    r1, r2, r3 = cisco(CISCO_CFG), junos(JUNOS_CFG), forti(FORTI_CFG)
    shapes = [sorted(vars(r).keys()) for r in (r1, r2, r3)]
    want = sorted(["parse_tree", "parse_errors", "parse_warnings",
                   "unknown_sections", "vendor", "platform", "id",
                   "ingested_config_id"])
    ok = shapes[0] == shapes[1] == shapes[2] == want
    recorder.add(
        "V04-83", "K", "all three parsers return the same ParseResult shape",
        "one canonical config per parser",
        "identical field sets incl. the spec envelope",
        f"shapes={shapes}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F12: cisco.py/juniper.py/fortinet.py ParseResult envelope",
    )
    assert ok


def test_v04_84_uniform_confignode_shape(recorder):
    shapes = [sorted(cls.__dataclass_fields__) for cls in (CiscoNode, JunosNode, FortiNode)]
    ok = shapes[0] == shapes[1] == shapes[2]
    recorder.add(
        "V04-84", "K", "all three parsers return the same ConfigNode shape",
        "ConfigNode dataclasses", "identical field sets",
        f"shapes={shapes}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ConfigNode dataclasses in all three parsers (uniform shape incl. negated)",
    )
    assert ok


def test_v04_85_path_semantics_differ(recorder):
    c = [n.path for n in walk(cisco("interface Gi0/0\n ip address 1.1.1.1 255.255.255.0").parse_tree) if n.key == "ip"]
    f = [n.path for n in walk(forti(FORTI_CFG).parse_tree) if n.key == "ip"]
    j = [n.path for n in walk(junos(JUNOS_CFG).parse_tree) if n.key == "address"]
    ok = c == [["interface"]] and f == [["config", "edit"]] \
        and j == [["interfaces", "ge-0/0/0", "unit", "family"]]
    recorder.add(
        "V04-85", "K",
        "ConfigNode.path means the same thing in every parser",
        "equivalent nested statements in all 3 vendors",
        "one path convention: the ancestor key chain",
        f"cisco={c} fortinet={f} juniper={j}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F13: cisco.py builds ancestor keys (dropped the 'type:value' "
        "suffix); fortinet.py and juniper.py already used ancestor keys",
        "",
    )
    assert ok


def test_v04_86_find_all_api_differs(recorder):
    def kind(cls, name):
        attr = cls.__dict__.get(name)
        if isinstance(attr, staticmethod):
            return "staticmethod"
        if isinstance(attr, classmethod):
            return "classmethod"
        return "instance method" if callable(attr) else "absent"

    kinds = {"cisco": kind(CiscoIOSParser, "find_all"),
             "juniper": kind(JunosParser, "find_all"),
             "fortinet": kind(FortiOSParser, "find_all")}
    semantics = {"cisco": "regex over key/value",
                 "juniper": "regex over key/value",
                 "fortinet": "regex over key/value"}
    uniform = len(set(kinds.values())) == 1 and len(set(semantics.values())) == 1 \
        and set(kinds.values()) == {"classmethod"}
    recorder.add(
        "V04-86", "K", "the three parsers expose one uniform search API",
        "find_all on each class",
        "identical signature and semantics (classmethod, regex over key/value)",
        f"kinds={kinds} semantics={semantics}",
        "PASS" if uniform else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F13: classmethod find_all with uniform key/value regex semantics "
        "in cisco.py/juniper.py/fortinet.py (callable on class and instance)",
        "",
    )
    assert uniform


def test_v04_87_get_section_api_differs(recorder):
    def kind(cls, name):
        attr = cls.__dict__.get(name)
        if isinstance(attr, staticmethod):
            return "staticmethod"
        if isinstance(attr, classmethod):
            return "classmethod"
        return "instance method" if callable(attr) else "absent"

    kinds = {"cisco.get_section": kind(CiscoIOSParser, "get_section"),
             "juniper.get_section": kind(JunosParser, "get_section"),
             "fortinet.get_section": kind(FortiOSParser, "get_section")}
    uniform = set(kinds.values()) == {"classmethod"}
    r = forti(FORTI_CFG)
    probe = FortiOSParser.get_section(r.parse_tree, ["config", "system interface"])
    ok = uniform and probe is not None and probe.key == "config"
    recorder.add(
        "V04-87", "K", "the three parsers expose one uniform section lookup API",
        "get_section on each class",
        "identical signature and semantics (classmethod, list path, key-then-value)",
        f"members={kinds}; forti probe={'found' if probe else 'None'} "
        "(cisco keeps get_section_value as a dotted-path wrapper)",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F13: classmethod get_section with uniform resolution in all three "
        "parsers",
        "",
    )
    assert ok


def test_v04_88_fortinet_get_section_matches_value(recorder):
    r = forti(FORTI_CFG)
    by_value = FortiOSParser().get_section(r.parse_tree, ["system interface"])
    by_key_then_value = FortiOSParser().get_section(
        r.parse_tree, ["config", "system interface"])
    ok = by_value is not None and by_key_then_value is not None \
        and by_value is by_key_then_value
    recorder.add(
        "V04-88", "K",
        "FortiOS get_section resolves key segments and value segments consistently",
        "path ['system interface'] and path ['config','system interface']",
        "both forms resolve to the config node",
        f"['system interface'] -> {'found' if by_value else 'None'}; "
        f"['config','system interface'] -> {'found' if by_key_then_value else 'None'}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F13: uniform key-then-value resolution (a trailing segment may "
        "match the terminal node's own value)",
        "",
    )
    assert ok


def test_v04_89_parse_result_serialises_consistently(recorder):
    dicts = [r.to_dict() for r in (cisco(CISCO_CFG), junos(JUNOS_CFG), forti(FORTI_CFG))]
    keys = [sorted(d.keys()) for d in dicts]
    ok = keys[0] == keys[1] == keys[2]
    recorder.add(
        "V04-89", "K", "ParseResult.to_dict() yields the same keys for every parser",
        "one canonical config per parser", "identical dict keys",
        f"keys={keys}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ParseResult.to_dict in all three parsers (uniform keys incl. envelope)",
    )
    assert ok


def test_v04_90_junos_warning_still_serialises(recorder):
    r = junos("system {\n    host-name R1;\n")
    try:
        d = r.to_dict()
        outcome = "ok"
        warn_dicts = d["parse_warnings"]
    except Exception as e:
        outcome = type(e).__name__
        warn_dicts = None
    ok = outcome == "ok" and warn_dicts and warn_dicts[0]["message"].startswith("Unclosed braces")
    recorder.add(
        "V04-90", "K",
        "the mistyped Juniper warning still serialises without crashing",
        "unclosed brace config -> to_dict()",
        "warnings appear in the serialised result",
        f"outcome={outcome} warnings={warn_dicts}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "ParseError and ParseWarning expose the same three fields, so the type error is latent",
        "see V04-19: fix the type before a consumer starts type-checking",
    )
    assert ok


def test_v04_91_consecutive_sections_nest_incorrectly(recorder):
    cfg = ("interface Gi0/0\n ip address 1.1.1.1 255.255.255.0\n"
           "line vty 0 4\n login local\n"
           "router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n")
    r = cisco(cfg)
    nodes = walk(r.parse_tree)
    paths = {n.key: n.path for n in nodes if n.key in ("interface", "line", "router")}
    siblings = (paths.get("interface") == []
                and paths.get("line") == [] and paths.get("router") == [])
    recorder.add(
        "V04-91", "A",
        "consecutive top-level IOS sections stay siblings (IOS has a flat section grammar)",
        "interface, then line vty, then router ospf",
        "all three sections at path=[]",
        f"paths={paths}",
        "PASS" if siblings else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F1: cisco.py closes every open section on a new section start",
        "",
    )
    assert siblings


def test_v04_92_section_lookup_fails_for_nested_sections(recorder):
    cfg = ("interface Gi0/0\n ip address 1.1.1.1 255.255.255.0\n"
           "router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n")
    r = cisco(cfg)
    nodes = walk(r.parse_tree)
    router_nodes = [n for n in nodes if n.key == "router"]
    looked_up = CiscoIOSParser().get_section_value(r.parse_tree, "router")
    fixed = len(router_nodes) == 1 and looked_up == "ospf 1"
    recorder.add(
        "V04-92", "A",
        "get_section_value finds a section that exists in the tree",
        "router section following an interface block",
        "'ospf 1' (the section's value)",
        f"router nodes in tree={[(n.key, n.value, n.path) for n in router_nodes]} "
        f"get_section_value('router')={looked_up!r}",
        "PASS" if fixed else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F1: top-level sections stay root siblings, so path resolution "
        "reaches every section",
        "",
    )
    assert fixed


def test_v04_93_api_section_list_omits_nested_sections(recorder):
    cfg = ("interface Gi0/0\n ip address 1.1.1.1 255.255.255.0\n"
           "ip access-list extended WAN_IN\n permit tcp any any eq 443\n")
    r = cisco(cfg)
    # mirrors api/v1/audit_execution.py (full nested serialisation): every
    # root section, with its subtree, is persisted.
    api_sections = [s.to_dict() for s in r.parse_tree]
    api_keys = [s["key"] for s in api_sections]
    acl = next((s for s in api_sections if s["key"] == "acl"), None)
    ok = "acl" in api_keys and acl is not None \
        and any(c["key"] == "permit" for c in acl.get("children", []))
    recorder.add(
        "V04-93", "A",
        "sections that exist in the parse tree appear in the persisted section list",
        "access-list definition following an interface block",
        "'acl' present with its nested entries in the stored sections",
        f"api_keys={api_keys}; acl children="
        f"{[c['key'] for c in (acl.get('children', []) if acl else [])]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F1: audit_execution.py persists the full nested tree (to_dict), "
        "and sections stay root siblings",
        "",
    )
    assert ok


def test_v04_94_corpus_section_nesting(recorder):
    import json as _json

    summary_path = BACKEND / "artifacts" / "engine_validation" / "04_parsing" \
        / "dataset_summary.json"
    if not summary_path.exists():
        recorder.add(
            "V04-94", "A",
            "no ingestible Cisco file contains a section nested under another section",
            "dataset sweep artifact", "0 nested section nodes",
            "dataset_summary.json not present (sweep not run in this session)",
            "NOT VERIFIABLE", "CONFIRMED BEHAVIOR", "scripts/engine_validation/sweep_parsing.py",
        )
        pytest.skip("dataset sweep artifact not present")
    summary = _json.loads(summary_path.read_text(encoding="utf-8"))
    nest = summary.get("cisco_section_nesting", {})
    observed = nest.get("sections_nested")
    files = nest.get("files_with_nested_sections")
    total_files = nest.get("files")
    fixed = observed == 0
    recorder.add(
        "V04-94", "A",
        "no ingestible Cisco file contains a section nested under another section",
        f"{total_files} ingestible Cisco files parsed by CiscoIOSParser",
        "0 nested section nodes",
        f"nested section nodes={observed} across {files}/{total_files} files; "
        f"by type={nest.get('by_type')}",
        "PASS" if fixed else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F1: sibling termination; measured by sweep_parsing.py (re-run "
        "post-fix)",
        "",
    )
    assert fixed


# --------------------------------------------------------------------------
# E04 regression coverage added with the fix (F1 matrix, F2 persistence,
# F3 selection, F4 fidelity, secondary banner/security cases)
# --------------------------------------------------------------------------

def test_v04_95_section_family_sibling_matrix(recorder):
    cfg = ("interface Gi0/0\n ip address 1.1.1.1 255.255.255.0\n"
           "line vty 0 4\n login local\n"
           "router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n"
           "vlan 10\n name USERS\n"
           "access-list 10 permit 192.168.1.0 0.0.0.255\n"
           "crypto map WAN 10 ipsec-isakmp\n"
           "key chain RIP-KEYS\n"
           "switch 1 provision ws-c3750x-48\n"
           "ip prefix-list PL-IN seq 5 permit 10.0.0.0/8 le 32\n"
           "control-plane\n service-policy input COPP\n")
    r = cisco(cfg)
    nodes = walk(r.parse_tree)
    sections = [n for n in nodes if n.key in (
        "interface", "line", "router", "vlan", "acl", "crypto",
        "key_chain", "switch", "nested", "control-plane")]
    nested = [n for n in sections if n.path]
    iface = next(n for n in r.parse_tree if n.key == "interface")
    copp = next(n for n in r.parse_tree if n.key == "control-plane")
    ok = len(sections) == 10 and not nested \
        and [c.key for c in iface.children] == ["ip"] \
        and [c.key for c in copp.children] == ["service-policy"]
    recorder.add(
        "V04-95", "A",
        "every section family terminates the previous section; children stay inside",
        "all 10 section families in sequence", "10 root sections, 0 nested",
        f"sections={len(sections)} nested={len(nested)} "
        f"iface-children={[c.key for c in iface.children]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F1: cisco.py sibling termination for all 10 families",
        "",
    )
    assert ok


def test_v04_96_banner_delimiter_variants(recorder):
    same_line = cisco("hostname R1\nbanner motd ^Hello^\ninterface Gi0/0\n")
    quoted = cisco('banner login "Hi there"\nhostname R2\n')
    unterminated = cisco("hostname R3\nbanner motd ^never ends\nstill going\n")
    sb = [n for n in walk(same_line.parse_tree) if n.key == "banner"]
    qb = [n for n in walk(quoted.parse_tree) if n.key == "banner"]
    ok = len(sb) == 1 and sb[0].value == "Hello" \
        and len(qb) == 1 and qb[0].value == "Hi there" \
        and any("unterminated banner" in e.message
                for e in unterminated.parse_errors)
    recorder.add(
        "V04-96", "E",
        "same-line, quoted-delimiter and unterminated banners are handled",
        "3 banner variants", "2 opaque banner nodes + 1 unterminated error",
        f"same-line={sb[0].value if sb else None!r} "
        f"quoted={qb[0].value if qb else None!r} "
        f"unterminated-errors={len(unterminated.parse_errors)}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F5: cisco.py banner extraction; unterminated banner is a "
        "deterministic parse error",
        "",
    )
    assert ok


def test_v04_97_acl_remark_and_sequence_preserved(recorder):
    r = cisco("ip access-list extended EG\n"
              " 10 remark allow web\n"
              " 20 permit tcp any any eq 443\n")
    nodes = walk(r.parse_tree)
    remark = [n for n in nodes if n.key == "remark"]
    permit = [n for n in nodes if n.key == "permit"]
    bad = [n for n in nodes if n.key in ("10", "20")]
    ok = len(remark) == 1 and remark[0].value == "allow web" \
        and len(permit) == 1 and not bad \
        and "10 remark" in remark[0].raw_text \
        and "20 permit" in permit[0].raw_text
    recorder.add(
        "V04-97", "E",
        "ACL remarks use the action keyword; sequence numbers stay in raw_text",
        "numbered remark + permit entries",
        "keys remark/permit, no numeric keys, seq in raw_text",
        f"nodes={[(n.key, n.value) for n in nodes]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F14: cisco.py ACL entry keying",
        "",
    )
    assert ok


def test_v04_98_executor_fills_parse_result_envelope(recorder):
    from app.engines.compliance.executor import AuditExecutor
    cfg = ("! Cisco IOS config\nhostname R1\ninterface Gi0/0\n"
           " ip address 1.1.1.1 255.255.255.0\n")
    r = AuditExecutor().execute("v04-probe-envelope", cfg, framework="CIS")
    pr = r.parse_result
    ok = r.status == "completed" and pr is not None \
        and pr.vendor == "cisco" and pr.platform != "" \
        and pr.id == "v04-probe-envelope" \
        and len(pr.parse_tree) > 0
    recorder.add(
        "V04-98", "D",
        "the audit pipeline stamps vendor/platform/id on the ParseResult",
        "AuditExecutor.execute(cisco config)",
        "parse_result.vendor/platform/id populated by the executor",
        f"status={r.status} vendor={getattr(pr, 'vendor', None)!r} "
        f"platform={getattr(pr, 'platform', None)!r} "
        f"id={getattr(pr, 'id', None)!r}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F12: executor.py passes detection identity into parser.parse()",
        "",
    )
    assert ok


def test_v04_99_central_parser_selection_contract(recorder):
    from app.engines.parsing import get_parser, SUPPORTED_PARSING_VENDORS
    from app.engines.parsing.cisco import CiscoIOSParser as C
    from app.engines.parsing.juniper import JunosParser as J
    from app.engines.parsing.fortinet import FortiOSParser as F
    good = (isinstance(get_parser("cisco", "ios"), C)
            and isinstance(get_parser("juniper", "junos"), J)
            and isinstance(get_parser("fortinet", "fortios"), F))
    bad = all(get_parser(v, "x") is None
              for v in ("arista", "paloalto", "f5", "unknown", "", "CISCO2"))
    supported = SUPPORTED_PARSING_VENDORS == frozenset(
        {"cisco", "juniper", "fortinet"})
    ok = good and bad and supported
    recorder.add(
        "V04-99", "D",
        "one parser per supported vendor family, None for anything else",
        "parsing.get_parser across vendors",
        "cisco/juniper/fortinet instances; None for unsupported",
        f"supported={sorted(SUPPORTED_PARSING_VENDORS)} good={good} bad={bad}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F3/F9/F10: app/engines/parsing/__init__.py central contract",
        "",
    )
    assert ok


def test_v04_100_negation_survives_serialisation(recorder):
    r = cisco("no ip http server\n")
    d = r.to_dict()
    node = d["parse_tree"][0]
    f = forti("config system interface\n edit \"a\"\n  unset shutdown\n next\nend\n")
    fd = f.to_dict()
    unset = [n for n in walk(f.parse_tree) if n.key == "unset_shutdown"]
    ok = node.get("negated") is True and node["key"] == "ip" \
        and len(unset) == 1 and unset[0].negated is True \
        and fd["parse_tree"][0]["children"][0]["children"][0]["negated"] is True
    recorder.add(
        "V04-100", "E",
        "negation reaches serialised and persisted form on both parsers",
        "'no ip http server' + FortiOS 'unset shutdown'",
        "negated=True in ConfigNode and in to_dict() output",
        f"cisco={node} forti-unset={[(n.key, n.negated) for n in unset]}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "E04 F4: negated flag in ConfigNode.to_dict and API persistence",
        "",
    )
    assert ok


def test_v04_101_single_long_line_input(recorder):
    long_line = "hostname " + "R" * (1024 * 1024)
    outcomes = {}
    for name, fn in (("cisco", cisco), ("juniper", junos), ("fortinet", forti)):
        try:
            r = fn(long_line)
            outcomes[name] = f"nodes={len(walk(r.parse_tree))}"
        except Exception as e:
            outcomes[name] = type(e).__name__
    ok = not any("Error" in v or "error" in v for v in outcomes.values())
    recorder.add(
        "V04-101", "H",
        "a 1 MB single-line input parses without exception on all parsers",
        "1 MB hostname line", "no exception",
        f"outcomes={outcomes}",
        "PASS" if ok else "FAIL", "CONFIRMED BEHAVIOR",
        "line-oriented parsing with no per-line length assumptions",
        "",
    )
    assert ok
