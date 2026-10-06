# Normalization Engine — Complete Scheme

> Source: `backend/app/engines/normalization.py` (2204 lines)
> Spec: §10.5 (engine contract), §12.1 (`NormalizedConfiguration` / `NormalizedValue`), §§21/22/25/43/47 (confidence, parse tree, platform identity, registry validation, evidence preference)
> Companion model: `backend/app/engines/universal_model.py` (`UniversalSecurityModel`)

One line: vendor-specific config **translate** karta hai Universal Security Model me — **invent** kuch nahi karta.

---

## 1. Pipeline position

```text
E04 parse (raw_lines / sections[]) ──┐
                                     ├─► normalize() ──► universal_config + mappings[] + unmapped_concepts[]
E02 vendor/platform ─────────────────┘         │
E06 knowledge base (optional) ─────────────────┘         ▼
                                              E07 compliance evaluation
```

---

## 2. Data contracts (verbatim)

```python
# Type of a mapper function: evidence -> (value, syntax, source, conf-class)
_MapperOut = Optional[tuple[Any, str, list[str], str]]

@dataclass
class _Evidence:          # one classified statement (internal)
    text: str             # cleaned statement (comment stripped)
    raw: str              # original source line (vendor syntax preserved)
    line: int             # 1-based source line number
    negated: bool         # real negation (no/unset/deactivate or E04 flag)
    section: tuple = ()   # enclosing section labels (best effort)

@dataclass
class _Ctx:                # per-normalize mapper context (internal)
    ev: list[_Evidence]
    vendor: str
    platform: str

@dataclass
class NormalizationMapping:      # spec §12.1 NormalizedValue
    model_path: str
    value: Any
    confidence: float
    source_path: list[str] = ...  # e.g. ["line:33"], ["line:5", "kb:<id>"]
    vendor_specific_syntax: str = ""

@dataclass
class NormalizationResult:       # spec §12.1 NormalizedConfiguration
    vendor: str
    platform: str
    universal_config: dict       # nested model tree, e.g. {"device": {"hostname": "S1"}}
    mappings: list[NormalizationMapping]
    unmapped_paths: list[str]    # mapper errors (recoverable)
    result_type: NormalizationResultType   # SUCCESS | PARTIAL | FAILED
    id: str = ""                                   # deterministic sha256, see §7
    semantic_interpretation_id: Optional[str] = None
    universal_model_version: str = ""
    unmapped_concepts: list[str] = ...     # model leaves nobody mapped (honest gap)
    normalized_values: list[dict] = ...    # mappings in contract shape (stored)

class NormalizationResultType(str, Enum):
    SUCCESS = "success"   # valid payload, no errors (mappings may be 0!)
    PARTIAL = "partial"   # completed with recoverable mapper issues
    FAILED  = "failed"    # unsupported vendor/platform or invalid payload
```

---

## 3. `normalize()` — the 7 stages (verbatim logic)

```python
def normalize(self, config, vendor, platform,
              semantic_interpretation=None, knowledge_base=None):
    # 1. CANONICALIZE (§25)
    canon_vendor = vendor.strip().lower()
    canon_platform = CANONICAL_PLATFORM.get((canon_vendor, platform.lower()),
                                            platform.lower())
    #   ("cisco","ios")->"ios_xe", ("juniper","junos")->"junos",
    #   ("fortinet","fortios")->"fortios"

    result_id = sha256(vendor + "\x00" + platform + "\x00"
                       + "\n".join(raw_lines))[:32]

    # 2. GATE: unknown vendor/platform map  -> FAILED
    #         non-dict config / non-list raw_lines / non-str line -> FAILED

    # 3. EVIDENCE (§47: E04 sections preferred, else raw_lines per vendor)
    evidence = _build_evidence(raw_lines, vendor, sections=...)

    # 4. FOREIGN CHECK: structurally foreign content -> FAILED (never fake success)

    # 5. MAPPERS: for universal_path, mapper_func in mapper.items():
    #       produced = mapper_func(ctx)            # None = absent, never a value
    #       value, syntax, source, conf_class = produced
    #       checked = _check_value(path, value)    # wrong type -> dropped, never coerced
    #       confidence = CONFIDENCE_POLICY[conf_class]
    #       _set_nested_value(universal_config, path, checked)
    #       mappings.append(NormalizationMapping(...))
    #     (mapper exception -> unmapped_paths, continue)

    # 6. KB BACKFILL (E06): only for paths deterministic mappers left
    #    unmapped; only confirmed + trusted + type-coercible hits.

    # 7. TYPE the result: unmapped_paths non-empty -> PARTIAL else SUCCESS.
    #    unmapped_concepts = model leaves - produced paths (always reported).
```

---

## 4. Confidence policy (§21 — fixed numbers)

| Class | Score | Meaning |
|---|---|---|
| `DIRECT_EXACT` | **0.95** | verbatim statement value |
| `DIRECT_NEGATED` | **0.95** | real negated statement |
| `STRUCTURED_EXTRACTION` | **0.85** | parsed/converted/section-scoped value |
| `DERIVED` | **0.75** | computed across statements (`secure_only`, implicit-deny, closed-world) |

Unknown confidence class defaults to `STRUCTURED_EXTRACTION`.

---

## 5. Fidelity rules (hard invariants)

- **F1:** only real statements produce values. Comments (vendor-aware: `!`, `#`, `##`-rule for JunOS), blanks, banner payloads never do.
- **Absence = `None`, never a fabricated value.** Model defaults live in the model, never in output. (One documented exception: `access_control.rules_count` emits `0` — a truthful measurement, not a default.)
- **Real negation honored** (`no …`, `unset …`, `deactivate …`, `inactive:`); commented-out negation is a comment.
- **F13 (`_check_value`):** output validated against the model concept (`boolean`/`integer`/`string`/`list`/`enum`/`object`); wrong type dropped. Only documented coercion: numeric strings → int.
- **F16 (`_sanitize`):** NUL/C0/surrogates stripped from string values (deletion only, never remapped).
- **F11 (JunOS):** token-boundary matching everywhere (`host` never matches `host-name`).

---

## 6. Evidence layer (per vendor)

| Vendor | Skipped | Sections | Negation |
|---|---|---|---|
| **cisco** | `!` comments, blanks, banner bodies (delimiter rule shared with E04) | flat IOS grammar: `interface/line/router/vlan/acl/crypto/key chain/control-plane/prefix-list…` open sections; `end` closes | leading `no ` |
| **juniper** | `#` comments (`##` = show-config content, kept) | `{`/`}` brace tracking (structure only) | `deactivate …`, `inactive:` |
| **fortinet** | `#` comments | `config …` / `edit …` stack, `end`/`next` unwind | `unset …` |

E04 parse-tree sections preferred when provided (`_evidence_from_sections`, recursive `visit()`; `banner` nodes and empty text skipped; FortiOS `unset_*` keys converted).

**Foreign check (`_is_foreign`):** cisco + braces/`config`/`edit` lines → foreign; juniper requires a JunOS marker (`{`, `set `, `;`) else foreign; fortinet requires `config`/`edit`/`end`/`next` else foreign. Foreign = `FAILED`.

---

## 7. Deterministic IDs and value helpers

```python
_result_id(vendor, platform, config)  # sha256(...)[:32] — stable across runs
_set_nested_value(d, "a.b.c", v)     # builds nested universal_config tree
_seq_at(tokens, seq)                 # multi-word key index (F7), else None
_to_int(token)                       # int or None (never raises)
_hit(evidence, value, conf)          # (value, raw, ["line:N", "section:…"], conf)
```

---

## 8. KB interplay (E06 F1 — backfill only, never override)

For each evidence statement (first-seen order): exact canonical `lookup(vendor, platform-canonical-then-raw, text, require_confirmed=True)`. A hit is consumed **only if** confirmed + trusted + names a valid model path + path still unmapped + meaning type-checks. Source recorded as `["line:N", "kb:<id>"]` with the **KB's own confidence**. KB failure never fails normalization.

---

## 9. Mapper registry — complete (`_initialize_mappers`, validated at init by `_validate_mapper_registry` against `UniversalSecurityModel`; drift = `ValueError` at startup, never at scoring)

`lambda ctx: None` = explicitly unmapped concept (documented gap, shows up in `unmapped_concepts`).

### cisco → ios / ios_xe (same table, ~70 paths)

| Universal path | Extractor |
|---|---|
| device.hostname | `_cisco_hostname` (`^hostname (\S+)`) |
| device.vendor / device.platform | `_caller_identity` (DERIVED from caller) |
| device.firmware_version | `_cisco_firmware` (`^version`) |
| device.time_zone | `_cisco_time_zone` (`clock timezone`) |
| management.http.enabled | `_cisco_http_enabled` (exact `ip http server` ± negation) |
| management.http.port | `_cisco_http_port` |
| management.http.secure_only | `_cisco_secure_only` (DERIVED: https-only ⇒ True) |
| management.https.enabled | `_cisco_https_enabled` (`ip http secure-server`) |
| management.https.port / .certificate_valid | None (explicit gap) |
| management.ssh.enabled | `_cisco_ssh_enabled` (`line vty` presence) |
| management.ssh.version | `_cisco_ssh_version` (`ip ssh version [12]`) |
| management.ssh.port | None (gap) |
| management.ssh.timeout | `_cisco_exec_timeout` (min/sec → seconds) |
| management.ssh.auth_retries / .max_retries | `_cisco_ssh_auth_retries` |
| management.ssh.source_interface | `_cisco_ssh_source_interface` |
| management.ssh.strict_host_key_check | `_cisco_strict_host_key` |
| management.ssh.root_login | None (gap — JunOS-only concept) |
| management.ssh.session_timeout | `_cisco_ssh_session_timeout` (`ip ssh time-out`) |
| management.ssh.key_size | `_cisco_ssh_key_size` (`crypto key generate rsa modulus`) |
| management.telnet.enabled | `_cisco_telnet_enabled` (vty `transport input` contains telnet; fully-specified-without-telnet ⇒ False DERIVED) |
| management.vty.transport | `_cisco_vty_transport` (ssh/telnet/none/unknown composition) |
| management.vty.exec_timeouts / .conflicts | `_cisco_exec_timeouts` / `_cisco_conflicts` (per-block structures) |
| config.conflicts | `_cisco_conflicts` (same) |
| management.vty.console_timeout / .aux_timeout / .vty_timeout | `_cisco_block_timeout(kind)` |
| authentication.password_policy.min_length | `_cisco_min_length` |
| authentication.password_policy.complexity | `_cisco_pw_complexity` |
| authentication.password_policy.expiration | `_cisco_pw_expiration` (`password aging`) |
| authentication.password_policy.history | `_cisco_pw_history` |
| authentication.password_policy.hash_algorithm | None (gap — JunOS-only) |
| authentication.mfa_enabled | None (gap) |
| aaa.authentication/authorization/accounting_enabled | `_cisco_aaa(kind)` |
| aaa.radius/tacacs_configured | `_cisco_aaa_server(key)` |
| logging.enabled / .level / .remote_enabled / .remote_server / .source_interface | `_cisco_logging_*` (level from 8 named severities) |
| ntp.configured / .authenticated / .servers | `_cisco_ntp_*` (deduped server list) |
| access_control.acl_applied / .rules_count / .default_action | `_cisco_acl_*` (named + classic ACLs; implicit-deny DERIVED) |
| crypto.ssh_key_size | `_cisco_ssh_key_size` |
| crypto.https_cert_valid | None (gap) |
| crypto.snmp_v3_auth | `_cisco_snmp_v3` |
| monitoring.syslog.enabled / .severity_level / .source_interface | logging extractors (severity name → 0–7) |
| monitoring.audit_trail.enabled | `_cisco_audit_trail` (`logging buffered/host`) |
| networking.access_control.enabled | `_cisco_net_access_control` (`no ip redirects/unreachables/…` inversion) |
| services.snmp.enabled / .version / .community_string_type | `_cisco_snmp_*` (group v3 ⇒ 3; community ⇒ 2 DERIVED; public/private/custom) |
| services.dns.configured | `_cisco_dns` (`ip name-server`) |
| services.dhcp.enabled | `_cisco_dhcp` (`ip dhcp`) |
| interfaces.unused_interfaces_shutdown | `_cisco_unused_shutdown` |
| interfaces.management_interface_identified | None (gap — FortiOS-only) |
| interfaces.loopback_configured | `_cisco_loopback` (`interface Loopback`) |

### fortinet → fortios (~26 paths, section-scoped)

| Universal path | Extractor |
|---|---|
| device.hostname | `_forti_hostname` (`set hostname`, quoted-aware) |
| device.vendor / device.platform | `_caller_identity` |
| device.firmware_version | None (gap) |
| management.http/https/ssh/telnet.enabled | `_forti_allowaccess(proto)` (`set allowaccess …`, skips `disable` blocks) |
| management.ssh.port | `_forti_admin_port("admin-ssh-port")` (`config system global`) |
| authentication.password_policy.min_length/expiration/history | `_forti_pw_int(key)` (`config system password-policy`) |
| authentication.password_policy.complexity | `_forti_pw_complexity` (enable/disable) |
| aaa.authentication/authorization_enabled | `_forti_section_present` (`config user local/group`) |
| logging.enabled / .remote_enabled / .remote_server | section present + `_forti_syslog_status/server` (`config log syslogd setting`) |
| ntp.configured / .servers | section present + `_forti_ntp_servers` (deduped) |
| access_control.acl_applied / .rules_count / .default_action | section present + `_forti_policy_count` (`edit N` count) + implicit-deny DERIVED |
| services.snmp.enabled | section present (`config system snmp-community`) |
| services.dns.configured | section present (`config system dns`) |
| services.dhcp.enabled | section present (`config system dhcp server`) |
| interfaces.management_interface_identified | `_forti_mgmt_interface` (`set dedicated-to management`) |

### juniper → junos (~33 paths, token + hierarchy-context)

Primitives: `_jtokens` (split), `_junos_ctx_tokens` (section labels + statement), `_junos_flag(ctx, context, target)`, `_junos_any(ctx, needles)`, `_junos_kv(ctx, key)` (first `key value` pair, either syntax).

| Universal path | Extractor |
|---|---|
| device.hostname | `_junos_hostname` (`set system host-name X` or brace `host-name X`) |
| device.vendor / device.platform | `_caller_identity` |
| device.firmware_version | `_junos_firmware` (`version …`) |
| device.time_zone | `_junos_time_zone` (`time-zone` kv) |
| management.ssh.enabled | `_junos_flag((system, services), ssh)` |
| management.ssh.port | `_junos_ssh_port` (ssh-scoped `port N`) |
| management.ssh.version | `_junos_ssh_version` (`protocol-version v2/v1` → 2/1) |
| management.ssh.root_login | `_junos_root_login` (deny→deny else allow) |
| management.telnet.enabled | `_junos_flag((system, services), telnet)` |
| management.http/https.enabled | `_junos_flag((web-management,), http/https)` |
| authentication.password_policy.min_length | `_junos_min_length` |
| authentication.password_policy.hash_algorithm | `_junos_pw_format` (md5/sha1/sha256/sha512) |
| authentication.lockout_policy.max_attempts | `_junos_tries` |
| authentication.lockout_policy.lockout_duration | `_junos_lockout` (minutes → seconds) |
| aaa.authentication/authorization_enabled | `_junos_any(authentication-order / authorization-order)` |
| aaa.accounting_enabled | `_junos_accounting` |
| logging.enabled | `_junos_flag((system,), syslog)` |
| logging.remote_enabled / .remote_server | `_junos_syslog_host/server` (system+syslog scoped `host`) |
| ntp.configured / .servers | `_junos_ntp_configured/servers` (key/version/prefer-aware) |
| ntp.authenticated | `_junos_flag((ntp,), authentication-key)` |
| ntp.version | `_junos_ntp_version` (3/4 only) |
| access_control.acl_applied | `_junos_flag((firewall,), filter)` |
| services.snmp.enabled | `_junos_any(snmp)` |
| services.snmp.version | `_junos_snmp_version` (v3 ⇒ 3, v2c ⇒ 2 DERIVED) |
| services.dns.configured | `_junos_any(name-server)` |
| interfaces.loopback_configured | `_junos_loopback` (lo0 + address) |
| config.conflicts | `_junos_conflicts` (same context+key, differing values; path map `_JUNOS_CONFLICT_PATH_MAP`) |

---

## 10. Cheat-sheet: reading any extractor

```text
for e in ctx.ev:                       # evidence order = file order (first hit wins)
    <match tokens/regex against e.text> # cleaned text, never raw
    if not e.negated: return (value, e.raw.strip(), [f"line:{e.line}"], "<CLASS>")
    <remember neg for later>
if neg: return (False, ..., "DIRECT_NEGATED")
return None                            # absent — never invented
```

`_Ctx.ev` / `_Evidence` / `_MapperOut` / `CANONICAL_PLATFORM` / `CONFIDENCE_POLICY` / `_UNSAFE_CHARS_RE`+`_sanitize` — all verbatim in §§2–7 above. Per-extractor bodies: `normalization.py` lines 958–2204, one screen each, all following the box above.
