"""
ML Training Pipeline — Vendor, Platform, Device Type Classification

Trains TF-IDF + LogisticRegression models on sample configs.
Produces model_artifacts/vendor_model.joblib and device_type_model.joblib

Usage:
  python -m app.ml.train
  python -m app.ml.train --eval
"""

import joblib
from pathlib import Path
from collections import Counter

# Paths
SAMPLE_DIR = Path(__file__).parent.parent.parent / "tests" / "sample_configs"
DEMO_DIR = Path(__file__).parent.parent.parent.parent / "demo-configs"
ARTIFACT_DIR = Path(__file__).parent / "model_artifacts"

# Labels inferred from filename + content heuristics
VENDOR_KEYWORDS = {
    "cisco": ["cisco", "ios", "ios_xe", "enable secret", "line vty", "interface GigabitEthernet"],
    "juniper": ["juniper", "junos", "set system", "##", "system {"],
    "fortinet": ["fortinet", "fortigate", "fortios", "config system", "edit \"", "set status"],
    "paloalto": ["paloalto", "panos", "set deviceconfig", "set rulebase"],
}

DEVICE_KEYWORDS = {
    "switch": ["switchport", "spanning-tree", "vlan", "interface FastEthernet", "interface Ethernet"],
    "router": ["router ospf", "router bgp", "router eigrp", "ip route", "interface Loopback", "interface Serial"],
    "firewall": ["access-list", "object network", "nat (", "threat-detection", "firewall policy", "set rulebase security"],
}


def infer_label(filepath: Path, content: str) -> tuple[str, str, str]:
    """Infer vendor, platform, device_type from filename and content."""
    fname = filepath.name.lower()
    content_lower = content.lower()

    # Vendor
    vendor = "cisco"  # default
    if "juniper" in fname:
        vendor = "juniper"
    elif "fortinet" in fname or "fortigate" in fname:
        vendor = "fortinet"
    elif "paloalto" in fname or "panos" in fname:
        vendor = "paloalto"
    else:
        # Content-based
        if "junos" in content_lower or "set system" in content_lower:
            vendor = "juniper"
        elif "fortios" in content_lower or "config system" in content_lower:
            vendor = "fortinet"
        elif "pan-os" in content_lower or "set deviceconfig" in content_lower:
            vendor = "paloalto"

    # Platform
    platform_map = {
        "cisco": "ios_xe",
        "juniper": "junos",
        "fortinet": "fortios",
        "paloalto": "panos",
    }
    platform = platform_map.get(vendor, "unknown")

    # Device type
    device_type = "unknown"
    scores = {k: 0 for k in DEVICE_KEYWORDS}
    for dtype, keywords in DEVICE_KEYWORDS.items():
        for kw in keywords:
            if kw.lower() in content_lower:
                scores[dtype] += 1
    best = max(scores, key=scores.get)
    if scores[best] >= 1:
        device_type = best
    # Fallback: filename hints
    if device_type == "unknown":
        if "switch" in fname:
            device_type = "switch"
        elif "router" in fname or "rtr" in fname:
            device_type = "router"
        elif "firewall" in fname or "fw" in fname or "fortigate" in fname:
            device_type = "firewall"
        else:
            device_type = "router"  # default for sample configs

    return vendor, platform, device_type


    return vendor, platform, device_type


def _generate_synthetic_configs():
    """Generate balanced synthetic configs for all vendor×device_type combos — next-level coverage."""
    synthetic = []
    for i in range(12):
        content = f"""hostname SW-CISCO-{i:02d}
!
aaa new-model
aaa authentication login default local
!
spanning-tree mode rapid-pvst
spanning-tree portfast default
spanning-tree portfast bpduguard default
vlan {10+i}
 name VLAN_{10+i}
!
interface GigabitEthernet0/{i % 48 + 1}
 switchport mode access
 switchport access vlan {10+i}
 spanning-tree portfast
 spanning-tree bpduguard enable
 switchport port-security
 switchport port-security maximum 2
 storm-control broadcast level 5.00
 ip dhcp snooping trust
 ip arp inspection trust
!
interface Vlan{10+i}
 ip address 192.168.{10+i}.1 255.255.255.0
 no ip redirects
!
interface Loopback0
 ip address 10.255.{i}.1 255.255.255.255
!
line vty 0 4
 transport input ssh
 exec-timeout 10 0
!
no ip http server
ip http secure-server
!
no cdp run
!
logging buffered 64000 informational
logging trap informational
logging host 10.0.0.{50+i}
ntp server 10.0.0.{10+i}
ntp authenticate
!
snmp-server group NETADMIN v3 priv
!
enable secret 5 $1$abc
service password-encryption
security passwords min-length 14
!
end
"""
        synthetic.append({"filename": f"syn_cisco_switch_{i:02d}.cfg", "content": content, "vendor": "cisco", "platform": "ios_xe", "device_type": "switch", "filepath": f"synthetic/cisco_switch_{i}"})
    for i in range(12):
        content = f"""hostname RTR-CISCO-{i:02d}
!
interface Loopback0
 ip address 10.0.{i}.1 255.255.255.255
!
interface Serial0/0/{i % 4}
 ip address 1.1.{i}.1 255.255.255.252
!
router ospf 1
 network 10.0.{i}.0 0.0.0.255 area 0
!
router bgp 6500{i}
 neighbor 2.2.{i}.1 remote-as 65001
!
ip route 0.0.0.0 0.0.0.0 1.1.{i}.2
!
enable secret 5 $1$xyz
"""
        synthetic.append({"filename": f"syn_cisco_router_{i:02d}.cfg", "content": content, "vendor": "cisco", "platform": "ios_xe", "device_type": "router", "filepath": f"synthetic/cisco_router_{i}"})
    for i in range(12):
        content = f"""hostname FW-ASA-{i:02d}
!
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.{i}.1 255.255.255.0
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.168.{i}.1 255.255.255.0
!
access-list outside_acl_{i} extended permit tcp any host 203.0.{i}.1 eq 80
access-group outside_acl_{i} in interface outside
!
object network INSIDE_NET_{i}
 subnet 192.168.{i}.0 255.255.255.0
 nat (inside,outside) source dynamic INSIDE_NET_{i} interface
!
threat-detection basic-threat
enable password 8Ry2YjIyt7RRXU24 encrypted
"""
        synthetic.append({"filename": f"syn_cisco_firewall_{i:02d}.cfg", "content": content, "vendor": "cisco", "platform": "asa", "device_type": "firewall", "filepath": f"synthetic/cisco_asa_{i}"})
    for i in range(10):
        content = f"""system {{
    host-name SW-JNPR-{i:02d};
}}
interfaces {{
    ge-0/0/{i} {{
        unit 0 {{
            family ethernet-switching {{
                vlan {{ members vlan{i+10}; }}
            }}
        }}
    }}
}}
vlans {{
    vlan{i+10} {{
        vlan-id {10+i};
        l3-interface vlan.{10+i};
    }}
}}
"""
        synthetic.append({"filename": f"syn_juniper_switch_{i:02d}.conf", "content": content, "vendor": "juniper", "platform": "junos", "device_type": "switch", "filepath": f"synthetic/juniper_switch_{i}"})
    for i in range(10):
        content = f"""system {{
    host-name RTR-JNPR-{i:02d};
}}
interfaces {{
    lo0 {{ unit 0 {{ family inet {{ address 10.0.{i}.1/32; }} }} }}
    ge-0/0/0 {{ unit 0 {{ family inet {{ address 1.1.{i}.1/30; }} }} }}
}}
protocols {{
    ospf {{ area 0.0.0.0 {{ interface ge-0/0/0.0; interface lo0.0; }} }}
    bgp {{ group ext {{ peer-as 65001; neighbor 2.2.{i}.1; }} }}
}}
"""
        synthetic.append({"filename": f"syn_juniper_router_{i:02d}.conf", "content": content, "vendor": "juniper", "platform": "junos", "device_type": "router", "filepath": f"synthetic/juniper_router_{i}"})
    for i in range(14):
        content = f"""config system global
    set hostname FGT-{i:02d}
end
config system interface
    edit "port1"
        set ip 192.168.{i}.1 255.255.255.0
    next
end
config firewall policy
    edit {i+1}
        set srcintf "internal"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end
"""
        synthetic.append({"filename": f"syn_fortinet_firewall_{i:02d}.conf", "content": content, "vendor": "fortinet", "platform": "fortios", "device_type": "firewall", "filepath": f"synthetic/fortinet_{i}"})
    for i in range(14):
        content = f"""set deviceconfig system hostname PA-FW-{i:02d}
set network interface ethernet ethernet1/1 layer3 ip 10.0.{i}.1/24
set rulebase security rules Allow-{i} from trust to untrust source 192.168.{i}.0/24 destination any application any service application-default action allow
"""
        synthetic.append({"filename": f"syn_paloalto_firewall_{i:02d}.cfg", "content": content, "vendor": "paloalto", "platform": "panos", "device_type": "firewall", "filepath": f"synthetic/paloalto_{i}"})
    for i in range(6):
        content = f"""set deviceconfig system hostname PA-RTR-{i:02d}
set network virtual-router default interface ethernet1/1
set network virtual-router default protocol bgp local-as 6500{i}
set network virtual-router default protocol ospf area 0.0.0.0 interface ethernet1/1
"""
        synthetic.append({"filename": f"syn_paloalto_router_{i:02d}.cfg", "content": content, "vendor": "paloalto", "platform": "panos", "device_type": "router", "filepath": f"synthetic/paloalto_rtr_{i}"})
    for i in range(12):
        content = f"""random gibberish {i}
foo bar baz qux
unknown command {i} xyz
parameter value {i} random
"""
        synthetic.append({"filename": f"syn_unknown_{i:02d}.txt", "content": content, "vendor": "unknown", "platform": "unknown", "device_type": "unknown", "filepath": f"synthetic/unknown_{i}"})
    return synthetic


def collect_dataset():
    """Collect all configs and labels — balanced, next-level."""
    configs = []

    # Sample configs (19 files)
    for f in sorted(SAMPLE_DIR.glob("*.txt")):
        try:
            content = f.read_text(errors="ignore")
            vendor, platform, dtype = infer_label(f, content)
            configs.append({
                "filepath": str(f),
                "filename": f.name,
                "content": content,
                "vendor": vendor,
                "platform": platform,
                "device_type": dtype,
            })
        except Exception as e:
            print(f"Skip {f}: {e}")

    # Demo configs if exist
    if DEMO_DIR.exists():
        for f in sorted(DEMO_DIR.glob("*.cfg")):
            try:
                content = f.read_text(errors="ignore")
                vendor, platform, dtype = infer_label(f, content)
                configs.append({
                    "filepath": str(f),
                    "filename": f.name,
                    "content": content,
                    "vendor": vendor,
                    "platform": platform,
                    "device_type": dtype,
                })
            except Exception:
                pass
        for f in sorted(DEMO_DIR.glob("*.conf")):
            try:
                content = f.read_text(errors="ignore")
                vendor, platform, dtype = infer_label(f, content)
                configs.append({
                    "filepath": str(f),
                    "filename": f.name,
                    "content": content,
                    "vendor": vendor,
                    "platform": platform,
                    "device_type": dtype,
                })
            except Exception:
                pass

    # Next-level: Add 92 balanced synthetic configs for all vendor×device_type combos
    synthetic = _generate_synthetic_configs()
    configs.extend(synthetic)
    print(f"Added {len(synthetic)} synthetic balanced configs")

    # Augment: generate synthetic variations for robustness
    augmented = []
    for c in configs:
        # Variation 1: uppercase
        augmented.append({**c, "content": c["content"].upper(), "filename": c["filename"] + "_upper"})
        # Variation 2: lower with extra whitespace
        augmented.append({**c, "content": c["content"].replace("\n", "\n\n"), "filename": c["filename"] + "_spaced"})
    configs.extend(augmented)

    return configs


def train():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score

    print("=== ConfigShield ML Training Pipeline ===")
    dataset = collect_dataset()
    print(f"Dataset: {len(dataset)} configs")
    print(f"  Vendors: {Counter(c['vendor'] for c in dataset)}")
    print(f"  Platforms: {Counter(c['platform'] for c in dataset)}")
    print(f"  Device types: {Counter(c['device_type'] for c in dataset)}")

    texts = [c["content"] for c in dataset]
    y_vendor = [c["vendor"] for c in dataset]
    y_device = [c["device_type"] for c in dataset]

    # Split
    X_train, X_test, yv_train, yv_test, yd_train, yd_test = train_test_split(
        texts, y_vendor, y_device, test_size=0.2, random_state=42, stratify=y_vendor
    )
    print(f"\nTrain: {len(X_train)}, Test: {len(X_test)}")

    # Vendor model
    print("\n--- Training Vendor Model (TF-IDF + LogisticRegression) ---")
    vendor_pipe = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=5000, ngram_range=(1, 3), lowercase=True, token_pattern=r"(?u)\b\w+\b")),
        ("clf", LogisticRegression(max_iter=500, solver="lbfgs")),
    ])
    vendor_pipe.fit(X_train, yv_train)
    yv_pred = vendor_pipe.predict(X_test)
    acc_v = accuracy_score(yv_test, yv_pred)
    print(f"Vendor Accuracy: {acc_v:.3f}")
    print(classification_report(yv_test, yv_pred, zero_division=0))

    # Device type model
    print("\n--- Training Device Type Model (TF-IDF + LogisticRegression) ---")
    device_pipe = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=3000, ngram_range=(1, 2), lowercase=True)),
        ("clf", LogisticRegression(max_iter=500, solver="lbfgs")),
    ])
    device_pipe.fit(X_train, yd_train)
    yd_pred = device_pipe.predict(X_test)
    acc_d = accuracy_score(yd_test, yd_pred)
    print(f"Device Type Accuracy: {acc_d:.3f}")
    print(classification_report(yd_test, yd_pred, zero_division=0))

    # Save artifacts
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(vendor_pipe, ARTIFACT_DIR / "vendor_model.joblib")
    joblib.dump(device_pipe, ARTIFACT_DIR / "device_type_model.joblib")

    # Save metadata
    import json
    meta = {
        "vendor_classes": sorted(set(y_vendor)),
        "device_type_classes": sorted(set(y_device)),
        "vendor_accuracy": acc_v,
        "device_type_accuracy": acc_d,
        "train_size": len(X_train),
        "test_size": len(X_test),
        "model": "TF-IDF + LogisticRegression",
        "features_vendor": 5000,
        "features_device": 3000,
        "ngram_vendor": "1-3",
        "ngram_device": "1-2",
    }
    with open(ARTIFACT_DIR / "metadata.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\n✓ Models saved to {ARTIFACT_DIR}")
    print("  - vendor_model.joblib")
    print("  - device_type_model.joblib")
    print(f"  - metadata.json: {meta}")

    return vendor_pipe, device_pipe, meta


if __name__ == "__main__":
    import sys
    if "--eval" in sys.argv:
        # Quick eval without retraining
        import joblib
        from pathlib import Path
        ARTIFACT_DIR = Path(__file__).parent / "model_artifacts"
        if not (ARTIFACT_DIR / "vendor_model.joblib").exists():
            print("No model found, training...")
            train()
        else:
            print("Model exists, loading...")
            vendor_pipe = joblib.load(ARTIFACT_DIR / "vendor_model.joblib")
            device_pipe = joblib.load(ARTIFACT_DIR / "device_type_model.joblib")
            print("Vendor model:", vendor_pipe)
            print("Device model:", device_pipe)
    else:
        train()
