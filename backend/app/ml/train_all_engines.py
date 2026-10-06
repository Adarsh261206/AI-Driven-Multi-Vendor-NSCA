"""
Train All Engines ML — Normalisation + Semantic + Risk Scoring

Trains 3 ML models for ConfigShield engines:
1. Normalisation: raw config line → universal_model_path (TF-IDF + Classifier)
2. Semantic: unknown syntax → meaning + security_relevance
3. Risk Scoring: (severity, vendor, category, confidence) → risk_score

Usage:
  python -m app.ml.train_all_engines
"""

import json
import joblib
from pathlib import Path
from collections import Counter

ARTIFACT_DIR = Path(__file__).parent / "model_artifacts"


# =====================================================================
# 1. NORMALISATION ENGINE — raw line → universal_model_path
# =====================================================================

NORMALISATION_TRAINING_DATA = [
    # AAA
    ("aaa new-model", "aaa.authentication_enabled"),
    ("aaa authentication login default local", "aaa.authentication_enabled"),
    ("aaa authorization exec default local", "aaa.authorization_enabled"),
    ("aaa accounting exec default start-stop local", "aaa.accounting_enabled"),
    # SSH
    ("ip ssh version 2", "management.ssh.version"),
    ("ip ssh authentication-retries 3", "management.ssh.auth_retries"),
    ("ip ssh time-out 120", "management.ssh.session_timeout"),
    ("ip ssh source-interface Loopback0", "management.ssh.source_interface"),
    ("transport input ssh", "management.vty.transport"),
    ("exec-timeout 10 0", "management.vty.vty_timeout"),
    # HTTP
    ("no ip http server", "management.http.enabled"),
    ("ip http secure-server", "management.https.enabled"),
    # Logging
    ("logging buffered informational", "monitoring.syslog.severity_level"),
    ("logging host 10.0.0.1", "monitoring.syslog.enabled"),
    ("logging source-interface Loopback0", "monitoring.syslog.source_interface"),
    ("service timestamps log datetime msec", "monitoring.audit_trail.enabled"),
    # NTP
    ("ntp server 1.1.1.1", "ntp.configured"),
    ("ntp authenticate", "ntp.authenticated"),
    ("ntp authentication-key 1 md5 cisco", "ntp.authenticated"),
    ("ntp trusted-key 1", "ntp.authenticated"),
    # SNMP
    ("snmp-server community public RO", "services.snmp.version"),
    ("snmp-server group TEST v3 priv", "services.snmp.version"),
    ("snmp-server user admin TEST v3 auth sha cisco priv aes cisco", "services.snmp.version"),
    # Password
    ("security passwords min-length 14", "authentication.password_policy.min_length"),
    ("enable secret 5 $1$xyz", "authentication.password_policy.min_length"),
    ("service password-encryption", "authentication.password_policy.complexity"),
    # Access control
    ("access-list 99 permit 10.0.0.0 0.0.0.255", "access_control.acl_applied"),
    ("access-class 99 in", "access_control.acl_applied"),
    # Services
    ("no service pad", "services.snmp.enabled"),
    ("no cdp run", "services.snmp.enabled"),
    ("no ip source-route", "networking.access_control.enabled"),
    # Interfaces
    ("interface Loopback0", "interfaces.loopback_configured"),
    ("hostname RTR-01", "device.hostname"),
    # Juniper
    ("set system host-name R1", "device.hostname"),
    ("set system time-zone UTC", "device.time_zone"),
    ("set system services ssh", "management.ssh.enabled"),
    ("set system login password format sha512", "authentication.password_policy.hash_algorithm"),
    # Fortinet
    ("config system global", "device.hostname"),
    ("set hostname FGT-01", "device.hostname"),
    ("config system password-policy", "authentication.password_policy.min_length"),
    # Unknown examples (should map to closest)
    ("banner motd # Authorized Access Only #", "device.hostname"),
    ("clock timezone IST 5 30", "device.time_zone"),
]


def train_normalisation():
    print("\n=== 1. Normalisation Engine — raw line → universal_model_path ===")
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report

    # Expand dataset with augmentations
    texts, labels = [], []
    for raw, path in NORMALISATION_TRAINING_DATA:
        texts.append(raw)
        labels.append(path)
        # Augment: variations
        texts.append(raw.upper())
        labels.append(path)
        texts.append(raw + "  ")
        labels.append(path)
        texts.append(raw.replace(" ", "  "))
        labels.append(path)

    print(f"Dataset: {len(texts)} samples, {len(set(labels))} universal paths")
    print(f"  Paths: {Counter(labels).most_common(5)}")

    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42)

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=3000, ngram_range=(1, 3), lowercase=True)),
        ("clf", LogisticRegression(max_iter=500, solver="lbfgs")),
    ])
    pipe.fit(X_train, y_train)
    y_pred = pipe.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {acc:.3f}")
    print(classification_report(y_test, y_pred, zero_division=0))

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, ARTIFACT_DIR / "normalisation_model.joblib")

    # Save label mapping
    meta = {
        "type": "normalisation",
        "model": "TF-IDF(3000, 1-3) + LogisticRegression",
        "train_size": len(X_train),
        "test_size": len(X_test),
        "accuracy": acc,
        "num_classes": len(set(labels)),
        "classes": sorted(set(labels)),
    }
    with open(ARTIFACT_DIR / "normalisation_meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"✓ Saved to {ARTIFACT_DIR / 'normalisation_model.joblib'} — {meta}")
    return pipe, meta


# =====================================================================
# 2. SEMANTIC ENGINE — unknown syntax → meaning + security_relevance
# =====================================================================

SEMANTIC_TRAINING_DATA = [
    ("ip domain-name example.com", "Domain name configuration", "LOW"),
    ("ip name-server 8.8.8.8", "DNS name server", "MEDIUM"),
    ("banner login ^C Authorized Users Only ^C", "Login banner", "LOW"),
    ("clock timezone IST 5 30", "Timezone configuration", "LOW"),
    ("service timestamps debug datetime msec", "Debug timestamp", "LOW"),
    ("archive", "Configuration archive", "MEDIUM"),
    ("path tftp://1.1.1.1/config", "Archive path", "MEDIUM"),
    ("errdisable recovery cause all", "Error disable recovery", "MEDIUM"),
    ("power inline never", "PoE configuration", "LOW"),
    ("udld port aggressive", "UDLD detection", "MEDIUM"),
    ("mls qos trust dscp", "QoS trust", "LOW"),
    ("ip dhcp snooping", "DHCP snooping", "HIGH"),
    ("ip arp inspection vlan 1", "ARP inspection", "HIGH"),
    ("storm-control broadcast level 5.00", "Storm control", "MEDIUM"),
    ("port-security maximum 5", "Port security", "HIGH"),
    ("dot1x pae authenticator", "802.1X authenticator", "HIGH"),
    ("aaa new-model", "AAA model", "HIGH"),  # known but for training
    ("crypto key generate rsa modulus 2048", "RSA key generation", "HIGH"),
    ("ip ssh version 2", "SSH version", "HIGH"),
    ("ntp server 10.0.0.1", "NTP server", "MEDIUM"),
    ("logging host 10.0.0.5", "Syslog host", "MEDIUM"),
    ("snmp-server enable traps", "SNMP traps", "MEDIUM"),
    ("access-list 10 permit 192.168.1.0", "ACL permit", "HIGH"),
    ("route-map RM permit 10", "Route map", "MEDIUM"),
    ("ip access-group 100 in", "Interface ACL", "HIGH"),
]


def train_semantic():
    print("\n=== 2. Semantic Analysis Engine — syntax → security relevance ===")
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report

    texts = [x[0] for x in SEMANTIC_TRAINING_DATA]
    labels = [x[2] for x in SEMANTIC_TRAINING_DATA]  # security relevance: LOW/MEDIUM/HIGH

    # Augment
    aug_texts, aug_labels = [], []
    for t, lab in zip(texts, labels):
        aug_texts.extend([t, t.upper(), t + " ", t.replace(" ", "  ")])
        aug_labels.extend([lab, lab, lab, lab])
    texts, labels = aug_texts, aug_labels

    print(f"Dataset: {len(texts)} samples, classes: {Counter(labels)}")

    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42)

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=2000, ngram_range=(1, 2), lowercase=True)),
        ("clf", LogisticRegression(max_iter=500, solver="lbfgs")),
    ])
    pipe.fit(X_train, y_train)
    y_pred = pipe.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {acc:.3f}")
    print(classification_report(y_test, y_pred, zero_division=0))

    joblib.dump(pipe, ARTIFACT_DIR / "semantic_model.joblib")

    meta = {
        "type": "semantic",
        "model": "TF-IDF(2000, 1-2) + LogisticRegression",
        "train_size": len(X_train),
        "test_size": len(X_test),
        "accuracy": acc,
        "classes": sorted(set(labels)),
    }
    with open(ARTIFACT_DIR / "semantic_meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"✓ Saved to {ARTIFACT_DIR / 'semantic_model.joblib'} — {meta}")
    return pipe, meta


# =====================================================================
# 3. RISK SCORING ENGINE — (severity, vendor, category, confidence) → risk_score
# =====================================================================

def train_risk():
    print("\n=== 3. Compliance Risk Scoring Engine — features → risk 0-100 ===")
    from sklearn.ensemble import RandomForestRegressor
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import mean_squared_error, r2_score
    import numpy as np
    import random

    # E09 F6: training shares the canonical serving vocabulary and feature
    # semantics exactly (same severity/vendor/category mappings, same
    # confidence transform, same feature order) via build_risk_features.
    # Labels remain SYNTHETIC (normative formula + noise) — the model is a
    # formula emulator for advisory use only; meta.scope says so explicitly.
    from app.engines.compliance.risk import (
        CATEGORY_IMPACT,
        RISK_FEATURES,
        SEVERITY_BASE,
        VENDOR_IMPACT,
        build_risk_features,
        deterministic_score,
    )

    random.seed(42)
    np.random.seed(42)

    data_rows = []
    for _ in range(2000):
        sev = random.choice(list(SEVERITY_BASE.keys()))
        vendor = random.choice(list(VENDOR_IMPACT.keys()))
        category = random.choice(list(CATEGORY_IMPACT.keys()))
        confidence = random.uniform(0.5, 1.0)

        sev_num, v_mult, c_mult, conf = build_risk_features(
            sev, vendor, category, confidence)
        risk = deterministic_score(sev, vendor, category, confidence)
        risk_noisy = risk + random.gauss(0, 2)
        risk_noisy = max(0, min(100, risk_noisy))

        data_rows.append([sev_num, v_mult, c_mult, conf, risk_noisy])

    arr = np.array(data_rows)
    X = arr[:, :4]  # severity_num, vendor_mult, category_mult, confidence
    y = arr[:, 4]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestRegressor(n_estimators=100, max_depth=10, random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    mse = mean_squared_error(y_test, y_pred)
    r2 = r2_score(y_test, y_pred)
    print(f"MSE: {mse:.2f}, R2: {r2:.3f}")
    feat_names = list(RISK_FEATURES)
    print(f"Feature importances: {dict(zip(feat_names, model.feature_importances_))}")

    joblib.dump(model, ARTIFACT_DIR / "risk_model.joblib")

    meta = {
        "type": "risk_scoring",
        "model": "RandomForestRegressor(100 trees, depth 10)",
        "train_size": len(X_train),
        "test_size": len(X_test),
        "mse": mse,
        "r2": r2,
        "features": feat_names,
        # E09 F6 honesty labeling: this model emulates the normative
        # deterministic formula on synthetic labels. r2/mse measure
        # formula-emulation fit on a synthetic holdout — never real-world
        # risk-prediction accuracy. The model is advisory-only.
        "scope": "advisory-only formula emulation (never normative)",
        "label_source": "synthetic: normative deterministic formula + N(0,2) noise",
        "label_formula": "base*vendor*category*max(conf,0.5)/15.6*100",
        "confidence_transform": "max(confidence, 0.5) (shared with serving)",
        "vocabulary": "canonical risk.py maps (shared with serving)",
    }
    with open(ARTIFACT_DIR / "risk_meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"✓ Saved to {ARTIFACT_DIR / 'risk_model.joblib'} — {meta}")
    return model, meta


def train_all():
    print("=== ConfigShield — Train All 3 Engines ML ===")
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    m1, meta1 = train_normalisation()
    m2, meta2 = train_semantic()
    m3, meta3 = train_risk()

    print("\n=== All 3 Engines Trained ===")
    print(f"Artifacts in {ARTIFACT_DIR}:")
    for f in sorted(ARTIFACT_DIR.glob("*.joblib")):
        print(f"  - {f.name} ({f.stat().st_size} bytes)")
    for f in sorted(ARTIFACT_DIR.glob("*.json")):
        print(f"  - {f.name}")

    # Combined meta
    combined = {
        "normalisation": meta1,
        "semantic": meta2,
        "risk": meta3,
        "total_models": 5,  # vendor, device_type, normalisation, semantic, risk
    }
    with open(ARTIFACT_DIR / "all_engines_meta.json", "w") as f:
        json.dump(combined, f, indent=2)
    print(f"\n✓ All engines meta: {combined}")


if __name__ == "__main__":
    train_all()
