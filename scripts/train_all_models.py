"""
Multi-Tool ML Scan Engine — Master Training Script
===================================================
Trains 7 specialized ML models:
  1. FirewallDetector      (Binary Classifier: Firewall present?)
  2. FlagOptimizer         (Multi-class: Best Nmap bypass flags)
  3. ServiceClassifier     (Multi-class: Service type from banner)
  4. VulnScorer            (Regressor: Threat likelihood 0-10 vs EPSS)
  5. WafPredictor          (Multi-class: WAF type & Web framework)
  6. WebFuzzOptimizer      (Multi-class: Fuzzing tool, wordlist & ext)
  7. NucleiTagSelector     (Multi-class: Best Nuclei template tags)
  8. SqliTamperScorer      (Multi-class: SQLmap tamper scripts & risk)

Run: python scripts/train_all_models.py
"""
import os
import sys
import time
import warnings
warnings.filterwarnings("ignore")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import pandas as pd
import numpy as np
import joblib

from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, mean_absolute_error, r2_score
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from ml_engine.feature_engineering import NetworkFeatureExtractor

try:
    from xgboost import XGBClassifier, XGBRegressor
    USE_XGB = True
except ImportError:
    USE_XGB = False

DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "ml_engine", "models")
os.makedirs(MODELS_DIR, exist_ok=True)


def make_classifier():
    if USE_XGB:
        return XGBClassifier(n_estimators=150, max_depth=6, learning_rate=0.05, n_jobs=-1, verbosity=0)
    return RandomForestClassifier(n_estimators=150, max_depth=8, random_state=42, n_jobs=-1)

def make_regressor():
    if USE_XGB:
        return XGBRegressor(n_estimators=150, max_depth=6, learning_rate=0.05, n_jobs=-1, verbosity=0)
    return RandomForestRegressor(n_estimators=150, max_depth=8, random_state=42, n_jobs=-1)

# ── MODEL 1: FirewallDetector ────────────────────────────────────
def train_firewall_detector(df):
    print("\n" + "─" * 50)
    print("  Training Model 1: FirewallDetector")
    print("─" * 50)
    df["banner_text"] = df["banner_text"].fillna("")
    df["os_fingerprint"] = df["os_fingerprint"].fillna("Unknown")
    df["port_state"] = df["port_state"].fillna("filtered")
    df["protocol"] = df["protocol"].fillna("tcp")

    X = df.drop(columns=["firewall_present", "firewall_type", "best_bypass_flag"], errors="ignore")
    y = df["firewall_present"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    clf = make_classifier()
    numeric_cols = ["port", "rtt_ms", "ttl", "icmp_blocked", "rst_received",
                    "filtered_port_count", "open_port_count", "total_ports_scanned"]
    avail_cols = [c for c in numeric_cols if c in X_train.columns]

    pipe = Pipeline([("net_feats", NetworkFeatureExtractor()), ("model", clf)])
    t0 = time.time()
    pipe.fit(X_train[avail_cols], y_train)
    acc = accuracy_score(y_test, pipe.predict(X_test[avail_cols]))
    print(f"  ✅ Accuracy: {acc:.4f} ({acc*100:.1f}%) | Time: {time.time()-t0:.1f}s")
    joblib.dump({"pipeline": pipe, "feature_cols": avail_cols}, os.path.join(MODELS_DIR, "firewall_detector.pkl"), compress=3)
    return pipe

# ── MODEL 2: FlagOptimizer ───────────────────────────────────────
def train_flag_optimizer(df):
    print("\n" + "─" * 50)
    print("  Training Model 2: FlagOptimizer")
    print("─" * 50)
    df_fw = df[df["firewall_present"] == 1].copy()
    if len(df_fw) < 100: df_fw = df.copy()

    le = LabelEncoder()
    y = le.fit_transform(df_fw["best_bypass_flag"])
    numeric_cols = ["port", "rtt_ms", "ttl", "icmp_blocked", "rst_received",
                    "filtered_port_count", "open_port_count", "total_ports_scanned"]
    avail_cols = [c for c in numeric_cols if c in df_fw.columns]
    X = df_fw[avail_cols]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    clf = make_classifier()
    pipe = Pipeline([("net_feats", NetworkFeatureExtractor()), ("model", clf)])
    t0 = time.time()
    pipe.fit(X_train, y_train)
    acc = accuracy_score(y_test, pipe.predict(X_test))
    print(f"  ✅ Accuracy: {acc:.4f} ({acc*100:.1f}%) | Time: {time.time()-t0:.1f}s")
    joblib.dump({"pipeline": pipe, "label_encoder": le, "feature_cols": avail_cols}, os.path.join(MODELS_DIR, "flag_optimizer.pkl"), compress=3)
    return pipe

# ── MODEL 3: ServiceClassifier ───────────────────────────────────
def train_service_classifier(df):
    print("\n" + "─" * 50)
    print("  Training Model 3: ServiceClassifier")
    print("─" * 50)
    df["banner_text"] = df["banner_text"].fillna("")
    le = LabelEncoder()
    y = le.fit_transform(df["service_label"])

    from scipy.sparse import hstack, csr_matrix
    tfidf = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), max_features=300, sublinear_tf=True)
    banner_feats = tfidf.fit_transform(df["banner_text"])
    port_sparse = csr_matrix(df[["port"]].fillna(0).values)
    X = hstack([banner_feats, port_sparse])

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    clf = make_classifier()
    t0 = time.time()
    clf.fit(X_train, y_train)
    acc = accuracy_score(y_test, clf.predict(X_test))
    print(f"  ✅ Accuracy: {acc:.4f} ({acc*100:.1f}%) | Time: {time.time()-t0:.1f}s")
    joblib.dump({"classifier": clf, "tfidf": tfidf, "label_encoder": le}, os.path.join(MODELS_DIR, "service_classifier.pkl"), compress=3)
    return clf

# ── MODEL 4: VulnScorer ──────────────────────────────────────────
def train_vuln_scorer(df):
    print("\n" + "─" * 50)
    print("  Training Model 4: VulnScorer")
    print("─" * 50)
    df["banner_text"] = df["banner_text"].fillna("")
    le_svc = LabelEncoder()
    df["svc_enc"] = le_svc.fit_transform(df["service_name"].fillna("Unknown"))

    from scipy.sparse import hstack, csr_matrix
    tfidf = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), max_features=200, sublinear_tf=True)
    banner_feats = tfidf.fit_transform(df["banner_text"])
    num_feats = df[["port", "svc_enc"]].fillna(0).values
    X = hstack([banner_feats, csr_matrix(num_feats)])
    y = df["vuln_score"].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    reg = make_regressor()
    t0 = time.time()
    reg.fit(X_train, y_train)
    mae = mean_absolute_error(y_test, np.clip(reg.predict(X_test), 0, 10))
    print(f"  ✅ MAE: {mae:.4f} (lower=better) | Time: {time.time()-t0:.1f}s")
    joblib.dump({"regressor": reg, "tfidf": tfidf, "label_encoder": le_svc}, os.path.join(MODELS_DIR, "vuln_scorer.pkl"), compress=3)
    return reg

# ── MODEL 5: WafPredictor (NEW) ──────────────────────────────────
def train_waf_predictor(df):
    print("\n" + "─" * 50)
    print("  Training Model 5: WafPredictor")
    print("─" * 50)
    df["server_header"] = df["server_header"].fillna("")
    le_waf = LabelEncoder()
    y = le_waf.fit_transform(df["waf_detected"])

    from scipy.sparse import hstack, csr_matrix
    tfidf = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), max_features=200)
    server_feats = tfidf.fit_transform(df["server_header"])
    num_feats = df[["status_code", "has_waf_cookie", "content_length"]].values
    X = hstack([server_feats, csr_matrix(num_feats)])

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = make_classifier()
    t0 = time.time()
    clf.fit(X_train, y_train)
    acc = accuracy_score(y_test, clf.predict(X_test))
    print(f"  ✅ WAF Detection Accuracy: {acc:.4f} ({acc*100:.1f}%) | Time: {time.time()-t0:.1f}s")
    joblib.dump({"classifier": clf, "tfidf": tfidf, "label_encoder": le_waf}, os.path.join(MODELS_DIR, "waf_predictor.pkl"), compress=3)
    return clf

# ── MODEL 6: WebFuzzOptimizer (NEW) ──────────────────────────────
def train_web_fuzz_optimizer(df):
    print("\n" + "─" * 50)
    print("  Training Model 6: WebFuzzOptimizer")
    print("─" * 50)
    le_tool = LabelEncoder()
    y = le_tool.fit_transform(df["recommended_tool"])

    from scipy.sparse import hstack, csr_matrix
    tfidf_fw = TfidfVectorizer(analyzer="word", max_features=100)
    fw_feats = tfidf_fw.fit_transform(df["framework"].fillna(""))
    tfidf_waf = TfidfVectorizer(analyzer="word", max_features=100)
    waf_feats = tfidf_waf.fit_transform(df["waf_type"].fillna(""))
    X = hstack([fw_feats, waf_feats])

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = make_classifier()
    t0 = time.time()
    clf.fit(X_train, y_train)
    acc = accuracy_score(y_test, clf.predict(X_test))
    print(f"  ✅ Fuzzing Tool Optimizer Accuracy: {acc:.4f} ({acc*100:.1f}%) | Time: {time.time()-t0:.1f}s")
    joblib.dump({"classifier": clf, "tfidf_fw": tfidf_fw, "tfidf_waf": tfidf_waf, "label_encoder": le_tool}, os.path.join(MODELS_DIR, "web_fuzz_optimizer.pkl"), compress=3)
    return clf

# ── MODEL 7: NucleiTagSelector (NEW) ─────────────────────────────
def train_nuclei_tag_selector(df):
    print("\n" + "─" * 50)
    print("  Training Model 7: NucleiTagSelector")
    print("─" * 50)
    le_tags = LabelEncoder()
    y = le_tags.fit_transform(df["recommended_nuclei_tags"])

    from scipy.sparse import hstack, csr_matrix
    tfidf_svc = TfidfVectorizer(analyzer="word", max_features=100)
    svc_feats = tfidf_svc.fit_transform(df["service"].fillna(""))
    num_feats = df[["port"]].values
    X = hstack([svc_feats, csr_matrix(num_feats)])

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = make_classifier()
    t0 = time.time()
    clf.fit(X_train, y_train)
    acc = accuracy_score(y_test, clf.predict(X_test))
    print(f"  ✅ Nuclei Tag Predictor Accuracy: {acc:.4f} ({acc*100:.1f}%) | Time: {time.time()-t0:.1f}s")
    joblib.dump({"classifier": clf, "tfidf_svc": tfidf_svc, "label_encoder": le_tags}, os.path.join(MODELS_DIR, "nuclei_tag_selector.pkl"), compress=3)
    return clf

# ── MODEL 8: SqliTamperScorer (NEW) ──────────────────────────────
def train_sqli_tamper_scorer(df):
    print("\n" + "─" * 50)
    print("  Training Model 8: SqliTamperScorer")
    print("─" * 50)
    le_tamper = LabelEncoder()
    y = le_tamper.fit_transform(df["recommended_tamper"])

    from scipy.sparse import hstack, csr_matrix
    tfidf_db = TfidfVectorizer(analyzer="word", max_features=100)
    db_feats = tfidf_db.fit_transform(df["db_type"].fillna(""))
    tfidf_waf = TfidfVectorizer(analyzer="word", max_features=100)
    waf_feats = tfidf_waf.fit_transform(df["waf_type"].fillna(""))
    X = hstack([db_feats, waf_feats])

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = make_classifier()
    t0 = time.time()
    clf.fit(X_train, y_train)
    acc = accuracy_score(y_test, clf.predict(X_test))
    print(f"  ✅ SQLmap Tamper Script Predictor Accuracy: {acc:.4f} ({acc*100:.1f}%) | Time: {time.time()-t0:.1f}s")
    joblib.dump({"classifier": clf, "tfidf_db": tfidf_db, "tfidf_waf": tfidf_waf, "label_encoder": le_tamper}, os.path.join(MODELS_DIR, "sqli_tamper_scorer.pkl"), compress=3)
    return clf


def main():
    start_time = time.time()
    print("=" * 60)
    print("  SUPER-SMART MULTI-TOOL ML ENGINE — TRAINING ALL 8 MODELS")
    print("=" * 60)

    # 1. Load Firewall & Network dataset
    p_fw = os.path.join(DATA_DIR, "unified_firewall_scans.csv")
    if not os.path.exists(p_fw): p_fw = os.path.join(DATA_DIR, "synthetic_firewall_scans.csv")
    df_fw = pd.read_csv(p_fw)
    print(f"✅ Firewall Dataset: {len(df_fw):,} rows")

    # 2. Load Service dataset
    p_svc = os.path.join(DATA_DIR, "unified_service_data.csv")
    if not os.path.exists(p_svc): p_svc = os.path.join(DATA_DIR, "synthetic_service_data.csv")
    df_svc = pd.read_csv(p_svc)
    print(f"✅ Service Dataset: {len(df_svc):,} rows")

    # 3. Load Vuln dataset
    p_vuln = os.path.join(DATA_DIR, "unified_vuln_scores.csv")
    if not os.path.exists(p_vuln): p_vuln = os.path.join(DATA_DIR, "synthetic_vuln_scores.csv")
    df_vuln = pd.read_csv(p_vuln)
    print(f"✅ Vuln Dataset: {len(df_vuln):,} rows")

    # 4. Load WAF dataset
    df_waf = pd.read_csv(os.path.join(DATA_DIR, "synthetic_waf_tech.csv"))
    print(f"✅ WAF & Tech Dataset: {len(df_waf):,} rows")

    # 5. Load Fuzzing dataset
    df_fuzz = pd.read_csv(os.path.join(DATA_DIR, "synthetic_web_fuzz.csv"))
    print(f"✅ Web Fuzzing Dataset: {len(df_fuzz):,} rows")

    # 6. Load Nuclei dataset
    df_nuclei = pd.read_csv(os.path.join(DATA_DIR, "synthetic_nuclei_tags.csv"))
    print(f"✅ Nuclei Tag Dataset: {len(df_nuclei):,} rows")

    # 7. Load SQLmap dataset
    df_sql = pd.read_csv(os.path.join(DATA_DIR, "synthetic_sqlmap.csv"))
    print(f"✅ SQLmap Tamper Dataset: {len(df_sql):,} rows")

    # Train all 8 models
    train_firewall_detector(df_fw)
    train_flag_optimizer(df_fw)
    train_service_classifier(df_svc)
    train_vuln_scorer(df_vuln)
    train_waf_predictor(df_waf)
    train_web_fuzz_optimizer(df_fuzz)
    train_nuclei_tag_selector(df_nuclei)
    train_sqli_tamper_scorer(df_sql)

    total_time = time.time() - start_time
    total_size = sum(os.path.getsize(os.path.join(MODELS_DIR, f)) for f in os.listdir(MODELS_DIR) if f.endswith(".pkl"))
    print("\n" + "=" * 60)
    print("  🎉 ALL 8 MULTI-TOOL ML MODELS TRAINED SUCCESSFULLY!")
    print(f"  ⏱  Total Training Time: {total_time:.1f}s")
    print(f"  💾 Total Model Storage: {total_size // 1024 // 1024} MB ({total_size // 1024} KB)")
    print("=" * 60)

if __name__ == "__main__":
    main()
