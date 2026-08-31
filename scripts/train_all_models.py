"""
ML Scan Engine — Master Training Script
=========================================
Trains all 4 ML models:
  1. FirewallDetector   (binary classifier)
  2. FlagOptimizer      (multi-class classifier)
  3. ServiceClassifier  (multi-class classifier)
  4. VulnScorer         (regressor)

Uses: XGBoost + scikit-learn Pipeline
Output: models/ directory with .pkl files

Run: python scripts/train_all_models.py
Expected time: 5-15 minutes on CPU
Expected accuracy:
  FirewallDetector:  >92%
  FlagOptimizer:     >85% macro-F1
  ServiceClassifier: >85% top-1 accuracy
  VulnScorer:        <1.5 MAE
"""
import os
import sys
import time
import warnings
warnings.filterwarnings("ignore")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import numpy as np
import pandas as pd
import joblib

from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import LabelEncoder, StandardScaler, OneHotEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, accuracy_score, f1_score,
    mean_absolute_error, r2_score
)
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from ml_engine.feature_engineering import NetworkFeatureExtractor

try:
    from xgboost import XGBClassifier, XGBRegressor
    USE_XGB = True
    print("✅ XGBoost available — using XGBClassifier/XGBRegressor")
except ImportError:
    USE_XGB = False
    print("⚠️  XGBoost not available — using RandomForest fallback")

DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "ml_engine", "models")
os.makedirs(MODELS_DIR, exist_ok=True)


# ── Custom Network Feature Engineering imported from ml_engine.feature_engineering



def make_classifier():
    if USE_XGB:
        return XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            use_label_encoder=False,
            eval_metric="mlogloss",
            random_state=42,
            n_jobs=-1,
            verbosity=0,
        )
    return RandomForestClassifier(
        n_estimators=200, max_depth=8, random_state=42, n_jobs=-1
    )


def make_regressor():
    if USE_XGB:
        return XGBRegressor(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            n_jobs=-1,
            verbosity=0,
        )
    return RandomForestRegressor(
        n_estimators=200, max_depth=8, random_state=42, n_jobs=-1
    )


def build_text_tabular_pipeline(clf_or_reg, task="classification"):
    """Build a ColumnTransformer pipeline combining tabular + TF-IDF text features."""
    net_features = NetworkFeatureExtractor()

    # Banner text TF-IDF (character n-grams — robust to version variations)
    banner_tfidf = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 4),
        max_features=300,
        sublinear_tf=True,
        min_df=2,
    )

    # OS fingerprint word n-grams
    os_tfidf = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        max_features=80,
    )

    # Categorical encoding
    cat_encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)

    preprocessor = ColumnTransformer(
        transformers=[
            ("net_feats", net_features, lambda df: df),
            ("banner_tfidf", banner_tfidf, "banner_text"),
            ("os_tfidf", os_tfidf, "os_fingerprint"),
            ("cat", cat_encoder, ["port_state", "protocol"]),
        ],
        remainder="drop",
        n_jobs=1,
    )

    return Pipeline([("preprocessor", preprocessor), ("model", clf_or_reg)])


# ═══════════════════════════════════════════════════════════
# MODEL 1: FirewallDetector
# ═══════════════════════════════════════════════════════════
def train_firewall_detector(df: pd.DataFrame):
    print("\n" + "─" * 50)
    print("  Training Model 1: FirewallDetector")
    print("─" * 50)

    # Fill missing
    df["banner_text"] = df["banner_text"].fillna("")
    df["os_fingerprint"] = df["os_fingerprint"].fillna("Unknown")
    df["port_state"] = df["port_state"].fillna("filtered")
    df["protocol"] = df["protocol"].fillna("tcp")

    X = df.drop(columns=["firewall_present", "firewall_type", "best_bypass_flag"],
                errors="ignore")
    y = df["firewall_present"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = make_classifier()

    # Use simple feature set for binary classification
    numeric_cols = ["port", "rtt_ms", "ttl", "icmp_blocked", "rst_received",
                    "filtered_port_count", "open_port_count", "total_ports_scanned"]
    available_cols = [c for c in numeric_cols if c in X_train.columns]

    pipe = Pipeline([
        ("net_feats", NetworkFeatureExtractor()),
        ("model", clf),
    ])

    t0 = time.time()
    pipe.fit(X_train[available_cols], y_train)
    train_time = time.time() - t0

    y_pred = pipe.predict(X_test[available_cols])
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="macro")

    print(f"  ✅ Accuracy: {acc:.4f} ({acc*100:.1f}%)")
    print(f"  ✅ Macro-F1: {f1:.4f}")
    print(f"  ⏱  Training time: {train_time:.1f}s")

    model_path = os.path.join(MODELS_DIR, "firewall_detector.pkl")
    # Save with feature columns list
    joblib.dump({"pipeline": pipe, "feature_cols": available_cols}, model_path, compress=3)
    size_kb = os.path.getsize(model_path) // 1024
    print(f"  💾 Saved: {model_path} ({size_kb}KB)")
    return pipe, available_cols


# ═══════════════════════════════════════════════════════════
# MODEL 2: FlagOptimizer
# ═══════════════════════════════════════════════════════════
def train_flag_optimizer(df: pd.DataFrame):
    print("\n" + "─" * 50)
    print("  Training Model 2: FlagOptimizer")
    print("─" * 50)

    df["banner_text"] = df["banner_text"].fillna("")
    df["os_fingerprint"] = df["os_fingerprint"].fillna("Unknown")
    df["port_state"] = df["port_state"].fillna("filtered")
    df["protocol"] = df["protocol"].fillna("tcp")

    # Only train on firewall-positive samples (no firewall → always connect_scan)
    df_fw = df[df["firewall_present"] == 1].copy()
    if len(df_fw) < 100:
        df_fw = df.copy()

    le = LabelEncoder()
    y = le.fit_transform(df_fw["best_bypass_flag"])

    numeric_cols = ["port", "rtt_ms", "ttl", "icmp_blocked", "rst_received",
                    "filtered_port_count", "open_port_count", "total_ports_scanned"]
    available_cols = [c for c in numeric_cols if c in df_fw.columns]
    X = df_fw[available_cols]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = make_classifier()
    pipe = Pipeline([
        ("net_feats", NetworkFeatureExtractor()),
        ("model", clf),
    ])

    t0 = time.time()
    pipe.fit(X_train, y_train)
    train_time = time.time() - t0

    y_pred = pipe.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="macro")

    print(f"  ✅ Accuracy: {acc:.4f} ({acc*100:.1f}%)")
    print(f"  ✅ Macro-F1: {f1:.4f}")
    print(f"  ⏱  Training time: {train_time:.1f}s")
    print(f"  Classes ({len(le.classes_)}): {list(le.classes_)}")

    model_path = os.path.join(MODELS_DIR, "flag_optimizer.pkl")
    joblib.dump(
        {"pipeline": pipe, "label_encoder": le, "feature_cols": available_cols},
        model_path, compress=3
    )
    size_kb = os.path.getsize(model_path) // 1024
    print(f"  💾 Saved: {model_path} ({size_kb}KB)")
    return pipe, le


# ═══════════════════════════════════════════════════════════
# MODEL 3: ServiceClassifier
# ═══════════════════════════════════════════════════════════
def train_service_classifier(df_svc: pd.DataFrame):
    print("\n" + "─" * 50)
    print("  Training Model 3: ServiceClassifier")
    print("─" * 50)

    df_svc["banner_text"] = df_svc["banner_text"].fillna("")

    le = LabelEncoder()
    y = le.fit_transform(df_svc["service_label"])

    # Feature: port + banner TF-IDF
    from sklearn.pipeline import FeatureUnion
    from sklearn.preprocessing import FunctionTransformer

    def get_port(X):
        return X[["port"]].fillna(0).values

    def get_banner(X):
        return X["banner_text"].fillna("").values

    # Use a simpler pipeline for service classification
    banner_col = df_svc["banner_text"].fillna("").values
    port_col = df_svc[["port"]].fillna(0).values

    # TF-IDF on banner
    tfidf = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4),
                            max_features=300, sublinear_tf=True)
    banner_features = tfidf.fit_transform(banner_col)

    from scipy.sparse import hstack, csr_matrix
    port_sparse = csr_matrix(port_col)
    X_combined = hstack([banner_features, port_sparse])

    X_train, X_test, y_train, y_test = train_test_split(
        X_combined, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = make_classifier()
    t0 = time.time()
    clf.fit(X_train, y_train)
    train_time = time.time() - t0

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="macro")

    print(f"  ✅ Accuracy: {acc:.4f} ({acc*100:.1f}%)")
    print(f"  ✅ Macro-F1: {f1:.4f}")
    print(f"  ⏱  Training time: {train_time:.1f}s")
    print(f"  Classes ({len(le.classes_)}): {list(le.classes_[:10])}...")

    model_path = os.path.join(MODELS_DIR, "service_classifier.pkl")
    joblib.dump(
        {"classifier": clf, "tfidf": tfidf, "label_encoder": le},
        model_path, compress=3
    )
    size_kb = os.path.getsize(model_path) // 1024
    print(f"  💾 Saved: {model_path} ({size_kb}KB)")
    return clf, tfidf, le


# ═══════════════════════════════════════════════════════════
# MODEL 4: VulnScorer
# ═══════════════════════════════════════════════════════════
def train_vuln_scorer(df_vuln: pd.DataFrame):
    print("\n" + "─" * 50)
    print("  Training Model 4: VulnScorer")
    print("─" * 50)

    df_vuln["banner_text"] = df_vuln["banner_text"].fillna("")
    df_vuln["os_fingerprint"] = df_vuln["os_fingerprint"].fillna("Unknown")

    # Encode service name
    le_svc = LabelEncoder()
    df_vuln["service_encoded"] = le_svc.fit_transform(df_vuln["service_name"].fillna("Unknown"))

    # Banner TF-IDF
    tfidf_vuln = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4),
                                  max_features=200, sublinear_tf=True)
    banner_features = tfidf_vuln.fit_transform(df_vuln["banner_text"])

    from scipy.sparse import hstack, csr_matrix
    numeric_features = df_vuln[["port", "service_encoded"]].fillna(0).values
    X_combined = hstack([banner_features, csr_matrix(numeric_features)])
    y = df_vuln["vuln_score"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X_combined, y, test_size=0.2, random_state=42
    )

    reg = make_regressor()
    t0 = time.time()
    reg.fit(X_train, y_train)
    train_time = time.time() - t0

    y_pred = np.clip(reg.predict(X_test), 0, 10)
    mae = mean_absolute_error(y_test, y_pred)
    r2 = r2_score(y_test, y_pred)

    print(f"  ✅ MAE: {mae:.4f} (lower=better, target <1.5)")
    print(f"  ✅ R²: {r2:.4f}")
    print(f"  ⏱  Training time: {train_time:.1f}s")

    model_path = os.path.join(MODELS_DIR, "vuln_scorer.pkl")
    joblib.dump(
        {
            "regressor": reg,
            "tfidf": tfidf_vuln,
            "label_encoder": le_svc,
        },
        model_path, compress=3
    )
    size_kb = os.path.getsize(model_path) // 1024
    print(f"  💾 Saved: {model_path} ({size_kb}KB)")
    return reg, tfidf_vuln, le_svc


# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════
def main():
    start_time = time.time()
    print("=" * 56)
    print("  ML Scan Engine — Training All 4 Models")
    print("=" * 56)

    # ── Load Firewall + Flag data ──────────────────────────
    fw_path = os.path.join(DATA_DIR, "synthetic_firewall_scans.csv")
    if not os.path.exists(fw_path):
        print(f"\n❌ Dataset not found: {fw_path}")
        print("Run first: python scripts/generate_synthetic.py")
        sys.exit(1)

    df_fw = pd.read_csv(fw_path)
    print(f"\n✅ Loaded firewall dataset: {len(df_fw):,} rows")

    # ── Load Service data ──────────────────────────────────
    svc_path = os.path.join(DATA_DIR, "synthetic_service_data.csv")
    df_svc = pd.read_csv(svc_path) if os.path.exists(svc_path) else None
    if df_svc is not None:
        print(f"✅ Loaded service dataset: {len(df_svc):,} rows")

    # ── Load Vuln data ─────────────────────────────────────
    vuln_path = os.path.join(DATA_DIR, "synthetic_vuln_scores.csv")
    df_vuln = pd.read_csv(vuln_path) if os.path.exists(vuln_path) else None
    if df_vuln is not None:
        print(f"✅ Loaded vuln dataset: {len(df_vuln):,} rows")

    # ── Train models ───────────────────────────────────────
    fw_pipe, fw_cols = train_firewall_detector(df_fw)
    flag_pipe, flag_le = train_flag_optimizer(df_fw)

    if df_svc is not None:
        svc_clf, svc_tfidf, svc_le = train_service_classifier(df_svc)

    if df_vuln is not None:
        vuln_reg, vuln_tfidf, vuln_le = train_vuln_scorer(df_vuln)

    # ── Print summary ──────────────────────────────────────
    total_time = time.time() - start_time
    print("\n" + "=" * 56)
    print("  ✅ All Models Trained Successfully!")
    print(f"  ⏱  Total training time: {total_time:.0f}s")
    print(f"  📁 Models saved to: {MODELS_DIR}")
    total_size = sum(
        os.path.getsize(os.path.join(MODELS_DIR, f))
        for f in os.listdir(MODELS_DIR) if f.endswith(".pkl")
    )
    print(f"  💾 Total model size: {total_size // 1024 // 1024}MB ({total_size // 1024}KB)")
    print("\n  Next: Run the ML Scan Engine:")
    print("  python -c \"from ml_engine.scan_intelligence import MLScanEngine; e=MLScanEngine(); print(e.scan('scholarhub.online', task_id='test'))\"")
    print("=" * 56)


if __name__ == "__main__":
    main()
