"""
ML Engine Feature Engineering
"""
import pandas as pd
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

class NetworkFeatureExtractor(BaseEstimator, TransformerMixin):
    """Derives domain-specific features from raw network scan data."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        df = pd.DataFrame(X).copy()

        def ttl_hop_count(ttl):
            if pd.isna(ttl) or ttl <= 0:
                return 10
            base_ttls = np.array([64, 128, 255])
            deltas = base_ttls - ttl
            valid = deltas[deltas >= 0]
            return int(np.min(valid)) if len(valid) > 0 else 10

        # TTL features
        if "ttl" in df.columns:
            df["ttl_hop_count"] = df["ttl"].apply(ttl_hop_count)
            df["ttl_class"] = pd.cut(
                df["ttl"], bins=[0, 64, 128, 255], labels=[0, 1, 2], right=True
            ).astype(float)
        else:
            df["ttl_hop_count"] = 10
            df["ttl_class"] = 0

        # Port features
        if "port" in df.columns:
            df["is_privileged_port"] = (df["port"] < 1024).astype(int)
            df["is_web_port"] = df["port"].isin([80, 443, 8080, 8443]).astype(int)
            df["is_db_port"] = df["port"].isin([3306, 5432, 1433, 1521, 27017, 6379]).astype(int)
        else:
            df["is_privileged_port"] = 0
            df["is_web_port"] = 0
            df["is_db_port"] = 0

        # RTT features
        if "rtt_ms" in df.columns:
            df["rtt_log"] = np.log1p(df["rtt_ms"].fillna(0))
            df["is_high_latency"] = (df["rtt_ms"] > 500).astype(int)
            df["is_timeout_rtt"] = (df["rtt_ms"] > 2000).astype(int)
        else:
            df["rtt_log"] = 0
            df["is_high_latency"] = 0
            df["is_timeout_rtt"] = 0

        # Firewall ratio features
        if "filtered_port_count" in df.columns and "total_ports_scanned" in df.columns:
            df["filtered_ratio"] = (
                df["filtered_port_count"] / (df["total_ports_scanned"].clip(1))
            ).fillna(0)
        else:
            df["filtered_ratio"] = 0

        numeric_cols = [
            "ttl_hop_count", "ttl_class", "is_privileged_port", "is_web_port",
            "is_db_port", "rtt_log", "is_high_latency", "is_timeout_rtt",
            "filtered_ratio"
        ]
        for col in ["port", "rtt_ms", "ttl", "icmp_blocked", "rst_received",
                    "filtered_port_count", "open_port_count", "total_ports_scanned"]:
            if col in df.columns:
                numeric_cols.append(col)
                df[col] = df[col].fillna(0)

        return df[list(dict.fromkeys(numeric_cols))].fillna(0).values
