"""
SQLite database and storage manager for TopoChain baselines and commit topologies.
"""

import sqlite3
import json
import io
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager
from datetime import datetime, timezone
import numpy as np


class StorageEngine:
    """
    Manages local SQLite database for topological state, embeddings, and baseline statistics.
    Ensures safe connection closure across all platforms including Windows.
    """

    def __init__(self, db_path: str = ".topochain/topochain.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self._connection() as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT,
                baseline_commit TEXT,
                created_at TIMESTAMP
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS commit_topology (
                commit_hash TEXT PRIMARY KEY,
                project_id TEXT,
                persistence_image BLOB,
                latent_embedding BLOB,
                drift_score REAL,
                is_anomaly BOOLEAN,
                diagnostics_json TEXT,
                timestamp TIMESTAMP,
                FOREIGN KEY(project_id) REFERENCES projects(id)
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS baseline_stats (
                project_id TEXT PRIMARY KEY,
                drift_mean REAL,
                drift_variance REAL,
                sample_count INTEGER DEFAULT 0,
                updated_at TIMESTAMP
            );
            """)
            conn.commit()

    @staticmethod
    def _serialize_array(arr: np.ndarray) -> bytes:
        out = io.BytesIO()
        np.save(out, arr)
        return out.getvalue()

    @staticmethod
    def _deserialize_array(data: bytes) -> np.ndarray:
        return np.load(io.BytesIO(data))

    def get_or_create_project(self, project_id: str, name: Optional[str] = None) -> Dict[str, Any]:
        with self._connection() as conn:
            cur = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
            row = cur.fetchone()
            if row:
                return dict(row)

            now = datetime.now(timezone.utc).isoformat()
            p_name = name or project_id
            conn.execute(
                "INSERT INTO projects (id, name, baseline_commit, created_at) VALUES (?, ?, ?, ?)",
                (project_id, p_name, None, now)
            )
            conn.execute(
                "INSERT OR REPLACE INTO baseline_stats (project_id, drift_mean, drift_variance, sample_count, updated_at) VALUES (?, ?, ?, ?, ?)",
                (project_id, 0.15, 0.005, 0, now)
            )
            conn.commit()
            return {"id": project_id, "name": p_name, "baseline_commit": None, "created_at": now}

    def record_commit(
        self,
        commit_hash: str,
        project_id: str,
        persistence_image: np.ndarray,
        latent_embedding: np.ndarray,
        drift_score: float,
        is_anomaly: bool,
        diagnostics: Optional[Dict[str, Any]] = None
    ) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        img_blob = self._serialize_array(persistence_image)
        emb_blob = self._serialize_array(latent_embedding)
        diag_str = json.dumps(diagnostics or {})

        with self._connection() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO commit_topology
            (commit_hash, project_id, persistence_image, latent_embedding, drift_score, is_anomaly, diagnostics_json, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (commit_hash, project_id, img_blob, emb_blob, drift_score, is_anomaly, diag_str, now))
            conn.commit()
        return True

    def get_latest_commit(self, project_id: str) -> Optional[Dict[str, Any]]:
        with self._connection() as conn:
            cur = conn.execute(
                "SELECT * FROM commit_topology WHERE project_id = ? ORDER BY timestamp DESC LIMIT 1",
                (project_id,)
            )
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_commit_dict(row)

    def get_commit(self, commit_hash: str) -> Optional[Dict[str, Any]]:
        with self._connection() as conn:
            cur = conn.execute(
                "SELECT * FROM commit_topology WHERE commit_hash = ?",
                (commit_hash,)
            )
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_commit_dict(row)

    def get_history(self, project_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            cur = conn.execute(
                "SELECT * FROM commit_topology WHERE project_id = ? ORDER BY timestamp DESC LIMIT ?",
                (project_id, limit)
            )
            return [self._row_to_commit_dict(r) for r in cur.fetchall()]

    def get_baseline_stats(self, project_id: str) -> Tuple[float, float, int]:
        with self._connection() as conn:
            cur = conn.execute(
                "SELECT drift_mean, drift_variance, sample_count FROM baseline_stats WHERE project_id = ?",
                (project_id,)
            )
            row = cur.fetchone()
            if row:
                return float(row["drift_mean"]), float(row["drift_variance"]), int(row["sample_count"] or 0)
            return 0.15, 0.005, 0

    def update_baseline_stats(self, project_id: str, drift_mean: float, drift_variance: float, sample_count: int = 1):
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO baseline_stats
            (project_id, drift_mean, drift_variance, sample_count, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """, (project_id, float(drift_mean), max(0.001, float(drift_variance)), sample_count, now))
            conn.commit()

    def _row_to_commit_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["persistence_image"] = self._deserialize_array(d["persistence_image"])
        d["latent_embedding"] = self._deserialize_array(d["latent_embedding"])
        d["diagnostics"] = json.loads(d["diagnostics_json"] or "{}")
        del d["diagnostics_json"]
        return d
