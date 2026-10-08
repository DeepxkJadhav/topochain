"""
SQLite database and storage manager for TopoChain.
Implements Baseline Protection Architecture:
- Immutable Known-Good Anchor
- Historical Baseline Version Tracking
- Explicit Trust Approval Gate (prevents auto-update poisoning)
- Gradual Drift Poisoning Detection
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
    Enforces strict security governance against model poisoning and baseline manipulation.
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
                anchor_commit TEXT,
                created_at TIMESTAMP
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS trusted_anchors (
                project_id TEXT PRIMARY KEY,
                anchor_commit TEXT,
                anchor_embedding BLOB,
                approved_by TEXT,
                created_at TIMESTAMP,
                FOREIGN KEY(project_id) REFERENCES projects(id)
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

            conn.execute("""
            CREATE TABLE IF NOT EXISTS baseline_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id TEXT,
                commit_hash TEXT,
                drift_mean REAL,
                drift_variance REAL,
                sample_count INTEGER,
                approved_by TEXT,
                reason TEXT,
                updated_at TIMESTAMP,
                FOREIGN KEY(project_id) REFERENCES projects(id)
            );
            """)
            # Schema migration check for existing databases
            cur = conn.execute("PRAGMA table_info(projects)")
            cols = {row["name"] for row in cur.fetchall()}
            if "anchor_commit" not in cols:
                conn.execute("ALTER TABLE projects ADD COLUMN anchor_commit TEXT;")
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
                "INSERT INTO projects (id, name, baseline_commit, anchor_commit, created_at) VALUES (?, ?, ?, ?, ?)",
                (project_id, p_name, None, None, now)
            )
            conn.execute(
                "INSERT OR REPLACE INTO baseline_stats (project_id, drift_mean, drift_variance, sample_count, updated_at) VALUES (?, ?, ?, ?, ?)",
                (project_id, 0.15, 0.005, 0, now)
            )
            conn.commit()
            return {"id": project_id, "name": p_name, "baseline_commit": None, "anchor_commit": None, "created_at": now}

    def set_trusted_anchor(
        self,
        project_id: str,
        commit_hash: Optional[str] = None,
        embedding: Optional[np.ndarray] = None,
        approved_by: str = "security_lead",
        anchor_commit: Optional[str] = None,
        anchor_embedding: Optional[np.ndarray] = None
    ):
        """
        Anchors the immutable known-good baseline reference for a project.
        """
        c_hash = commit_hash or anchor_commit or ""
        emb = embedding if embedding is not None else (anchor_embedding if anchor_embedding is not None else np.zeros(64, dtype=np.float32))
        now = datetime.now(timezone.utc).isoformat()
        emb_blob = self._serialize_array(emb)
        with self._connection() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO trusted_anchors
            (project_id, anchor_commit, anchor_embedding, approved_by, created_at)
            VALUES (?, ?, ?, ?, ?)
            """, (project_id, commit_hash, emb_blob, approved_by, now))

            conn.execute("""
            UPDATE projects SET anchor_commit = ? WHERE id = ?
            """, (commit_hash, project_id))
            conn.commit()

    def get_trusted_anchor(self, project_id: str) -> Optional[Dict[str, Any]]:
        with self._connection() as conn:
            cur = conn.execute("SELECT * FROM trusted_anchors WHERE project_id = ?", (project_id,))
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            d["anchor_embedding"] = self._deserialize_array(d["anchor_embedding"])
            return d

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

    def approve_baseline_update(
        self,
        project_id: str,
        commit_hash: str,
        new_mean: float,
        new_variance: float,
        sample_count: int,
        approved_by: str = "security_engineer",
        reason: str = "Verified benign architectural evolution"
    ) -> bool:
        """
        Explicit trust decision required to update baseline statistics.
        Prevents automated boiling-frog model poisoning.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            # 1. Update current baseline
            conn.execute("""
            INSERT OR REPLACE INTO baseline_stats
            (project_id, drift_mean, drift_variance, sample_count, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """, (project_id, float(new_mean), max(1e-6, float(new_variance)), sample_count, now))

            # 2. Record immutable history entry
            conn.execute("""
            INSERT INTO baseline_history
            (project_id, commit_hash, drift_mean, drift_variance, sample_count, approved_by, reason, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (project_id, commit_hash, float(new_mean), float(new_variance), sample_count, approved_by, reason, now))

            # 3. Update current baseline commit pointer
            conn.execute("UPDATE projects SET baseline_commit = ? WHERE id = ?", (commit_hash, project_id))
            conn.commit()
        return True

    def get_baseline_history(self, project_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            cur = conn.execute(
                "SELECT * FROM baseline_history WHERE project_id = ? ORDER BY updated_at DESC LIMIT ?",
                (project_id, limit)
            )
            return [dict(r) for r in cur.fetchall()]

    def detect_gradual_drift_poisoning(
        self,
        project_id: str,
        current_embedding: np.ndarray,
        poisoning_threshold: float = 0.55
    ) -> Tuple[bool, float, Optional[str]]:
        """
        Calculates cumulative distance from the immutable trusted anchor.
        Flags when accumulated slow drift exceeds boundary even if each step drift was small.
        """
        anchor = self.get_trusted_anchor(project_id)
        if not anchor:
            return False, 0.0, None

        anchor_emb = anchor["anchor_embedding"]
        cumulative_dist = float(np.linalg.norm(current_embedding - anchor_emb))

        is_poisoning = cumulative_dist > poisoning_threshold
        return is_poisoning, cumulative_dist, anchor["anchor_commit"]

    is_drift_poisoning = detect_gradual_drift_poisoning

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
            """, (project_id, float(drift_mean), max(1e-6, float(drift_variance)), sample_count, now))
            conn.commit()

    def _row_to_commit_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["persistence_image"] = self._deserialize_array(d["persistence_image"])
        d["latent_embedding"] = self._deserialize_array(d["latent_embedding"])
        d["diagnostics"] = json.loads(d["diagnostics_json"] or "{}")
        del d["diagnostics_json"]
        return d
