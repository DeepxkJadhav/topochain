"""
Sample repository generation and benchmark dataset loader for TopoChain.
"""

from pathlib import Path
from typing import Dict, Any


class BenchmarkRepoGenerator:
    """
    Creates realistic sample microservice codebases for testing, training, and benchmarking.
    """

    @staticmethod
    def create_sample_service(target_dir: str) -> str:
        target = Path(target_dir)
        target.mkdir(parents=True, exist_ok=True)

        # requirements.txt
        reqs = target / "requirements.txt"
        reqs.write_text("fastapi>=0.95.0\npydantic>=1.10.0\nrequests>=2.28.0\n", encoding="utf-8")

        # auth.py
        auth = target / "auth.py"
        auth.write_text('''"""Authentication and Token Management Module."""
import hashlib
import time

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_token(token: str, secret: str) -> bool:
    if not token or len(token) < 16:
        return False
    expected = hashlib.sha256((secret + "token_salt").encode()).hexdigest()
    return token.startswith(expected[:12])

def generate_session(user_id: str) -> dict:
    ts = int(time.time())
    return {"user_id": user_id, "created_at": ts, "valid": True}
''', encoding="utf-8")

        # database.py
        db = target / "database.py"
        db.write_text('''"""Database abstraction and query simulation."""

class DatabaseClient:
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.connected = False

    def connect(self):
        self.connected = True
        return self

    def query_user(self, username: str) -> dict:
        if not self.connected:
            self.connect()
        return {"id": "usr_99", "username": username, "role": "member"}

    def write_audit_log(self, action: str, user_id: str):
        pass
''', encoding="utf-8")

        # api.py
        api = target / "api.py"
        api.write_text('''"""API route controllers and business logic."""
from auth import verify_token, generate_session
from database import DatabaseClient

db_client = DatabaseClient("sqlite:///:memory:")

def handle_login(username: str, token: str) -> dict:
    if verify_token(token, "default_secret"):
        user = db_client.query_user(username)
        session = generate_session(user["id"])
        db_client.write_audit_log("login", user["id"])
        return {"status": "ok", "session": session}
    return {"status": "unauthorized"}

def handle_user_profile(user_id: str, token: str) -> dict:
    if verify_token(token, "default_secret"):
        return {"user_id": user_id, "data": "profile_info"}
    return {"status": "denied"}
''', encoding="utf-8")

        return str(target)
