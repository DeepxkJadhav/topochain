"""
Dedicated Dependency Intelligence Subsystem for TopoChain.
Analyzes package manifests, lockfiles, lifecycle scripts, name similarity, and dependency confusion.
Supports: npm, Python (pip/pyproject/poetry), Go, and Rust (Cargo).
"""

import os
import re
import json
import tomllib
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple

from topochain.core.extractor.base import DependencyEntity


@dataclass
class DependencyChangeEvidence:
    dependency: str
    change: str  # "added", "removed", "modified", "unpinned", "existing"
    risk: str  # "low", "medium", "high", "critical"
    reasons: List[str] = field(default_factory=list)
    version: str = "*"
    source_file: str = ""
    capabilities: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dependency": self.dependency,
            "change": self.change,
            "risk": self.risk,
            "reasons": self.reasons,
            "version": self.version,
            "source_file": self.source_file,
            "capabilities": self.capabilities,
        }


@dataclass
class DependencyIntelligenceResult:
    dependencies: List[DependencyEntity] = field(default_factory=list)
    evidence: List[DependencyChangeEvidence] = field(default_factory=list)
    risk_score: float = 0.0  # 0.0 to 1.0
    lifecycle_scripts: List[Dict[str, str]] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    ecosystems_detected: List[str] = field(default_factory=list)

    def summary(self) -> Dict[str, Any]:
        return {
            "total_dependencies": len(self.dependencies),
            "risk_score": round(self.risk_score, 3),
            "evidence_count": len(self.evidence),
            "lifecycle_scripts_count": len(self.lifecycle_scripts),
            "ecosystems": self.ecosystems_detected,
            "findings": self.findings,
        }


class DependencyExtractor:
    """
    Multi-ecosystem dependency parser and intelligence analyzer.
    """

    POPULAR_PACKAGES = {
        # Python
        "requests", "urllib3", "numpy", "scipy", "pandas", "flask", "django",
        "fastapi", "pytest", "cryptography", "boto3", "torch", "tensorflow",
        "celery", "pydantic", "httpx", "aiohttp", "sqlalchemy", "redis",
        # npm
        "express", "lodash", "react", "vue", "axios", "chalk", "debug",
        "moment", "commander", "webpack", "babel", "rxjs", "inquirer",
        "typescript", "next", "eslint", "prettier", "jest",
        # Rust / Cargo
        "serde", "tokio", "syn", "rand", "regex", "actix", "clap", "anyhow",
        # Go
        "gin", "logrus", "fiber", "mux", "viper", "cobra", "testify"
    }

    SUSPICIOUS_LIFECYCLE_COMMANDS = {
        "curl", "wget", "bash", "sh", "powershell", "cmd.exe", "eval",
        "node -e", "python -c", "http", "nc ", "netcat", "base64", "chmod +x"
    }

    def __init__(self, internal_namespaces: Optional[List[str]] = None):
        self.internal_namespaces = [ns.lower() for ns in (internal_namespaces or ["internal", "corp", "private", "infra"])]

    def extract_from_directory(self, base_dir: str) -> List[DependencyEntity]:
        """
        Backward-compatible method returning flat list of DependencyEntities.
        """
        intel = self.analyze_directory(base_dir)
        return intel.dependencies

    def analyze_directory(
        self,
        base_dir: str,
        previous_deps: Optional[List[DependencyEntity]] = None
    ) -> DependencyIntelligenceResult:
        """
        Deep dependency intelligence extraction across supported package ecosystems.
        """
        base = Path(base_dir).resolve()
        deps: List[DependencyEntity] = []
        lifecycle_scripts: List[Dict[str, str]] = []
        ecosystems = set()

        # 1. Python ecosystem
        for req_file in base.glob("**/requirements*.txt"):
            if self._is_safe_file(req_file, base):
                parsed = self._parse_requirements_txt(str(req_file))
                deps.extend(parsed)
                ecosystems.add("python/pip")

        for pyproj in base.glob("**/pyproject.toml"):
            if self._is_safe_file(pyproj, base):
                parsed = self._parse_pyproject_toml(str(pyproj))
                deps.extend(parsed)
                ecosystems.add("python/pyproject")

        for poetry_lock in base.glob("**/poetry.lock"):
            if self._is_safe_file(poetry_lock, base):
                parsed = self._parse_poetry_lock(str(poetry_lock))
                deps.extend(parsed)
                ecosystems.add("python/poetry")

        # 2. npm ecosystem
        for pkg_json in base.glob("**/package.json"):
            if self._is_safe_file(pkg_json, base) and "node_modules" not in str(pkg_json):
                parsed, scripts = self._parse_package_json(str(pkg_json))
                deps.extend(parsed)
                lifecycle_scripts.extend(scripts)
                ecosystems.add("npm")

        for pkg_lock in base.glob("**/package-lock.json"):
            if self._is_safe_file(pkg_lock, base) and "node_modules" not in str(pkg_lock):
                parsed = self._parse_package_lock_json(str(pkg_lock))
                deps.extend(parsed)
                ecosystems.add("npm/lockfile")

        # 3. Rust ecosystem
        for cargo_toml in base.glob("**/Cargo.toml"):
            if self._is_safe_file(cargo_toml, base) and "target" not in str(cargo_toml):
                parsed = self._parse_cargo_toml(str(cargo_toml))
                deps.extend(parsed)
                ecosystems.add("rust/cargo")

        for cargo_lock in base.glob("**/Cargo.lock"):
            if self._is_safe_file(cargo_lock, base) and "target" not in str(cargo_lock):
                parsed = self._parse_cargo_lock(str(cargo_lock))
                deps.extend(parsed)
                ecosystems.add("rust/cargolock")

        # 4. Go ecosystem
        for gomod in base.glob("**/go.mod"):
            if self._is_safe_file(gomod, base):
                parsed = self._parse_go_mod(str(gomod))
                deps.extend(parsed)
                ecosystems.add("go")

        # Deduplicate dependencies by name + source_file
        unique_deps: Dict[Tuple[str, str], DependencyEntity] = {}
        for d in deps:
            key = (d.name.lower(), d.source_file)
            if key not in unique_deps:
                unique_deps[key] = d
            else:
                unique_deps[key].suspicious_flags.extend(d.suspicious_flags)
        deduped_deps = list(unique_deps.values())

        # Generate structured delta evidence and risk scoring
        evidence, risk_score, findings = self._evaluate_evidence(
            current_deps=deduped_deps,
            previous_deps=previous_deps,
            lifecycle_scripts=lifecycle_scripts
        )

        return DependencyIntelligenceResult(
            dependencies=deduped_deps,
            evidence=evidence,
            risk_score=risk_score,
            lifecycle_scripts=lifecycle_scripts,
            findings=findings,
            ecosystems_detected=sorted(list(ecosystems))
        )

    @staticmethod
    def _is_safe_file(path: Path, base: Path) -> bool:
        """Prevent path traversal and ignore cache directories."""
        try:
            resolved = path.resolve()
            if not str(resolved).startswith(str(base)):
                return False
            parts = resolved.parts
            return not any(p in {".git", ".venv", "venv", "node_modules", "target", "build", "dist"} for p in parts)
        except Exception:
            return False

    def _parse_requirements_txt(self, file_path: str) -> List[DependencyEntity]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=><~^!].*)?$", line)
                    if m:
                        pkg_name = m.group(1).lower()
                        ver = m.group(2) or "*"
                        flags = self._check_package_red_flags(pkg_name)
                        deps.append(DependencyEntity(
                            name=pkg_name,
                            version_spec=ver,
                            source_file=file_path,
                            suspicious_flags=flags
                        ))
        except Exception:
            pass
        return deps

    def _parse_package_json(self, file_path: str) -> Tuple[List[DependencyEntity], List[Dict[str, str]]]:
        deps = []
        scripts = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Inspect lifecycle scripts (postinstall, preinstall, etc.)
            raw_scripts = data.get("scripts", {})
            for hook in ["preinstall", "install", "postinstall", "preuninstall"]:
                if hook in raw_scripts:
                    cmd = str(raw_scripts[hook])
                    is_suspicious = any(p in cmd.lower() for p in self.SUSPICIOUS_LIFECYCLE_COMMANDS)
                    scripts.append({
                        "hook": hook,
                        "command": cmd,
                        "is_suspicious": is_suspicious,
                        "source_file": file_path
                    })

            for name, ver in data.get("dependencies", {}).items():
                flags = self._check_package_red_flags(name)
                deps.append(DependencyEntity(
                    name=name.lower(),
                    version_spec=str(ver),
                    is_dev=False,
                    source_file=file_path,
                    suspicious_flags=flags
                ))

            for name, ver in data.get("devDependencies", {}).items():
                flags = self._check_package_red_flags(name)
                deps.append(DependencyEntity(
                    name=name.lower(),
                    version_spec=str(ver),
                    is_dev=True,
                    source_file=file_path,
                    suspicious_flags=flags
                ))
        except Exception:
            pass
        return deps, scripts

    def _parse_package_lock_json(self, file_path: str) -> List[DependencyEntity]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            packages = data.get("packages", {})
            for pkg_path, details in packages.items():
                if not pkg_path:
                    continue
                name = pkg_path.replace("node_modules/", "").strip()
                if name:
                    ver = details.get("version", "*")
                    flags = self._check_package_red_flags(name)
                    deps.append(DependencyEntity(
                        name=name.lower(),
                        version_spec=ver,
                        is_direct=not details.get("dev", False),
                        source_file=file_path,
                        suspicious_flags=flags
                    ))
        except Exception:
            pass
        return deps

    def _parse_pyproject_toml(self, file_path: str) -> List[DependencyEntity]:
        deps = []
        try:
            with open(file_path, "rb") as f:
                data = tomllib.load(f)
            project = data.get("project", {})
            for item in project.get("dependencies", []):
                m = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:[>=<~!].*)?$", item.strip())
                if m:
                    pkg = m.group(1).lower()
                    flags = self._check_package_red_flags(pkg)
                    deps.append(DependencyEntity(
                        name=pkg,
                        version_spec="*",
                        source_file=file_path,
                        suspicious_flags=flags
                    ))
            tool_poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            for pkg, ver in tool_poetry.items():
                if pkg.lower() != "python":
                    flags = self._check_package_red_flags(pkg)
                    deps.append(DependencyEntity(
                        name=pkg.lower(),
                        version_spec=str(ver),
                        source_file=file_path,
                        suspicious_flags=flags
                    ))
        except Exception:
            pass
        return deps

    def _parse_poetry_lock(self, file_path: str) -> List[DependencyEntity]:
        deps = []
        try:
            with open(file_path, "rb") as f:
                data = tomllib.load(f)
            for pkg_info in data.get("package", []):
                name = pkg_info.get("name")
                ver = pkg_info.get("version", "*")
                if name:
                    flags = self._check_package_red_flags(name)
                    deps.append(DependencyEntity(
                        name=name.lower(),
                        version_spec=ver,
                        source_file=file_path,
                        suspicious_flags=flags
                    ))
        except Exception:
            pass
        return deps

    def _parse_cargo_toml(self, file_path: str) -> List[DependencyEntity]:
        deps = []
        try:
            with open(file_path, "rb") as f:
                data = tomllib.load(f)
            for dep_section in ["dependencies", "dev-dependencies", "build-dependencies"]:
                for name, details in data.get(dep_section, {}).items():
                    ver = details if isinstance(details, str) else details.get("version", "*")
                    flags = self._check_package_red_flags(name)
                    deps.append(DependencyEntity(
                        name=name.lower(),
                        version_spec=str(ver),
                        is_dev=(dep_section == "dev-dependencies"),
                        source_file=file_path,
                        suspicious_flags=flags
                    ))
        except Exception:
            pass
        return deps

    def _parse_cargo_lock(self, file_path: str) -> List[DependencyEntity]:
        deps = []
        try:
            with open(file_path, "rb") as f:
                data = tomllib.load(f)
            for pkg_info in data.get("package", []):
                name = pkg_info.get("name")
                ver = pkg_info.get("version", "*")
                if name:
                    flags = self._check_package_red_flags(name)
                    deps.append(DependencyEntity(
                        name=name.lower(),
                        version_spec=ver,
                        source_file=file_path,
                        suspicious_flags=flags
                    ))
        except Exception:
            pass
        return deps

    def _parse_go_mod(self, file_path: str) -> List[DependencyEntity]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    m = re.match(r"^([a-zA-Z0-9_\-\./]+)\s+(v[0-9\.\-a-zA-Z]+)", line)
                    if m and not line.startswith("module"):
                        name = m.group(1).lower()
                        ver = m.group(2)
                        flags = self._check_package_red_flags(name)
                        deps.append(DependencyEntity(
                            name=name,
                            version_spec=ver,
                            source_file=file_path,
                            suspicious_flags=flags
                        ))
        except Exception:
            pass
        return deps

    def _check_package_red_flags(self, name: str) -> List[str]:
        flags = []
        clean = name.replace("-", "").replace("_", "").lower()
        sub_name = clean.replace("0", "o").replace("1", "l").replace("3", "e")

        # 1. Typosquatting
        for pop in self.POPULAR_PACKAGES:
            clean_pop = pop.replace("-", "").replace("_", "").lower()
            if clean == clean_pop:
                continue
            if sub_name == clean_pop:
                flags.append(f"typosquat_leetspeak_{pop}")
                continue
            d = self._damerau_levenshtein(clean, clean_pop)
            if d == 1 or (d == 2 and len(clean_pop) >= 6):
                flags.append(f"possible_typosquat_of_{pop}")

        # 2. Dependency confusion
        for ns in self.internal_namespaces:
            if ns in clean and not name.startswith("@") and "/" not in name:
                flags.append(f"possible_dependency_confusion_{ns}")

        return flags

    def _evaluate_evidence(
        self,
        current_deps: List[DependencyEntity],
        previous_deps: Optional[List[DependencyEntity]],
        lifecycle_scripts: List[Dict[str, str]]
    ) -> Tuple[List[DependencyChangeEvidence], float, List[str]]:
        evidence: List[DependencyChangeEvidence] = []
        findings: List[str] = []
        total_risk = 0.0

        is_diff_comparison = (previous_deps is not None)
        prev_map = {d.name.lower(): d for d in (previous_deps or [])}
        cur_map = {d.name.lower(): d for d in current_deps}

        # Check added & modified dependencies
        for name, dep in cur_map.items():
            reasons = []
            risk_level = "low"
            change_type = "added" if (is_diff_comparison and name not in prev_map) else "existing"

            if change_type == "added":
                reasons.append("New dependency introduced into manifest")
                total_risk += 0.10

            # Typosquatting flags
            for flag in dep.suspicious_flags:
                if "typosquat" in flag:
                    reasons.append(f"Package name similarity: {flag}")
                    risk_level = "high"
                    total_risk += 0.65
                elif "dependency_confusion" in flag:
                    reasons.append(f"Unscoped internal naming pattern: {flag}")
                    risk_level = "high"
                    total_risk += 0.50

            if reasons:
                evidence.append(DependencyChangeEvidence(
                    dependency=name,
                    change=change_type,
                    risk=risk_level,
                    reasons=reasons,
                    version=dep.version_spec,
                    source_file=dep.source_file,
                    capabilities=["network"] if "requests" in name or "http" in name else []
                ))
                findings.extend([f"[{dep.name}] {r}" for r in reasons])

        # Check removed dependencies
        if previous_deps:
            for name, dep in prev_map.items():
                if name not in cur_map:
                    evidence.append(DependencyChangeEvidence(
                        dependency=name,
                        change="removed",
                        risk="low",
                        reasons=["Dependency removed from project manifests"],
                        version=dep.version_spec,
                        source_file=dep.source_file
                    ))

        # Check lifecycle scripts
        for script in lifecycle_scripts:
            if script.get("is_suspicious"):
                total_risk += 0.70
                findings.append(f"Suspicious lifecycle script detected in {script.get('hook')}: {script.get('command')}")
                evidence.append(DependencyChangeEvidence(
                    dependency="package.json#scripts",
                    change="modified",
                    risk="critical",
                    reasons=[f"Untrusted lifecycle script in {script.get('hook')}: {script.get('command')}"],
                    source_file=script.get("source_file", "")
                ))

        normalized_risk = min(1.0, total_risk)
        return evidence, normalized_risk, findings

    def _damerau_levenshtein(self, s1: str, s2: str) -> int:
        d = {}
        len1 = len(s1)
        len2 = len(s2)
        for i in range(-1, len1 + 1):
            d[(i, -1)] = i + 1
        for j in range(-1, len2 + 1):
            d[(-1, j)] = j + 1

        for i in range(len1):
            for j in range(len2):
                cost = 0 if s1[i] == s2[j] else 1
                d[(i, j)] = min(
                    d[(i - 1, j)] + 1,
                    d[(i, j - 1)] + 1,
                    d[(i - 1, j - 1)] + cost
                )
                if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                    d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)

        return d[(len1 - 1, len2 - 1)]
