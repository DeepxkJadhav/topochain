"""
Dedicated Semantic Analysis Subsystem for TopoChain.
Analyzes code semantics, sensitive API capabilities, credential access, auth logic, and data exfiltration patterns.
Operates deterministically without requiring cloud LLM dependencies (LLMs treated as optional evidence providers).
"""

import re
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple


@dataclass
class SemanticEvidence:
    category: str
    symbol: str
    file_path: str
    line_number: int
    severity: str  # "low", "medium", "high", "critical"
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "symbol": self.symbol,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "severity": self.severity,
            "description": self.description,
        }


@dataclass
class SemanticAnalysisResult:
    risk_score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    capabilities_detected: List[str] = field(default_factory=list)
    evidence: List[SemanticEvidence] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)

    def summary(self) -> Dict[str, Any]:
        return {
            "risk_score": round(self.risk_score, 3),
            "confidence": round(self.confidence, 3),
            "capabilities": self.capabilities_detected,
            "evidence_count": len(self.evidence),
            "findings": self.findings,
        }


class SemanticAnalyzer:
    """
    Analyzes whether code changes introduce unauthorized behaviors or privilege-sensitive operational sinks.
    """

    CAPABILITY_RULES = {
        "DYNAMIC_EXECUTION": {
            "patterns": [
                r"\beval\s*\(", r"\bexec\s*\(", r"\b__import__\s*\(",
                r"Function\s*\([^)]*\)\s*\(", r"vm\.runInThisContext\s*\("
            ],
            "severity": "critical",
            "weight": 0.85,
            "desc": "Dynamic code execution via eval/exec/Function constructor"
        },
        "SUBPROCESS_EXECUTION": {
            "patterns": [
                r"os\.(?:system|popen|exec[a-z]*|spawn[a-z]*)\s*\(",
                r"subprocess\.(?:Popen|call|run|check_output)\s*\(",
                r"child_process\.(?:exec|execSync|spawn|spawnSync)\s*\("
            ],
            "severity": "high",
            "weight": 0.70,
            "desc": "Native operating system subprocess invocation"
        },
        "NETWORK_COMMUNICATION": {
            "patterns": [
                r"(?:urllib\.request|requests\.(?:get|post|put|delete)|http\.client)\b",
                r"\bsocket\.socket\b", r"\bfetch\s*\(", r"\baxios\.(?:get|post)\b",
                r"https?:\/\/(?!localhost|127\.0\.0\.1)[^\s\"']+"
            ],
            "severity": "medium",
            "weight": 0.40,
            "desc": "Outbound network connection or HTTP dispatch"
        },
        "CREDENTIAL_ACCESS": {
            "patterns": [
                r"(?:api_key|access_token|secret_key|password|private_key)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{12,}['\"]",
                r"\/etc\/(?:shadow|passwd)", r"~?\/\.ssh\/id_[a-z]+",
                r"(?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|SLACK_TOKEN)\b"
            ],
            "severity": "critical",
            "weight": 0.90,
            "desc": "Access or exfiltration of authentication credentials or secrets"
        },
        "ENVIRONMENT_ACCESS": {
            "patterns": [
                r"os\.environ(?:\[|\.get\()", r"process\.env\.[A-Z0-9_]+",
                r"System\.getenv\("
            ],
            "severity": "low",
            "weight": 0.20,
            "desc": "Inspection of host environment variables"
        },
        "AUTHENTICATION_BYPASS": {
            "patterns": [
                r"(?:if\s+.*(?:root_override|admin_backdoor|magic_token|bypass_auth))",
                r"return\s+True\s*#.*bypass",
                r"is_authenticated\s*=\s*True\s*(?:#|;|\n)"
            ],
            "severity": "critical",
            "weight": 0.95,
            "desc": "Potential hardcoded authentication or authorization logic bypass"
        },
        "SUSPICIOUS_OBFUSCATION": {
            "patterns": [
                r"base64\.(?:b64decode|b85decode)\s*\(",
                r"Buffer\.from\([^)]+,\s*['\"]base64['\"]\)",
                r"(?:\\x[0-9a-fA-F]{2}){8,}",
                r"fromCharCode\s*\("
            ],
            "severity": "high",
            "weight": 0.75,
            "desc": "Obfuscated payload encoding or reflection routine"
        },
        "UNSAFE_DESERIALIZATION": {
            "patterns": [
                r"pickle\.loads\s*\(", r"marshal\.loads\s*\(",
                r"yaml\.(?:load|unsafe_load)\s*\([^)]*Loader\s*=\s*(?:yaml\.)?Loader"
            ],
            "severity": "critical",
            "weight": 0.85,
            "desc": "Unsafe object deserialization leading to remote code execution"
        }
    }

    def __init__(self):
        self._compiled_rules = {
            cat: [re.compile(p, re.IGNORECASE) for p in data["patterns"]]
            for cat, data in self.CAPABILITY_RULES.items()
        }

    def analyze_directory(self, repo_dir: str) -> SemanticAnalysisResult:
        """
        Scans repository source files for semantic capability shifts and suspicious patterns.
        """
        base = Path(repo_dir).resolve()
        evidence: List[SemanticEvidence] = []
        capabilities = set()
        findings: List[str] = []
        total_risk = 0.0

        for root, _, files in os.walk(base):
            # Skip ignored directories
            if any(part in {".git", ".venv", "venv", "node_modules", "target", "build", "dist"} for part in Path(root).parts):
                continue

            for file in files:
                ext = Path(file).suffix.lower()
                if ext in {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".go", ".rs"}:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, base)
                    f_evidence = self._scan_file(file_path, rel_path)
                    evidence.extend(f_evidence)

        # Aggregate capabilities and calculate risk
        cat_scores: Dict[str, float] = {}
        for ev in evidence:
            capabilities.add(ev.category)
            rule_weight = self.CAPABILITY_RULES[ev.category]["weight"]
            cat_scores[ev.category] = max(cat_scores.get(ev.category, 0.0), rule_weight)

        # Correlated Risk: Exfiltration (Network + Credential/Environment)
        if "NETWORK_COMMUNICATION" in capabilities and ("CREDENTIAL_ACCESS" in capabilities or "ENVIRONMENT_ACCESS" in capabilities):
            cat_scores["DATA_EXFILTRATION_CORRELATION"] = 0.95
            findings.append("HIGH CONFIDENCE: Simultaneous presence of network dispatch and credential/environment access")

        if "AUTHENTICATION_BYPASS" in capabilities:
            findings.append("CRITICAL: Detected hardcoded conditional authentication bypass hook")

        if "DYNAMIC_EXECUTION" in capabilities and "SUSPICIOUS_OBFUSCATION" in capabilities:
            cat_scores["OBFUSCATED_DYNAMIC_PAYLOAD"] = 0.98
            findings.append("CRITICAL: Obfuscated decoding paired with dynamic execution")

        # Composite score calculation
        if cat_scores:
            # Multi-signal risk formula
            sorted_scores = sorted(cat_scores.values(), reverse=True)
            # Dominant score + damped secondary contributions
            comp_score = sorted_scores[0]
            for s in sorted_scores[1:]:
                comp_score += (1.0 - comp_score) * 0.3 * s
            total_risk = min(1.0, float(comp_score))
        else:
            total_risk = 0.0

        confidence = 0.85 if len(evidence) >= 2 else (0.60 if len(evidence) == 1 else 0.95)

        for ev in evidence[:10]:
            findings.append(f"[{ev.category}] {ev.file_path}:{ev.line_number} - {ev.description}")

        return SemanticAnalysisResult(
            risk_score=total_risk,
            confidence=confidence,
            capabilities_detected=sorted(list(capabilities)),
            evidence=evidence,
            findings=findings
        )

    def _scan_file(self, full_path: str, rel_path: str) -> List[SemanticEvidence]:
        file_evidence = []
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            for line_idx, line in enumerate(lines):
                line_no = line_idx + 1
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                    continue

                for cat, regexes in self._compiled_rules.items():
                    for reg in regexes:
                        match = reg.search(line)
                        if match:
                            rule_meta = self.CAPABILITY_RULES[cat]
                            file_evidence.append(SemanticEvidence(
                                category=cat,
                                symbol=match.group(0)[:40],
                                file_path=rel_path,
                                line_number=line_no,
                                severity=rule_meta["severity"],
                                description=rule_meta["desc"]
                            ))
                            break  # Avoid double reporting same category on same line
        except Exception:
            pass
        return file_evidence
