"""
Git Evolution and Commit History Analysis Subsystem for TopoChain.
Analyzes developer behavioral signals, change churn, commit velocity, and author entropy.
"""

import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple


@dataclass
class GitEvolutionResult:
    risk_score: float  # 0.0 to 1.0 (additional corroborating signal, never proof alone)
    confidence: float
    metrics: Dict[str, Any] = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)

    def summary(self) -> Dict[str, Any]:
        return {
            "risk_score": round(self.risk_score, 3),
            "confidence": round(self.confidence, 3),
            "metrics": self.metrics,
            "findings": self.findings,
        }


class GitEvolutionAnalyzer:
    """
    Evaluates whether commit evolution deviates significantly from historical patterns.
    """

    def __init__(self, high_churn_threshold: int = 500):
        self.high_churn_threshold = high_churn_threshold

    def analyze_repository(
        self,
        repo_dir: str,
        commit_ref: str = "HEAD"
    ) -> GitEvolutionResult:
        repo_path = Path(repo_dir).resolve()
        git_dir = repo_path / ".git"

        # If not a git repository, return graceful baseline
        if not git_dir.exists() or not shutil.which("git"):
            return GitEvolutionResult(
                risk_score=0.10,
                confidence=0.30,
                metrics={"is_git_repo": False, "churn": 0, "author_status": "unknown"},
                findings=["Not a git repository; using default historical baseline"]
            )

        metrics = {}
        findings = []
        risk = 0.0

        try:
            # 1. Author inspection
            author_res = subprocess.run(
                ["git", "log", "-1", "--format=%an <%ae>", commit_ref],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=5
            )
            current_author = author_res.stdout.strip() if author_res.returncode == 0 else "unknown"
            metrics["current_author"] = current_author

            # Count author's historical commits
            history_res = subprocess.run(
                ["git", "shortlog", "-sn", "--no-merges", "HEAD~1"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=5
            )
            known_authors = history_res.stdout if history_res.returncode == 0 else ""
            is_new_contributor = (current_author != "unknown") and (current_author.split("<")[0].strip() not in known_authors)
            metrics["is_new_contributor"] = is_new_contributor

            if is_new_contributor:
                risk += 0.25
                findings.append(f"First-time contributor identified: {current_author}")

            # 2. Churn inspection (lines added/deleted)
            diff_stat_res = subprocess.run(
                ["git", "diff", "--shortstat", f"{commit_ref}~1", commit_ref],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=5
            )
            diff_stat = diff_stat_res.stdout.strip() if diff_stat_res.returncode == 0 else ""
            metrics["diff_stat"] = diff_stat

            # Parse lines changed
            import re
            insertions = 0
            deletions = 0
            m_ins = re.search(r"(\d+)\s+insertion", diff_stat)
            m_del = re.search(r"(\d+)\s+deletion", diff_stat)
            if m_ins:
                insertions = int(m_ins.group(1))
            if m_del:
                deletions = int(m_del.group(1))

            total_churn = insertions + deletions
            metrics["total_churn"] = total_churn

            if total_churn > self.high_churn_threshold:
                risk += 0.35
                findings.append(f"Sudden high churn: {total_churn} lines altered")
            elif total_churn > self.high_churn_threshold * 3:
                risk += 0.60
                findings.append(f"Massive structural churn: {total_churn} lines altered")

            # 3. High-risk file alterations
            changed_files_res = subprocess.run(
                ["git", "diff", "--name-only", f"{commit_ref}~1", commit_ref],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=5
            )
            changed_files = [f.strip() for f in changed_files_res.stdout.splitlines() if f.strip()]
            metrics["changed_files_count"] = len(changed_files)

            has_ci_changes = any(".github" in f or ".gitlab" in f or "workflow" in f for f in changed_files)
            has_auth_changes = any("auth" in f.lower() or "security" in f.lower() for f in changed_files)
            has_manifest_changes = any(f.endswith(("package.json", "requirements.txt", "Cargo.toml", "go.mod")) for f in changed_files)

            if has_ci_changes and is_new_contributor:
                risk += 0.40
                findings.append("New contributor modified CI/CD pipeline definitions")

            if has_manifest_changes and has_auth_changes:
                risk += 0.30
                findings.append("Simultaneous modifications to dependency manifests and authentication modules")

        except Exception as e:
            metrics["error"] = str(e)
            findings.append(f"Git analysis encountered warning: {str(e)[:40]}")

        final_risk = min(1.0, float(risk))
        confidence = 0.75 if git_dir.exists() else 0.30

        return GitEvolutionResult(
            risk_score=final_risk,
            confidence=confidence,
            metrics=metrics,
            findings=findings
        )
