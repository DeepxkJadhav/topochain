"""
Dependency manifest extractor for TopoChain.
Parses requirements.txt, pyproject.toml, package.json, go.mod and flags typosquatting / suspicious packages.
"""

import os
import re
import json
from pathlib import Path
from typing import List, Dict, Any, Optional

from topochain.core.extractor.base import DependencyEntity


class DependencyExtractor:
    """
    Extracts package dependencies and checks for structural supply chain red flags.
    """

    POPULAR_PACKAGES = {
        "requests", "urllib3", "numpy", "scipy", "pandas", "flask", "django",
        "fastapi", "pytest", "cryptography", "boto3", "torch", "tensorflow",
        "express", "lodash", "react", "vue", "axios", "chalk", "debug",
        "moment", "commander", "webpack", "babel", "rxjs", "inquirer"
    }

    def __init__(self):
        pass

    def extract_from_directory(self, base_dir: str) -> List[DependencyEntity]:
        deps: List[DependencyEntity] = []
        base = Path(base_dir)

        # requirements.txt
        for req_file in base.glob("**/requirements*.txt"):
            deps.extend(self._parse_requirements_txt(str(req_file)))

        # package.json
        for pkg_file in base.glob("**/package.json"):
            if "node_modules" not in str(pkg_file):
                deps.extend(self._parse_package_json(str(pkg_file)))

        # pyproject.toml
        for pyproj in base.glob("**/pyproject.toml"):
            deps.extend(self._parse_pyproject_toml(str(pyproj)))

        # go.mod
        for gomod in base.glob("**/go.mod"):
            deps.extend(self._parse_go_mod(str(gomod)))

        return deps

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
                        flags = self._check_typosquatting(pkg_name)
                        deps.append(DependencyEntity(
                            name=pkg_name,
                            version_spec=ver,
                            source_file=file_path,
                            suspicious_flags=flags
                        ))
        except Exception:
            pass
        return deps

    def _parse_package_json(self, file_path: str) -> List[DependencyEntity]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            prod_deps = data.get("dependencies", {})
            for name, ver in prod_deps.items():
                flags = self._check_typosquatting(name)
                deps.append(DependencyEntity(
                    name=name.lower(),
                    version_spec=str(ver),
                    is_dev=False,
                    source_file=file_path,
                    suspicious_flags=flags
                ))

            dev_deps = data.get("devDependencies", {})
            for name, ver in dev_deps.items():
                flags = self._check_typosquatting(name)
                deps.append(DependencyEntity(
                    name=name.lower(),
                    version_spec=str(ver),
                    is_dev=True,
                    source_file=file_path,
                    suspicious_flags=flags
                ))
        except Exception:
            pass
        return deps

    def _parse_pyproject_toml(self, file_path: str) -> List[DependencyEntity]:
        deps = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            in_deps = False
            for line in content.splitlines():
                if "dependencies" in line and "=" in line:
                    in_deps = True
                    continue
                if in_deps:
                    if "]" in line:
                        in_deps = False
                        continue
                    m = re.search(r'["\']([a-zA-Z0-9_\-\.]+)(?:[>=<~!].*)?["\']', line)
                    if m:
                        pkg = m.group(1).lower()
                        flags = self._check_typosquatting(pkg)
                        deps.append(DependencyEntity(
                            name=pkg,
                            version_spec="*",
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
                    if line.startswith("require (") or line.startswith("require"):
                        continue
                    m = re.match(r"^([a-zA-Z0-9_\-\./]+)\s+(v[0-9\.\-a-zA-Z]+)", line)
                    if m:
                        deps.append(DependencyEntity(
                            name=m.group(1),
                            version_spec=m.group(2),
                            source_file=file_path
                        ))
        except Exception:
            pass
        return deps

    def _check_typosquatting(self, name: str) -> List[str]:
        flags = []
        clean_name = name.replace("-", "").replace("_", "")
        # Number substitutions: '0' -> 'o', '1' -> 'l'
        sub_name = clean_name.replace("0", "o").replace("1", "l").replace("3", "e")

        for pop in self.POPULAR_PACKAGES:
            clean_pop = pop.replace("-", "").replace("_", "")
            if clean_name == clean_pop:
                continue

            # Exact match with common leetspeak substitutions
            if sub_name == clean_pop:
                flags.append(f"possible_typosquat_of_{pop}")
                continue

            # Damerau-Levenshtein distance (allows transpositions)
            d = self._damerau_levenshtein(clean_name, clean_pop)
            if d == 1 or (d == 2 and len(clean_pop) >= 6):
                flags.append(f"possible_typosquat_of_{pop}")

        return flags

    def _damerau_levenshtein(self, s1: str, s2: str) -> int:
        """
        Calculates the Damerau-Levenshtein distance between two strings,
        supporting insertion, deletion, substitution, and transposition of two adjacent characters.
        """
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
                    d[(i - 1, j)] + 1,        # deletion
                    d[(i, j - 1)] + 1,        # insertion
                    d[(i - 1, j - 1)] + cost  # substitution
                )
                if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                    d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)  # transposition

        return d[(len1 - 1, len2 - 1)]
