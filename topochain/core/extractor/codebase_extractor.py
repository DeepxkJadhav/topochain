"""
Unified codebase extractor orchestrator for TopoChain.
Traverses project directories, parses source files across languages, and constructs the extracted AST topology.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Set

from topochain.core.extractor.base import (
    CodeEntity,
    DependencyEntity,
    EntityType,
    ExtractionResult,
)
from topochain.core.extractor.python_extractor import PythonASTExtractor
from topochain.core.extractor.js_extractor import JavaScriptExtractor
from topochain.core.extractor.dependency_extractor import DependencyExtractor


class CodebaseExtractor:
    """
    Extracts complete architectural topology from a codebase directory or commit tree.
    """

    IGNORE_DIRS = {
        ".git", ".svn", ".hg", "__pycache__", ".venv", "venv", "env",
        "node_modules", "dist", "build", ".idea", ".vscode", ".pytest_cache",
        "coverage", ".tox", "eggs", ".eggs"
    }

    def __init__(self):
        self.py_extractor = PythonASTExtractor()
        self.js_extractor = JavaScriptExtractor()
        self.dep_extractor = DependencyExtractor()

    def extract_directory(self, repo_dir: str) -> ExtractionResult:
        result = ExtractionResult()
        repo_path = Path(repo_dir).resolve()

        if not repo_path.exists():
            return result

        # 1. Extract dependencies
        dependencies = self.dep_extractor.extract_from_directory(str(repo_path))
        result.dependencies = dependencies

        # Register dependencies as entities
        for dep in dependencies:
            dep_id = f"dep:{dep.name}"
            dep_entity = CodeEntity(
                id=dep_id,
                name=dep.name,
                entity_type=EntityType.EXTERNAL_DEPENDENCY,
                file_path=dep.source_file,
                attributes={
                    "version": dep.version_spec,
                    "is_dev": dep.is_dev,
                    "suspicious_flags": dep.suspicious_flags,
                }
            )
            result.entities[dep_id] = dep_entity

        # 2. Walk directory for source code
        for root, dirs, files in os.walk(repo_path):
            # Prune ignored directories
            dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS and not d.startswith(".")]

            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, repo_path)
                ext = Path(file).suffix.lower()

                if ext in {".py", ".pyw"}:
                    result.files_scanned.append(rel_path)
                    result.language_stats["python"] = result.language_stats.get("python", 0) + 1
                    file_entities, file_edges = self.py_extractor.extract_file(file_path)
                    result.entities.update(file_entities)
                    result.call_edges.extend(file_edges)

                elif ext in {".js", ".jsx", ".ts", ".tsx", ".mjs"}:
                    result.files_scanned.append(rel_path)
                    result.language_stats["javascript"] = result.language_stats.get("javascript", 0) + 1
                    file_entities, file_edges = self.js_extractor.extract_file(file_path)
                    result.entities.update(file_entities)
                    result.call_edges.extend(file_edges)

        # 3. Connect code entity imports / external calls to registered dependencies
        dep_lookup = {dep.name.lower(): f"dep:{dep.name.lower()}" for dep in dependencies}
        for entity in list(result.entities.values()):
            if entity.entity_type in {EntityType.FUNCTION, EntityType.METHOD, EntityType.MODULE}:
                for imp in entity.imports:
                    pkg_root = imp.split(".")[0].lower()
                    if pkg_root in dep_lookup:
                        target_dep_id = dep_lookup[pkg_root]
                        result.call_edges.append((
                            entity.id,
                            target_dep_id,
                            {"type": "dependency_use", "weight": 0.7, "package": pkg_root}
                        ))

        return result
