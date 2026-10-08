"""
JavaScript / TypeScript source code extractor for TopoChain.
Extracts functions, modules, dependencies, and sensitive runtime calls.
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from topochain.core.extractor.base import CodeEntity, EntityType


class JavaScriptExtractor:
    """
    Extracts functions, calls, and dependencies from JS / TS source files.
    """

    SENSITIVE_CALLS = {
        "eval", "Function", "exec", "execSync", "spawn", "spawnSync",
        "fetch", "axios", "https.request", "http.request",
        "child_process", "fs.readFileSync", "fs.writeFileSync",
        "Buffer.from", "crypto.createCipheriv", "crypto.privateEncrypt"
    }

    FUNC_DEF_REGEX = re.compile(
        r"(?:(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\(([^)]*)\))|"
        r"(?:(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>)|"
        r"(?:(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*function\s*\(([^)]*)\))"
    )

    REQUIRE_IMPORT_REGEX = re.compile(
        r"(?:require\(['\"]([^'\"]+)['\"]\))|"
        r"(?:from\s+['\"]([^'\"]+)['\"])|"
        r"(?:import\s+['\"]([^'\"]+)['\"])"
    )

    CALL_REGEX = re.compile(r"([a-zA-Z0-9_$]+(?:\.[a-zA-Z0-9_$]+)*)\s*\(")

    def extract_file(self, file_path: str, source_code: Optional[str] = None) -> Tuple[Dict[str, CodeEntity], List[Tuple[str, str, Dict[str, Any]]]]:
        if source_code is None:
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    source_code = f.read()
            except Exception:
                return {}, []

        entities: Dict[str, CodeEntity] = {}
        edges: List[Tuple[str, str, Dict[str, Any]]] = []

        module_name = Path(file_path).stem
        module_id = f"mod:{module_name}"

        # Find imports
        imports = []
        for match in self.REQUIRE_IMPORT_REGEX.finditer(source_code):
            dep = match.group(1) or match.group(2) or match.group(3)
            if dep:
                imports.append(dep)

        mod_entity = CodeEntity(
            id=module_id,
            name=module_name,
            entity_type=EntityType.MODULE,
            file_path=file_path,
            imports=imports
        )
        entities[module_id] = mod_entity

        # Find functions
        lines = source_code.splitlines()
        for idx, line in enumerate(lines):
            line_num = idx + 1
            for m in self.FUNC_DEF_REGEX.finditer(line):
                fname = m.group(1) or m.group(3) or m.group(5)
                if not fname:
                    continue

                func_id = f"fn:{module_name}.{fname}"
                # Analyze function body / calls within next 20 lines (heuristic window)
                body_chunk = "\n".join(lines[idx:min(len(lines), idx + 30)])
                calls = []
                sensitive_ops = []

                for cm in self.CALL_REGEX.finditer(body_chunk):
                    callee = cm.group(1)
                    if callee and callee != fname:
                        calls.append(callee)
                        for sens in self.SENSITIVE_CALLS:
                            if callee == sens or callee.endswith(f".{sens}"):
                                sensitive_ops.append(callee)
                        target_id = f"fn:{module_name}.{callee}" if "." not in callee else f"ext:{callee}"
                        edges.append((func_id, target_id, {"type": "call", "weight": 0.5, "callee": callee}))

                entity = CodeEntity(
                    id=func_id,
                    name=fname,
                    entity_type=EntityType.FUNCTION,
                    file_path=file_path,
                    line_start=line_num,
                    line_end=min(len(lines), line_num + 20),
                    complexity=1 + body_chunk.count("if ") + body_chunk.count("for ") + body_chunk.count("while "),
                    calls=calls,
                    sensitive_operations=sensitive_ops
                )
                entities[func_id] = entity
                edges.append((module_id, func_id, {"type": "contains", "weight": 0.2}))

        return entities, edges
