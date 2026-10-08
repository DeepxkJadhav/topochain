"""
Python AST extractor for TopoChain.
Extracts functions, classes, call graphs, external imports, and security-critical invocations.
"""

import ast
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any, Optional

from topochain.core.extractor.base import CodeEntity, EntityType


class PythonASTExtractor:
    """
    Parses Python source files into CodeEntities and call graph connections.
    """

    SENSITIVE_PATTERNS = {
        "exec", "eval", "__import__", "compile",
        "os.system", "os.popen", "os.exec", "os.spawn",
        "subprocess.Popen", "subprocess.call", "subprocess.run", "subprocess.check_output",
        "socket.socket", "socket", "urllib.request", "urllib", "requests.get", "requests.post", "requests", "http.client",
        "base64.b64decode", "base64.b85decode", "base64", "codecs.decode",
        "pickle.loads", "pickle", "marshal.loads", "yaml.load",
        "ctypes.cdll", "ctypes.windll", "sys.settrace", "pty.spawn"
    }

    KNOWN_EXTERNAL_ROOTS = {
        "os", "sys", "urllib", "subprocess", "socket", "requests",
        "http", "base64", "pickle", "ctypes", "shutil", "builtins"
    }

    def __init__(self):
        pass

    def extract_file(self, file_path: str, source_code: Optional[str] = None) -> Tuple[Dict[str, CodeEntity], List[Tuple[str, str, Dict[str, Any]]]]:
        if source_code is None:
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    source_code = f.read()
            except Exception:
                return {}, []

        try:
            tree = ast.parse(source_code, filename=file_path)
        except SyntaxError:
            return {}, []

        entities: Dict[str, CodeEntity] = {}
        edges: List[Tuple[str, str, Dict[str, Any]]] = []

        module_name = Path(file_path).stem
        module_id = f"mod:{module_name}"

        # Track all imports anywhere in the file
        imported_symbols: Dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    imported_symbols[name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    name = alias.asname or alias.name
                    imported_symbols[name] = f"{mod}.{alias.name}" if mod else alias.name

        # Create module entity
        mod_entity = CodeEntity(
            id=module_id,
            name=module_name,
            entity_type=EntityType.MODULE,
            file_path=file_path,
            imports=list(imported_symbols.values()),
        )
        entities[module_id] = mod_entity

        # Traverse for classes and functions
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ent, func_edges = self._process_function(node, file_path, module_name, parent_class=None, imported_symbols=imported_symbols)
                entities[ent.id] = ent
                edges.extend(func_edges)
                edges.append((module_id, ent.id, {"type": "contains", "weight": 0.2}))

            elif isinstance(node, ast.ClassDef):
                class_id = f"cls:{module_name}.{node.name}"
                class_ent = CodeEntity(
                    id=class_id,
                    name=node.name,
                    entity_type=EntityType.CLASS,
                    file_path=file_path,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    imports=list(imported_symbols.values()),
                )
                entities[class_id] = class_ent
                edges.append((module_id, class_id, {"type": "contains", "weight": 0.2}))

                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        ent, meth_edges = self._process_function(item, file_path, module_name, parent_class=node.name, imported_symbols=imported_symbols)
                        entities[ent.id] = ent
                        edges.extend(meth_edges)
                        edges.append((class_id, ent.id, {"type": "member", "weight": 0.1}))

        return entities, edges

    def _process_function(
        self,
        node: ast.AST,
        file_path: str,
        module_name: str,
        parent_class: Optional[str],
        imported_symbols: Dict[str, str]
    ) -> Tuple[CodeEntity, List[Tuple[str, str, Dict[str, Any]]]]:
        prefix = f"{module_name}."
        if parent_class:
            prefix += f"{parent_class}."
        func_id = f"fn:{prefix}{node.name}"

        complexity = 1
        calls: List[str] = []
        sensitive_ops: List[str] = []
        edges: List[Tuple[str, str, Dict[str, Any]]] = []

        for subnode in ast.walk(node):
            if isinstance(subnode, (ast.If, ast.While, ast.For, ast.ExceptHandler, ast.With, ast.Assert)):
                complexity += 1
            elif isinstance(subnode, ast.BoolOp):
                complexity += len(subnode.values) - 1

            if isinstance(subnode, ast.Call):
                callee_name = self._resolve_callee_name(subnode.func)
                if callee_name:
                    calls.append(callee_name)

                    # Check sensitive patterns
                    for pat in self.SENSITIVE_PATTERNS:
                        if pat == callee_name or pat in callee_name or callee_name.startswith(f"{pat}."):
                            sensitive_ops.append(callee_name)
                            break

                    target_id = self._resolve_target_id(callee_name, module_name, imported_symbols)
                    edges.append((func_id, target_id, {
                        "type": "call",
                        "weight": 0.5,
                        "callee": callee_name
                    }))

        entity = CodeEntity(
            id=func_id,
            name=node.name,
            entity_type=EntityType.METHOD if parent_class else EntityType.FUNCTION,
            file_path=file_path,
            line_start=node.lineno,
            line_end=getattr(node, "end_lineno", node.lineno),
            complexity=complexity,
            calls=calls,
            sensitive_operations=sensitive_ops,
            attributes={
                "is_async": isinstance(node, ast.AsyncFunctionDef),
                "args_count": len(node.args.args),
                "parent_class": parent_class
            }
        )

        return entity, edges

    def _resolve_callee_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._resolve_callee_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return None

    def _resolve_target_id(self, callee_name: str, current_module: str, imported_symbols: Dict[str, str]) -> str:
        parts = callee_name.split(".")
        root = parts[0]
        if root in imported_symbols:
            imported = imported_symbols[root]
            rest = ".".join(parts[1:])
            full = f"{imported}.{rest}" if rest else imported
            return f"ext:{full}"
        elif root in self.KNOWN_EXTERNAL_ROOTS:
            return f"ext:{callee_name}"
        elif len(parts) == 1:
            return f"fn:{current_module}.{callee_name}"
        else:
            return f"fn:{callee_name}"
