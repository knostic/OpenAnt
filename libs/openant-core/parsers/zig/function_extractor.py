"""
Stage 2: Function Extractor for Zig

Extracts functions, methods, and structs from Zig source files using tree-sitter.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

import tree_sitter_zig as ts_zig
from tree_sitter import Language, Parser, Node


class FunctionExtractor:
    """Extracts functions and structs from Zig source files using tree-sitter."""

    ZIG_LANGUAGE = Language(ts_zig.language())

    def __init__(self, repo_path: str, scan_results: Dict[str, Any]):
        self.repo_path = Path(repo_path).resolve()
        self.scan_results = scan_results
        self.parser = Parser(self.ZIG_LANGUAGE)

    def extract(self) -> Dict[str, Any]:
        """
        Extract all functions and structs from scanned files.

        Returns functions.json structure with functions, classes (structs), imports.
        """
        functions = {}
        classes = {}  # Zig structs
        imports = {}
        files_processed = 0
        files_with_errors = 0

        for file_info in self.scan_results.get("files", []):
            file_path = file_info["path"]
            full_path = self.repo_path / file_path

            try:
                with open(full_path, "rb") as f:
                    source = f.read()

                tree = self.parser.parse(source)
                file_functions, file_structs, file_imports = self._extract_from_tree(
                    tree.root_node, source, file_path
                )

                functions.update(file_functions)
                classes.update(file_structs)
                imports[file_path] = file_imports
                files_processed += 1

            except Exception as e:
                print(f"Error processing {file_path}: {e}")
                files_with_errors += 1

        return {
            "repository": str(self.repo_path),
            "extraction_time": datetime.now().isoformat(),
            "functions": functions,
            "classes": classes,
            "imports": imports,
            "statistics": {
                "total_functions": len(functions),
                "total_classes": len(classes),
                "files_processed": files_processed,
                "files_with_errors": files_with_errors,
            },
        }

    def _extract_from_tree(
        self, root: Node, source: bytes, file_path: str
    ) -> tuple[Dict[str, Any], Dict[str, Any], List[str]]:
        """Extract functions, structs, and imports from a parse tree."""
        functions = {}
        structs = {}
        imports = []

        # Walk the AST
        self._walk_node(root, source, file_path, functions, structs, imports, None)

        return functions, structs, imports

    def _walk_node(
        self,
        node: Node,
        source: bytes,
        file_path: str,
        functions: Dict[str, Any],
        structs: Dict[str, Any],
        imports: List[str],
        current_struct: Optional[str],
    ) -> None:
        """Recursively walk the AST to extract definitions."""

        if node.type == "function_declaration" or node.type == "FnProto":
            func_info = self._extract_function(node, source, file_path, current_struct)
            if func_info:
                func_id = f"{file_path}:{func_info['qualified_name']}"
                functions[func_id] = func_info

        elif node.type == "VarDecl":
            # Check if this is a struct/enum definition
            struct_info = self._extract_struct_from_var_decl(node, source, file_path)
            if struct_info:
                struct_id = f"{file_path}:{struct_info['name']}"
                structs[struct_id] = struct_info
                # Extract methods within the struct
                self._extract_struct_methods(
                    node, source, file_path, struct_info["name"], functions
                )

        elif node.type == "container_decl" or node.type == "ContainerDecl":
            # Direct struct/enum declarations
            struct_info = self._extract_container(node, source, file_path)
            if struct_info:
                struct_id = f"{file_path}:{struct_info['name']}"
                structs[struct_id] = struct_info

        elif node.type == "@import" or (
            node.type == "builtin_call_expr"
            and self._get_node_text(node, source).startswith("@import")
        ):
            import_path = self._extract_import(node, source)
            if import_path:
                imports.append(import_path)

        # Recurse into children
        for child in node.children:
            self._walk_node(
                child, source, file_path, functions, structs, imports, current_struct
            )

    def _extract_function(
        self, node: Node, source: bytes, file_path: str, current_struct: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Extract function information from a function declaration node."""
        # Find function name
        name = None
        parameters = []

        for child in node.children:
            if child.type == "identifier" or child.type == "IDENTIFIER":
                name = self._get_node_text(child, source)
            elif child.type == "parameters" or child.type == "ParamDeclList":
                parameters = self._extract_parameters(child, source)

        if not name:
            return None

        # Determine qualified name and unit type
        if current_struct:
            qualified_name = f"{current_struct}.{name}"
            unit_type = "method"
        else:
            qualified_name = name
            unit_type = self._classify_function(name, file_path)

        start_line = node.start_point[0] + 1  # 1-indexed
        end_line = node.end_point[0] + 1

        return {
            "name": name,
            "qualified_name": qualified_name,
            "file_path": file_path,
            "start_line": start_line,
            "end_line": end_line,
            "code": self._get_node_text(node, source),
            "class_name": current_struct,
            "module_name": None,
            "parameters": parameters,
            "unit_type": unit_type,
        }

    def _extract_parameters(self, node: Node, source: bytes) -> List[str]:
        """Extract parameter names from a parameter list node."""
        params = []
        for child in node.children:
            if child.type == "parameter" or child.type == "ParamDecl":
                for subchild in child.children:
                    if subchild.type == "identifier" or subchild.type == "IDENTIFIER":
                        params.append(self._get_node_text(subchild, source))
                        break
        return params

    def _extract_struct_from_var_decl(
        self, node: Node, source: bytes, file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Extract struct info from a variable declaration (const Foo = struct {...})."""
        name = None
        is_struct = False

        for child in node.children:
            if child.type == "identifier" or child.type == "IDENTIFIER":
                name = self._get_node_text(child, source)
            elif child.type == "container_decl" or child.type == "ContainerDecl":
                is_struct = True

        if name and is_struct:
            return {
                "name": name,
                "file_path": file_path,
                "start_line": node.start_point[0] + 1,
                "end_line": node.end_point[0] + 1,
                "code": self._get_node_text(node, source),
            }
        return None

    def _extract_container(
        self, node: Node, source: bytes, file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Extract struct/enum from a container declaration."""
        # Anonymous container - try to find name from parent
        return None

    def _extract_struct_methods(
        self,
        node: Node,
        source: bytes,
        file_path: str,
        struct_name: str,
        functions: Dict[str, Any],
    ) -> None:
        """Extract methods from within a struct definition."""
        for child in node.children:
            if child.type == "container_decl" or child.type == "ContainerDecl":
                for member in child.children:
                    if (
                        member.type == "function_declaration"
                        or member.type == "FnProto"
                        or member.type == "container_field"
                    ):
                        # Check if it's a function field
                        func_info = self._extract_function(
                            member, source, file_path, struct_name
                        )
                        if func_info:
                            func_id = f"{file_path}:{func_info['qualified_name']}"
                            functions[func_id] = func_info

    def _extract_import(self, node: Node, source: bytes) -> Optional[str]:
        """Extract import path from an @import call."""
        text = self._get_node_text(node, source)
        # Parse @import("path")
        if "@import" in text:
            start = text.find('"')
            end = text.rfind('"')
            if start != -1 and end != -1 and start < end:
                return text[start + 1 : end]
        return None

    def _get_node_text(self, node: Node, source: bytes) -> str:
        """Get the source text for a node."""
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def _classify_function(self, name: str, file_path: str) -> str:
        """Classify the function type based on name and context."""
        name_lower = name.lower()

        # Test functions
        if name_lower.startswith("test") or "_test" in name_lower:
            return "test"

        # Init/constructor patterns
        if name in ("init", "create", "new"):
            return "constructor"

        # Main entry point
        if name == "main":
            return "function"

        return "function"

    def save_results(self, output_path: str, results: Dict[str, Any]) -> None:
        """Save extraction results to a JSON file."""
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
