"""
Stage 2: Function Extractor for Zig

Extracts functions, methods, and structs from Zig source files using tree-sitter.
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

from utilities.file_io import write_json

from tree_sitter import Language, Parser, Node


def _load_zig_language() -> Language:
    """Load the Zig tree-sitter grammar lazily.

    The grammar package (``tree-sitter-zig``) is an optional runtime
    dependency. Importing it at module top level made the entire Zig parser
    unimportable in any environment where the package is absent (e.g. a clean
    install that does not need Zig support). Resolving it here, on first use,
    lets the module import unconditionally and surfaces a clear, actionable
    error only when the Zig parser is actually exercised.
    """
    try:
        import tree_sitter_zig as ts_zig
    except ImportError as exc:  # pragma: no cover - exercised via the no-dep test
        raise ImportError(
            "The Zig parser requires the 'tree-sitter-zig' package, which is not "
            "installed. Install it with `pip install tree-sitter-zig` "
            "(declared in pyproject.toml / requirements.txt)."
        ) from exc
    return Language(ts_zig.language())


class FunctionExtractor:
    """Extracts functions and structs from Zig source files using tree-sitter."""

    def __init__(self, repo_path: str, scan_results: Dict[str, Any]):
        self.repo_path = Path(repo_path).resolve()
        self.scan_results = scan_results
        self.parser = Parser(_load_zig_language())

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
        """Recursively walk the AST to extract definitions.

        Node-type names match the tree-sitter-zig grammar actually in use
        (variable_declaration / struct_declaration / function_declaration /
        builtin_function). Earlier names (VarDecl / container_decl / FnProto /
        builtin_call_expr) were from a different grammar revision and never
        matched, leaving struct extraction dead and methods mis-emitted.
        """

        # The struct context for any children we recurse into. It only changes
        # when this node is itself a `const Name = struct {...}` declaration.
        child_struct = current_struct

        if node.type == "function_declaration":
            func_info = self._extract_function(node, source, file_path, current_struct)
            if func_info:
                func_id = f"{file_path}:{func_info['qualified_name']}"
                functions[func_id] = func_info
                # Zig's generic-container idiom is a type-returning function:
                # `fn List(comptime T: type) type { return struct { fn push() ... }; }`.
                # The returned struct is anonymous in the AST (not a `const Name =
                # struct {...}` variable_declaration), so without this its methods would
                # recurse with current_struct unchanged and be emitted as bare top-level
                # functions. Thread the function name as the struct context so they
                # qualify as List.push and distinct containers' methods don't collide.
                if self._returns_type(node, source):
                    child_struct = func_info["name"]

        elif node.type == "variable_declaration":
            # `const Foo = struct { ... };` -- a named struct/enum definition.
            struct_info = self._extract_struct_from_var_decl(node, source, file_path)
            if struct_info:
                struct_id = f"{file_path}:{struct_info['name']}"
                structs[struct_id] = struct_info
                # Thread the struct name down into the body so its method
                # function_declarations are emitted ONCE, qualified as
                # Struct.method (a method visited via recursion produces the
                # same func_id as the eager scan, so there is no bare duplicate).
                child_struct = struct_info["name"]

        elif node.type == "builtin_function" and self._get_node_text(
            node, source
        ).startswith("@import"):
            import_path = self._extract_import(node, source)
            if import_path:
                imports.append(import_path)

        # Recurse into children with the (possibly updated) struct context so
        # nested function_declarations are qualified correctly. Struct FIELDS
        # (`container_field`) are not function_declarations, so they are never
        # emitted as units.
        for child in node.children:
            self._walk_node(
                child, source, file_path, functions, structs, imports, child_struct
            )

    def _extract_function(
        self, node: Node, source: bytes, file_path: str, current_struct: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Extract function information from a function declaration node."""
        # Find function name. In the grammar a function_declaration is
        # `[pub] fn <identifier> (params) [return-type] block`; the function
        # name is the FIRST identifier. A return type can also be a bare
        # identifier (e.g. `fn init(...) Point {`), so capture the name once
        # and stop -- otherwise the return-type identifier overwrites it.
        name = None
        parameters = []

        for child in node.children:
            if child.type == "identifier" or child.type == "IDENTIFIER":
                if name is None:
                    name = self._get_node_text(child, source)
            elif child.type in ("parameters", "ParamDeclList"):
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

    def _returns_type(self, node: Node, source: bytes) -> bool:
        """True if a function_declaration's return type is the builtin `type` — Zig's
        generic-container idiom (`fn Foo(...) type { return struct {...} }`).

        The return type is the function_declaration's direct child that follows the
        `parameters` node (a `builtin_type`). This deliberately inspects only direct
        children, so the `type` inside a `comptime T: type` parameter (nested under
        `parameters`) is not mistaken for the return type.
        """
        seen_params = False
        for child in node.children:
            if child.type in ("parameters", "ParamDeclList"):
                seen_params = True
            elif seen_params and child.type == "builtin_type":
                return self._get_node_text(child, source).strip() == "type"
        return False

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
            if child.type in ("identifier", "IDENTIFIER"):
                if name is None:
                    name = self._get_node_text(child, source)
            elif child.type in ("struct_declaration", "enum_declaration",
                                "union_declaration", "opaque_declaration"):
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

        # Test functions. Anchor on the underscore-delimited test convention
        # (`test_foo`, `foo_test`, or a bare `test`). A camelCase identifier
        # that merely starts with "test" (e.g. `testConnection`) is an ordinary
        # function, not a zig `test "..." {}` block.
        if name_lower == "test" or name_lower.startswith("test_") or name_lower.endswith("_test"):
            return "test"

        # Init/constructor patterns
        if name in ("init", "create", "new"):
            return "constructor"

        # Main entry point. Classify as 'main' (matching the C and Go parsers)
        # so the reachability seeder recognises a Zig binary's program entry —
        # 'main' is an ENTRY_POINT_TYPE. Returning the generic 'function' here
        # left every Zig binary with zero seeded entry points.
        if name == "main":
            return "main"

        return "function"

    def save_results(self, output_path: str, results: Dict[str, Any]) -> None:
        """Save extraction results to a JSON file."""
        write_json(output_path, results)
