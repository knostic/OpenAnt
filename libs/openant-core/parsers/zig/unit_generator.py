"""
Stage 4: Unit Generator for Zig

Creates self-contained analysis units with dependency context.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Set


class UnitGenerator:
    """Generates analysis units from call graph data."""

    # File boundary marker using Zig comment syntax
    FILE_BOUNDARY = "\n\n// ========== File Boundary ==========\n\n"

    def __init__(
        self,
        call_graph_output: Dict[str, Any],
        repo_path: str,
        dependency_depth: int = 3,
    ):
        self.functions = call_graph_output.get("functions", {})
        self.classes = call_graph_output.get("classes", {})
        self.call_graph = call_graph_output.get("call_graph", {})
        self.reverse_call_graph = call_graph_output.get("reverse_call_graph", {})
        self.repository = repo_path
        self.dependency_depth = dependency_depth

    def generate(self, name: Optional[str] = None) -> tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Generate analysis units.

        Returns:
            (dataset.json, analyzer_output.json)
        """
        units = []
        dataset_name = name or Path(self.repository).name

        for func_id, func_info in self.functions.items():
            unit = self._generate_unit(func_id, func_info)
            units.append(unit)

        # Calculate statistics
        by_type: Dict[str, int] = {}
        units_with_upstream = 0
        units_with_downstream = 0
        total_upstream = 0
        total_downstream = 0

        for unit in units:
            unit_type = unit["unit_type"]
            by_type[unit_type] = by_type.get(unit_type, 0) + 1

            dep_meta = unit["code"]["dependency_metadata"]
            if dep_meta["total_upstream"] > 0:
                units_with_upstream += 1
                total_upstream += dep_meta["total_upstream"]
            if dep_meta["total_downstream"] > 0:
                units_with_downstream += 1
                total_downstream += dep_meta["total_downstream"]

        avg_upstream = total_upstream / len(units) if units else 0
        avg_downstream = total_downstream / len(units) if units else 0

        dataset = {
            "name": dataset_name,
            "repository": self.repository,
            "units": units,
            "statistics": {
                "total_units": len(units),
                "by_type": by_type,
                "units_with_upstream": units_with_upstream,
                "units_with_downstream": units_with_downstream,
                "units_enhanced": len([u for u in units if u["code"]["primary_origin"]["deps_inlined"]]),
                "avg_upstream": round(avg_upstream, 2),
                "avg_downstream": round(avg_downstream, 2),
            },
            "metadata": {
                "generator": "zig_unit_generator.py",
                "generated_at": datetime.now().isoformat(),
                "dependency_depth": self.dependency_depth,
            },
        }

        # Generate analyzer_output.json (camelCase for historical reasons)
        analyzer_output = {
            "repository": self.repository,
            "functions": {
                func_id: {
                    "name": func_info["name"],
                    "unitType": func_info["unit_type"],
                    "code": func_info["code"],
                    "filePath": func_info["file_path"],
                    "startLine": func_info["start_line"],
                    "endLine": func_info["end_line"],
                    "isExported": self._is_exported(func_info),
                    "parameters": func_info.get("parameters", []),
                    "className": func_info.get("class_name"),
                }
                for func_id, func_info in self.functions.items()
            },
            "call_graph": self.call_graph,
            "reverse_call_graph": self.reverse_call_graph,
        }

        return dataset, analyzer_output

    def _generate_unit(self, func_id: str, func_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a single analysis unit."""
        # Get dependencies (upstream - functions this calls)
        upstream = self._get_dependencies(func_id, self.call_graph, self.dependency_depth)
        # Get dependents (downstream - functions that call this)
        downstream = self._get_dependencies(func_id, self.reverse_call_graph, self.dependency_depth)

        # Get direct callers and callees
        direct_calls = self.call_graph.get(func_id, [])
        direct_callers = self.reverse_call_graph.get(func_id, [])

        # Build enhanced code with dependencies
        primary_code, files_included = self._build_enhanced_code(func_id, func_info, upstream)

        original_length = len(func_info.get("code", ""))
        enhanced_length = len(primary_code)

        return {
            "id": func_id,
            "unit_type": func_info["unit_type"],
            "code": {
                "primary_code": primary_code,
                "primary_origin": {
                    "file_path": func_info["file_path"],
                    "start_line": func_info["start_line"],
                    "end_line": func_info["end_line"],
                    "function_name": func_info["name"],
                    "class_name": func_info.get("class_name"),
                    "deps_inlined": len(upstream) > 0,
                    "files_included": files_included,
                    "original_length": original_length,
                    "enhanced_length": enhanced_length,
                },
                "dependencies": [],
                "dependency_metadata": {
                    "depth": self.dependency_depth,
                    "total_upstream": len(upstream),
                    "total_downstream": len(downstream),
                    "direct_calls": len(direct_calls),
                    "direct_callers": len(direct_callers),
                },
            },
            "ground_truth": {
                "status": "UNKNOWN",
                "vulnerability_types": [],
                "issues": [],
                "annotation_source": None,
                "annotation_key": None,
                "notes": None,
            },
            "metadata": {
                "parameters": func_info.get("parameters", []),
                "generator": "zig_unit_generator.py",
                "direct_calls": direct_calls,
                "direct_callers": direct_callers,
            },
        }

    def _get_dependencies(
        self, func_id: str, graph: Dict[str, List[str]], max_depth: int
    ) -> Set[str]:
        """Get all dependencies up to max_depth."""
        dependencies: Set[str] = set()
        current_level = {func_id}

        for _ in range(max_depth):
            next_level: Set[str] = set()
            for fid in current_level:
                for dep in graph.get(fid, []):
                    if dep not in dependencies and dep != func_id:
                        dependencies.add(dep)
                        next_level.add(dep)
            current_level = next_level
            if not current_level:
                break

        return dependencies

    def _build_enhanced_code(
        self, func_id: str, func_info: Dict[str, Any], upstream: Set[str]
    ) -> tuple[str, List[str]]:
        """Build enhanced code with dependency context."""
        # Start with the primary function's code
        primary_code = func_info.get("code", "")
        files_included = [func_info["file_path"]]

        if not upstream:
            return primary_code, files_included

        # Group dependencies by file
        deps_by_file: Dict[str, List[str]] = {}
        for dep_id in upstream:
            dep_info = self.functions.get(dep_id)
            if dep_info:
                file_path = dep_info["file_path"]
                if file_path not in deps_by_file:
                    deps_by_file[file_path] = []
                deps_by_file[file_path].append(dep_id)

        # Build enhanced code
        code_parts = [primary_code]

        for file_path, dep_ids in deps_by_file.items():
            if file_path == func_info["file_path"]:
                # Same file - add dependencies without file boundary
                for dep_id in dep_ids:
                    dep_info = self.functions.get(dep_id)
                    if dep_info:
                        code_parts.append(dep_info.get("code", ""))
            else:
                # Different file - add file boundary
                if file_path not in files_included:
                    files_included.append(file_path)
                file_code = []
                for dep_id in dep_ids:
                    dep_info = self.functions.get(dep_id)
                    if dep_info:
                        file_code.append(dep_info.get("code", ""))
                if file_code:
                    code_parts.append(self.FILE_BOUNDARY + "\n".join(file_code))

        return "\n\n".join(code_parts), files_included

    def _is_exported(self, func_info: Dict[str, Any]) -> bool:
        """Check if a function is exported (pub in Zig)."""
        code = func_info.get("code", "")
        return code.strip().startswith("pub ")

    def save_results(
        self,
        output_dir: str,
        dataset: Dict[str, Any],
        analyzer_output: Dict[str, Any],
    ) -> None:
        """Save generated outputs to files."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        with open(output_path / "dataset.json", "w") as f:
            json.dump(dataset, f, indent=2)

        with open(output_path / "analyzer_output.json", "w") as f:
            json.dump(analyzer_output, f, indent=2)
