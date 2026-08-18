"""
Agent Tools for Codebase Exploration

Tool definitions and implementations for Stage 2 verification and agentic
context enhancement. These tools allow the model to search and read code
from the repository to validate security assessments.

Available Tools:
    - search_usages: Find where a function is called in the codebase
    - search_definitions: Find where a function is defined
    - read_function: Get full source code of a function by ID
    - list_functions: List all functions in a specific file
    - finish: Complete the analysis (for context enhancement)

Classes:
    ToolExecutor: Executes tool calls against a RepositoryIndex
"""

import json
from typing import Any

from .repository_index import RepositoryIndex


# Tool definitions for Anthropic API
TOOL_DEFINITIONS = [
    {
        "name": "search_usages",
        "description": "Search for all places where a function is called/used in the codebase. Returns list of functions that call the target function, with matching lines.",
        "input_schema": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "Name of the function to find usages of (e.g., 'validateInput', 'isUnsafeFilePath')"
                }
            },
            "required": ["function_name"]
        }
    },
    {
        "name": "search_definitions",
        "description": "Search for where a function is defined. Returns the function definition with full code.",
        "input_schema": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "Name of the function to find definition of"
                }
            },
            "required": ["function_name"]
        }
    },
    {
        "name": "read_function",
        "description": "Read the full source code of a function by its ID. Use this after search_usages or search_definitions to get complete code.",
        "input_schema": {
            "type": "object",
            "properties": {
                "function_id": {
                    "type": "string",
                    "description": "Function identifier in format 'file/path.ts:functionName' or 'file/path.ts:ClassName.methodName'"
                }
            },
            "required": ["function_id"]
        }
    },
    {
        "name": "list_functions",
        "description": "List all functions defined in a specific file. Useful to understand file structure.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file relative to repository root (e.g., 'src/utils/validator.ts')"
                }
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "read_file_section",
        "description": "Read a specific section of a file by line numbers. Use when you need context around a function.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file relative to repository root"
                },
                "start_line": {
                    "type": "integer",
                    "description": "Start line number (1-indexed)"
                },
                "end_line": {
                    "type": "integer",
                    "description": "End line number (1-indexed, inclusive)"
                }
            },
            "required": ["file_path", "start_line", "end_line"]
        }
    },
    {
        "name": "get_static_dependencies",
        "description": "Get the statically-analyzed dependencies (functions called) and callers for the unit being analyzed. Returns resolved function IDs that can be read with read_function. Use this first to understand what the code calls and to trace into service methods for auth/validation checks.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "finish",
        "description": "Complete the analysis and return the final result. Call this when you have gathered enough context to understand the code's intent and security implications.",
        "input_schema": {
            "type": "object",
            "properties": {
                "include_functions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Function ID to include in context"
                            },
                            "reason": {
                                "type": "string",
                                "description": "Why this function is needed for context"
                            }
                        },
                        "required": ["id", "reason"]
                    },
                    "description": "Functions that should be included in the analysis context"
                },
                "usage_context": {
                    "type": "string",
                    "description": "Description of how this code is used in the application"
                },
                "security_classification": {
                    "type": "string",
                    "enum": ["exploitable", "vulnerable_internal", "security_control", "neutral"],
                    "description": "Classification: exploitable (vulnerable + reachable from user input), vulnerable_internal (vulnerable but not user-reachable), security_control (defensive code), neutral (no security relevance)"
                },
                "classification_reasoning": {
                    "type": "string",
                    "description": "Detailed explanation of why you classified it this way"
                },
                "confidence": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "description": "Confidence level in your analysis (0.0-1.0)"
                }
            },
            "required": ["include_functions", "usage_context", "security_classification", "classification_reasoning", "confidence"]
        }
    }
]


class ToolExecutor:
    """
    Executes tools using the repository index.
    """

    def __init__(self, index: RepositoryIndex):
        """
        Initialize with repository index.

        Args:
            index: RepositoryIndex instance for searching
        """
        self.index = index
        self._unit_static_deps: list[str] = []
        self._unit_static_callers: list[str] = []

    def set_unit_context(self, static_deps: list[str], static_callers: list[str]):
        """Set static dependency data for the current unit being analyzed."""
        self._unit_static_deps = static_deps or []
        self._unit_static_callers = static_callers or []

    def execute(self, tool_name: str, tool_input: dict) -> dict:
        """
        Execute a tool and return the result.

        Args:
            tool_name: Name of the tool to execute
            tool_input: Input parameters for the tool

        Returns:
            Dict with result or error
        """
        try:
            if tool_name == "search_usages":
                return self._search_usages(tool_input)
            elif tool_name == "search_definitions":
                return self._search_definitions(tool_input)
            elif tool_name == "read_function":
                return self._read_function(tool_input)
            elif tool_name == "list_functions":
                return self._list_functions(tool_input)
            elif tool_name == "read_file_section":
                return self._read_file_section(tool_input)
            elif tool_name == "get_static_dependencies":
                return self._get_static_dependencies(tool_input)
            elif tool_name == "finish":
                return self._finish(tool_input)
            else:
                return {"error": f"Unknown tool: {tool_name}"}
        except Exception as e:
            return {"error": str(e)}

    def _search_usages(self, input: dict) -> dict:
        """Search for usages of a function."""
        function_name = input.get("function_name", "")
        if not function_name:
            return {"error": "function_name is required"}

        results = self.index.search_usages(function_name)

        if not results:
            return {
                "found": False,
                "message": f"No usages of '{function_name}' found in the codebase",
                "results": []
            }

        return {
            "found": True,
            "count": len(results),
            "results": results[:10]  # Limit to 10 results
        }

    def _search_definitions(self, input: dict) -> dict:
        """Search for function definitions."""
        function_name = input.get("function_name", "")
        if not function_name:
            return {"error": "function_name is required"}

        results = self.index.search_definitions(function_name)

        if not results:
            # Try partial match
            partial_results = self.index.search_by_name(function_name, exact=False)
            if partial_results:
                return {
                    "found": False,
                    "message": f"No exact match for '{function_name}', but found similar functions",
                    "similar": [{"id": r["id"], "name": r["name"]} for r in partial_results[:5]]
                }
            return {
                "found": False,
                "message": f"No function named '{function_name}' found in the codebase",
                "results": []
            }

        return {
            "found": True,
            "count": len(results),
            "results": results
        }

    def _read_function(self, input: dict) -> dict:
        """Read full function code by ID."""
        function_id = input.get("function_id", "")
        if not function_id:
            return {"error": "function_id is required"}

        func = self.index.get_function(function_id)
        if not func:
            return {
                "found": False,
                "message": f"Function '{function_id}' not found"
            }

        return {
            "found": True,
            "id": function_id,
            "name": func.get("name"),
            "code": func.get("code"),
            "startLine": func.get("startLine"),
            "endLine": func.get("endLine"),
            "unitType": func.get("unitType"),
            "className": func.get("className")
        }

    def _list_functions(self, input: dict) -> dict:
        """List functions in a file."""
        file_path = input.get("file_path", "")
        if not file_path:
            return {"error": "file_path is required"}

        results = self.index.list_functions_in_file(file_path)

        if not results:
            return {
                "found": False,
                "message": f"No functions found in '{file_path}' (file may not exist or have no functions)"
            }

        return {
            "found": True,
            "file": file_path,
            "count": len(results),
            "functions": results
        }

    def _read_file_section(self, input: dict) -> dict:
        """Read a section of a file."""
        file_path = input.get("file_path", "")
        start_line = input.get("start_line", 1)
        end_line = input.get("end_line", 50)

        if not file_path:
            return {"error": "file_path is required"}

        content = self.index.read_file_section(file_path, start_line, end_line)

        if content is None:
            return {
                "found": False,
                "message": f"Could not read '{file_path}' (file may not exist or repository path not set)"
            }

        return {
            "found": True,
            "file": file_path,
            "start_line": start_line,
            "end_line": end_line,
            "content": content
        }

    def _get_static_dependencies(self, input: dict) -> dict:
        """Get resolved static dependencies and callers for the current unit."""
        resolved_deps = self.index.resolve_dependencies(self._unit_static_deps)
        resolved_callers = self.index.resolve_dependencies(self._unit_static_callers)

        return {
            "dependencies": {
                "raw": self._unit_static_deps[:20],
                "resolved": resolved_deps[:20],
                "count": len(self._unit_static_deps)
            },
            "callers": {
                "raw": self._unit_static_callers[:20],
                "resolved": resolved_callers[:20],
                "count": len(self._unit_static_callers)
            }
        }

    def _finish(self, input: dict) -> dict:
        """Process finish tool - just validate and return the input."""
        required = ["include_functions", "usage_context", "security_classification", "classification_reasoning", "confidence"]

        for field in required:
            if field not in input:
                return {"error": f"Missing required field: {field}"}

        # Validate security_classification
        valid_classifications = ["exploitable", "vulnerable_internal", "security_control", "neutral"]
        if input["security_classification"] not in valid_classifications:
            return {"error": f"Invalid security_classification. Must be one of: {valid_classifications}"}

        # Validate confidence
        confidence = input.get("confidence", 0)
        if not (0.0 <= confidence <= 1.0):
            return {"error": "confidence must be between 0.0 and 1.0"}

        return {
            "status": "complete",
            "result": input
        }


def format_tool_result(tool_name: str, result: dict) -> str:
    """
    Format tool result for display to the agent.

    Args:
        tool_name: Name of the tool
        result: Tool execution result

    Returns:
        Formatted string for the agent
    """
    if "error" in result:
        return f"Error: {result['error']}"

    return json.dumps(result, indent=2)
