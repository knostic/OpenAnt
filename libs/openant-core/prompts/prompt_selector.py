"""
Prompt Selector Module

Routes to the vulnerability analysis prompt.
"""

from typing import List, TYPE_CHECKING

from . import vulnerability_analysis

if TYPE_CHECKING:
    from context.application_context import ApplicationContext


def get_analysis_prompt(
    code: str,
    language: str = None,
    route: str = None,
    files_included: List[str] = None,
    security_classification: str = None,
    classification_reasoning: str = None,
    app_context: "ApplicationContext" = None
) -> str:
    """
    Get the security assessment prompt for the given code.

    Args:
        code: Source code to analyze
        language: Programming language (optional, for code block formatting)
        route: Optional route/endpoint identifier
        files_included: Optional list of files in context
        security_classification: Optional hint from agentic parser
        classification_reasoning: Optional reasoning for classification
        app_context: Optional ApplicationContext for reducing false positives

    Returns:
        Prompt string for security assessment
    """
    # Default to generic code block if no language specified
    if not language:
        language = "code"

    return vulnerability_analysis.get_analysis_prompt(
        code=code,
        language=language,
        route=route,
        files_included=files_included,
        security_classification=security_classification,
        classification_reasoning=classification_reasoning,
        app_context=app_context
    )
