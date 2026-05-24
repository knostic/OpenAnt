#!/usr/bin/env python3
"""CLI for generating application security context.

Usage:
    python -m context.generate_context /path/to/repo
    python -m context.generate_context /path/to/repo -o context.json
    python -m context.generate_context /path/to/repo --force  # Skip manual override
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from context.application_context import (
    ApplicationType,
    APPLICATION_TYPE_INFO,
    UnsupportedApplicationTypeError,
    generate_application_context,
    save_context,
    format_context_for_prompt,
)


def print_supported_types():
    """Print information about supported application types."""
    print("\nSupported Application Types:")
    print("=" * 60)
    for type_value, info in APPLICATION_TYPE_INFO.items():
        print(f"\n  {type_value}:")
        print(f"    Description: {info['description']}")
        print(f"    Attack Model: {info['attack_model']}")
        print(f"    Examples: {info['examples']}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Generate application security context for vulnerability analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported Application Types:
  web_app          Web applications and API servers (HTTP-based)
  cli_tool         Command-line tools (local user has shell access)
  library          Reusable code packages (no direct attack surface)
  agent_framework  AI agent/LLM frameworks (code execution is intentional)

Examples:
    # Generate context for a repository
    python -m context.generate_context /path/to/langchain

    # Save to specific output file
    python -m context.generate_context /path/to/repo -o my_context.json

    # Force regeneration (ignore manual override)
    python -m context.generate_context /path/to/repo --force

Manual Override:
    Create a OPENANT.md or OPENANT.json file in the repository root
    to provide manual security context. See OPENANT_TEMPLATE.md for format.
        """,
    )

    parser.add_argument(
        "repo_path",
        type=Path,
        nargs="?",  # Make optional for --list-types
        help="Path to the repository to analyze",
    )

    parser.add_argument(
        "--output", "-o",
        type=Path,
        help="Output JSON path (default: <repo>/application_context.json)",
    )

    parser.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config to use for the app_context phase "
            "(default: file's default_llm or openant-default)."
        ),
    )

    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Force regeneration, ignoring manual override files",
    )

    parser.add_argument(
        "--show-prompt",
        action="store_true",
        help="Show the formatted context as it would appear in prompts",
    )

    parser.add_argument(
        "--list-types",
        action="store_true",
        help="List supported application types and exit",
    )

    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Minimal output",
    )

    args = parser.parse_args()

    # Handle --list-types
    if args.list_types:
        print_supported_types()
        sys.exit(0)

    # Require repo_path for all other operations
    if not args.repo_path:
        parser.error("repo_path is required")

    # Validate repository path
    if not args.repo_path.exists():
        print(f"Error: Repository path does not exist: {args.repo_path}", file=sys.stderr)
        sys.exit(1)

    if not args.repo_path.is_dir():
        print(f"Error: Repository path is not a directory: {args.repo_path}", file=sys.stderr)
        sys.exit(1)

    # Determine output path
    output_path = args.output or args.repo_path / "application_context.json"

    try:
        # Generate context
        if not args.quiet:
            print(f"Analyzing repository: {args.repo_path}")
            print()

        # Build a phase registry locally so the standalone CLI uses
        # the same llm-config plumbing as ``openant scan``. The probe
        # runs upfront so bad keys / typo'd model IDs surface before
        # we read any repo files.
        from utilities.llm import (
            build_phase_registry,
            load_config_file,
            probe_registry_or_raise,
            resolve_llm_config,
        )
        cf = load_config_file()
        registry = build_phase_registry(cf, resolve_llm_config(cf, args.llm_config))
        probe_registry_or_raise(registry)
        binding = registry.get("app_context")

        context = generate_application_context(
            args.repo_path,
            binding,
            force_regenerate=args.force,
        )

        # Display results
        if not args.quiet:
            print()
            print("=" * 60)
            print("APPLICATION CONTEXT")
            print("=" * 60)
            print()
            print(f"Type:                  {context.application_type}")

            type_info = context.get_type_info()
            if type_info:
                print(f"Type Description:      {type_info.get('description', '')}")
                print(f"Attack Model:          {type_info.get('attack_model', '')}")

            print(f"Purpose:               {context.purpose}")
            print(f"Requires Remote Trigger: {context.requires_remote_trigger}")
            print(f"Confidence:            {context.confidence:.0%}")
            print(f"Source:                {context.source}")
            print()

            if context.intended_behaviors:
                print("Intended Behaviors (NOT vulnerabilities):")
                for item in context.intended_behaviors:
                    print(f"  - {item}")
                print()

            if context.trust_boundaries:
                print("Trust Boundaries:")
                for source, level in context.trust_boundaries.items():
                    print(f"  - {source}: {level}")
                print()

            if context.not_a_vulnerability:
                print("Do NOT Flag as Vulnerable:")
                for item in context.not_a_vulnerability:
                    print(f"  - {item}")
                print()

            if context.security_model:
                print(f"Security Model: {context.security_model}")
                print()

            if context.evidence:
                print("Evidence:")
                for item in context.evidence:
                    print(f"  - {item}")
                print()

        # Save context
        save_context(context, output_path)

        # Show prompt format if requested
        if args.show_prompt:
            print()
            print("=" * 60)
            print("PROMPT FORMAT")
            print("=" * 60)
            print()
            print(format_context_for_prompt(context))

        if not args.quiet:
            print()
            print(f"Context saved to: {output_path}")

    except UnsupportedApplicationTypeError as e:
        print()
        print("=" * 60)
        print("UNSUPPORTED APPLICATION TYPE")
        print("=" * 60)
        print()
        print(f"Detected type: {e.detected_type}")
        print()
        print("OpenAnt currently supports these application types:")
        for t in ApplicationType.supported_values():
            info = APPLICATION_TYPE_INFO.get(t, {})
            print(f"  - {t}: {info.get('description', '')}")
        print()
        print("To analyze this repository anyway, create a manual override file:")
        print(f"  1. Create {args.repo_path}/OPENANT.md")
        print("  2. Add a JSON block with application_type set to one of the supported types")
        print("  3. See context/OPENANT_TEMPLATE.md for the full format")
        print()

        if e.evidence:
            print("Evidence for detected type:")
            for item in e.evidence:
                print(f"  - {item}")
            print()

        sys.exit(2)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
