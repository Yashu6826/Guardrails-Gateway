#!/usr/bin/env python3
"""
Guardrails Gateway CLI Tool

Usage:
    python cli.py analyze --input sample_request.json --output out.json
"""

import argparse
import json
import os
import sys
import uuid

import requests

# Exit codes
EXIT_OK = 0
EXIT_BAD_INPUT = 2
EXIT_NETWORK_ERROR = 3
EXIT_API_ERROR = 4
EXIT_UNKNOWN = 1


def analyze_prompt(api_url: str, payload: dict) -> dict:
    """Send payload to POST /analyze and return the JSON response."""
    try:
        response = requests.post(f"{api_url}/analyze", json=payload, timeout=30)
    except requests.exceptions.ConnectionError as e:
        print(f"Error: cannot reach API at {api_url} — {e}", file=sys.stderr)
        sys.exit(EXIT_NETWORK_ERROR)
    except requests.exceptions.Timeout:
        print("Error: request timed out after 30 s", file=sys.stderr)
        sys.exit(EXIT_NETWORK_ERROR)
    except requests.exceptions.RequestException as e:
        print(f"Error calling API: {e}", file=sys.stderr)
        sys.exit(EXIT_NETWORK_ERROR)

    if response.status_code == 422:
        print(f"Error: API rejected the payload — {response.text}", file=sys.stderr)
        sys.exit(EXIT_BAD_INPUT)
    if response.status_code != 200:
        print(f"Error: API returned {response.status_code}", file=sys.stderr)
        sys.exit(EXIT_API_ERROR)

    return response.json()


def main():
    parser = argparse.ArgumentParser(description="Guardrails Gateway CLI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a prompt")
    analyze_parser.add_argument(
        "--input", required=True, dest="input_file",
        help="JSON input file with the request payload",
    )
    analyze_parser.add_argument(
        "--output", required=True, dest="output_file",
        help="Output file for the JSON response",
    )
    analyze_parser.add_argument(
        "--api-url", default=None,
        help="API base URL (default: $GUARDRAILS_API_URL or http://localhost:8000)",
    )

    args = parser.parse_args()

    if args.command != "analyze":
        parser.print_help()
        sys.exit(EXIT_BAD_INPUT)

    # Resolve API URL: flag > env var > default
    api_url = (
        args.api_url
        or os.getenv("GUARDRAILS_API_URL")
        or f"http://localhost:{os.getenv('PORT', '8000')}"
    )

    # Load input JSON
    try:
        with open(args.input_file, "r") as f:
            request_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: input file '{args.input_file}' not found", file=sys.stderr)
        sys.exit(EXIT_BAD_INPUT)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in input file — {e}", file=sys.stderr)
        sys.exit(EXIT_BAD_INPUT)

    # Ensure metadata has a unique request_id if not provided
    if "metadata" not in request_data or request_data["metadata"] is None:
        request_data["metadata"] = {
            "app_id": "cli_tool",
            "user_id": "cli_user",
            "request_id": str(uuid.uuid4()),
        }
    elif "request_id" not in request_data["metadata"]:
        request_data["metadata"]["request_id"] = str(uuid.uuid4())

    # Call API
    result = analyze_prompt(api_url, request_data)

    # Write output
    with open(args.output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Results written to {args.output_file}")
    print(f"Decision: {result['decision']}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Risk Tags: {', '.join(result.get('risk_tags', []))}")


if __name__ == "__main__":
    main()