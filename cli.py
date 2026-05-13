#!/usr/bin/env python3
"""
Guardrails Gateway CLI Tool

Usage:
    python cli.py analyze --prompt "Your prompt" --input-file input.json --output-file output.json
    python cli.py analyze --prompt "Your prompt" --context "doc1.txt" --output output.json
"""

import argparse
import json
import sys
import requests
from pathlib import Path

def analyze_prompt(api_url, prompt, context_docs=None, metadata=None):
    """Send prompt to API for analysis."""
    if context_docs is None:
        context_docs = []
    
    if metadata is None:
        metadata = {
            "app_id": "cli_tool",
            "user_id": "cli_user",
            "request_id": "cli_request"
        }
    
    payload = {
        "prompt": prompt,
        "context_docs": context_docs,
        "metadata": metadata
    }
    
    try:
        response = requests.post(f"{api_url}/analyze", json=payload, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error calling API: {e}", file=sys.stderr)
        sys.exit(1)

def load_context_from_files(file_paths):
    """Load context documents from text files."""
    context_docs = []
    for i, file_path in enumerate(file_paths):
        path = Path(file_path)
        if path.exists():
            with open(path, 'r') as f:
                text = f.read()
            context_docs.append({
                "id": path.stem,
                "text": text
            })
        else:
            print(f"Warning: File {file_path} not found", file=sys.stderr)
    return context_docs

def main():
    parser = argparse.ArgumentParser(description="Guardrails Gateway CLI")
    parser.add_argument("--api-url", default="http://localhost:8000", 
                       help="API base URL")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a prompt")
    analyze_parser.add_argument("--prompt", help="Prompt text to analyze")
    analyze_parser.add_argument("--input-file", help="JSON input file with request")
    analyze_parser.add_argument("--output-file", required=True, 
                               help="Output file for results")
    analyze_parser.add_argument("--context", nargs="*", 
                               help="Context document files")
    
    args = parser.parse_args()
    
    if args.command == "analyze":
        if args.input_file:
            # Load from JSON file
            with open(args.input_file, 'r') as f:
                request_data = json.load(f)
            prompt = request_data.get("prompt", "")
            context_docs = request_data.get("context_docs", [])
            metadata = request_data.get("metadata")
        else:
            # Use command line arguments
            if not args.prompt:
                print("Error: Either --prompt or --input-file is required", 
                      file=sys.stderr)
                sys.exit(1)
            prompt = args.prompt
            context_docs = []
            if args.context:
                context_docs = load_context_from_files(args.context)
            metadata = None
        
        # Call API
        result = analyze_prompt(args.api_url, prompt, context_docs, metadata)
        
        # Write output
        with open(args.output_file, 'w') as f:
            json.dump(result, f, indent=2)
        
        print(f"Results written to {args.output_file}")
        print(f"Decision: {result['decision']}")
        print(f"Risk Score: {result['risk_score']}")
        print(f"Risk Tags: {', '.join(result['risk_tags'])}")
    
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()