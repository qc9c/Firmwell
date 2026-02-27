#!/usr/bin/env python3
"""
Main entry point for IPC parameter extraction analysis.
"""

import argparse
import json
import logging
import sys
import os
from typing import List, Optional

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ipc_reason.analyzer_factory import AnalyzerFactory, analyze_binary


def setup_logging(log_level: str, log_file: Optional[str] = None):
    """Setup logging configuration."""
    level = getattr(logging, log_level.upper())
    
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )


def main():
    """Main function for command-line interface."""
    parser = argparse.ArgumentParser(
        description='Extract IPC parameters from binary files using angr symbolic execution',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze socket IPC (both network and Unix sockets automatically detected)
  python -m ipc_reason.main tests/socket_ipc/server --analyzer socket
  
  # Analyze Unix socket (same unified socket analyzer)
  python -m ipc_reason.main tests/socket_ipc_unix/unix_server --analyzer socket
  
  # Auto-detect and analyze all IPC mechanisms
  python -m ipc_reason.main tests/socket_ipc/server --auto-detect
  
  # Analyze multiple binaries with specific analyzers
  python -m ipc_reason.main tests/file/file_writer --analyzer file --output results.json
        """
    )
    
    parser.add_argument(
        'binary_path',
        help='Path to the binary file to analyze'
    )
    
    parser.add_argument(
        '--analyzer', '-a',
        action='append',
        choices=AnalyzerFactory.get_available_analyzers(),
        help='Analyzer type(s) to use (can be specified multiple times)'
    )
    
    parser.add_argument(
        '--auto-detect',
        action='store_true',
        help='Automatically detect relevant analyzers based on binary content'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file for results (JSON format)'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level'
    )
    
    parser.add_argument(
        '--log-file',
        help='Log file path'
    )
    
    parser.add_argument(
        '--pretty',
        action='store_true',
        help='Pretty-print JSON output'
    )
    
    parser.add_argument(
        '--list-analyzers',
        action='store_true',
        help='List available analyzers and exit'
    )
    
    parser.add_argument(
        '--main-only',
        action='store_true',
        help='Only analyze the main function (useful for complex binaries with Unix sockets)'
    )
    
    args = parser.parse_args()
    
    # List analyzers and exit
    if args.list_analyzers:
        print("Available analyzers:")
        for analyzer in AnalyzerFactory.get_available_analyzers():
            print(f"  - {analyzer}")
        return 0
    
    # Setup logging
    setup_logging(args.log_level, args.log_file)
    
    # Validate binary path
    if not os.path.exists(args.binary_path):
        print(f"Error: Binary file not found: {args.binary_path}", file=sys.stderr)
        return 1
    
    # Determine analyzer types
    analyzer_types = args.analyzer
    auto_detect = args.auto_detect
    
    if not analyzer_types and not auto_detect:
        print("Error: Must specify --analyzer or --auto-detect", file=sys.stderr)
        return 1
    
    try:
        # Run analysis
        print(f"Analyzing binary: {args.binary_path}")
        if analyzer_types:
            print(f"Using analyzers: {', '.join(analyzer_types)}")
        if auto_detect:
            print("Auto-detecting relevant analyzers...")
        
        results = analyze_binary(
            args.binary_path,
            analyzer_types=analyzer_types,
            log_level=args.log_level,
            auto_detect=auto_detect,
            main_only=args.main_only
        )
        
        # Format output
        if args.pretty:
            json_output = json.dumps(results, indent=2, default=str)
        else:
            json_output = json.dumps(results, default=str)
        
        # Write output
        if args.output:
            with open(args.output, 'w') as f:
                f.write(json_output)
            print(f"Results written to: {args.output}")
        else:
            print("\nAnalysis Results:")
            print("=" * 50)
            print(json_output)
        
        # Print summary
        print(f"\nSummary:")
        print(f"  Analyzers used: {len(results['analyzers_used'])}")
        print(f"  Successful: {len(results['results'])}")
        print(f"  Errors: {len(results['errors'])}")
        
        if results['errors']:
            print("\nErrors:")
            for analyzer, error in results['errors'].items():
                print(f"  {analyzer}: {error}")
        
        return 0
        
    except Exception as e:
        print(f"Error: Analysis failed: {e}", file=sys.stderr)
        if args.log_level == 'DEBUG':
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())