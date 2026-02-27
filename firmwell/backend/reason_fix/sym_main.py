#!/usr/bin/env python3

import sys
import os
import argparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sym_loc import ErrorAnalyzer
# from sym_executor import SymbolicExecutor
from sym_executor import SymbolicExecutor

def main():
    parser = argparse.ArgumentParser(description='Symbolic execution based on error trace analysis')
    parser.add_argument('--trace-file', required=True, help='Path to trace log file')
    parser.add_argument('--fs-path', required=True, help='Filesystem root path')
    parser.add_argument('--main-binary', required=True, help='Path to main binary')
    parser.add_argument('--error-file', required=True, help='Error file pattern to search for (e.g., /dev/a)')
    parser.add_argument('--output-dir', default='./sym_infer_output', help='Output directory for results')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    
    filtered_trace_path = os.path.join(args.output_dir, 'filtered_trace.log')
    
    print("=== Symbolic Inference Analysis ===")
    print(f"Trace file: {args.trace_file}")
    print(f"Filesystem path: {args.fs_path}")
    print(f"Main binary: {args.main_binary}")
    print(f"Error file: {args.error_file}")
    print(f"Output directory: {args.output_dir}")
    print()
    
    excluded_libs = ['libgcc', 'libc', 'libdl', 'libnvram']
    
    print("=== Step 1: Error Trace Analysis ===")
    analyzer = ErrorAnalyzer(
        trace_file_path=args.trace_file,
        filtered_trace_log_path=filtered_trace_path,
        fs_path=args.fs_path,
        main_binary_path=args.main_binary,
        error_file=args.error_file,
        excluded_lib_str=excluded_libs
    )
    
    analyzer.merged_map = analyzer.extract_lib_mapping()
    
    excluded_lib_ranges = []
    for lib_str in excluded_libs:
        for lib, ranges in analyzer.merged_map.items():
            if lib_str in lib:
                excluded_lib_ranges.extend(ranges)
    
    analyzer.filter_trace_log(excluded_lib_ranges)
    print(f"Filtered trace log saved to: {filtered_trace_path}")
    
    err_bin_path, find_addr = analyzer.locate_error_bin()
    
    if not err_bin_path or not find_addr:
        print("Error: Could not locate error binary and address")
        return 1
    
    print(f"\nError binary: {err_bin_path}")
    print(f"Error address: {hex(find_addr)}")
    
    print("\n=== Step 2: Symbolic Execution ===")
    sym_executor = SymbolicExecutor(
        err_bin_path=err_bin_path,
        find_addr=find_addr,
        fs_path=args.fs_path,
        error_file=args.error_file,
        output_dir=args.output_dir
    )
    
    results = sym_executor.run_symbolic_execution()
    
    if results:
        print(f"\n=== Success: Found {len(results)} solutions ===")
        for i, result in enumerate(results):
            print(f"Solution {i+1} saved to: {result['output_file']}")
            
            final_output = os.path.join(args.output_dir, os.path.basename(result['output_file']))
            os.rename(result['output_file'], final_output)
            print(f"  -> Moved to: {final_output}")
    else:
        print("\n=== No valid solutions found ===")
        
    print("\n=== Analysis Complete ===")
    return 0

if __name__ == "__main__":
    sys.exit(main())