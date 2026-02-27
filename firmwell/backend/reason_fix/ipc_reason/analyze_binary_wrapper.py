#!/usr/bin/env python3
"""
Wrapper script for analyze_binary that runs in a subprocess with resource limits.
This script is designed to be executed with ulimit constraints to prevent OOM.
Supports both socket and shared memory analysis.
"""
import sys
import json
import logging
import os

# Add parent directory to path to find modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../..')))

# Suppress logging to avoid interference with JSON output
logging.disable(logging.CRITICAL)

def analyze_socket(binary_path, socket_addr):
    """Analyze binary for socket usage"""
    try:
        from firmwell.backend.reason_fix.ipc_reason.analyzer_factory import analyze_binary
        
        results = analyze_binary(
            binary_path=binary_path,
            analyzer_types=['socket'],
            log_level='ERROR'  # Minimize logging
        )
        
        # Check if binary uses the socket address
        socket_results = results.get('results', {}).get('SocketAnalyzer', {})
        extracted_calls = socket_results.get('extracted_calls', [])
        
        uses_socket = False
        for call in extracted_calls:
            socket_params = call.get('socket_params', {})
            
            # Check for Unix socket match
            if 'socket_path' in socket_params:
                if socket_addr in socket_params['socket_path']:
                    uses_socket = True
                    break
            
            # Check for IP:PORT match
            if 'ip_address' in socket_params and 'port' in socket_params:
                ip_port = f"{socket_params['ip_address']}:{socket_params['port']}"
                if socket_addr == ip_port or str(socket_params['port']) in socket_addr:
                    uses_socket = True
                    break
        
        return {"success": True, "uses_socket": uses_socket}
    except Exception as e:
        return {"success": False, "error": str(e)}

def analyze_shm(binary_path):
    """Analyze binary for shared memory usage"""
    try:
        from firmwell.backend.reason_fix.ipc_reason.analyzer_factory import analyze_binary
        
        results = analyze_binary(
            binary_path=binary_path,
            analyzer_types=['shm'],
            log_level='ERROR'  # Minimize logging
        )
        
        # Check if binary uses shared memory
        shm_results = results.get('results', {}).get('ShmAnalyzer', {})
        extracted_calls = shm_results.get('extracted_calls', [])
        
        uses_shm = len(extracted_calls) > 0
        
        return {"success": True, "uses_shm": uses_shm, "shm_calls": len(extracted_calls)}
    except Exception as e:
        return {"success": False, "error": str(e)}

def main():
    if len(sys.argv) < 3:
        print(json.dumps({"success": False, "error": "Usage: analyze_binary_wrapper.py <socket|shm> <binary_path> [socket_addr]"}))
        sys.exit(1)
    
    analysis_type = sys.argv[1]
    binary_path = sys.argv[2]
    
    if analysis_type == "socket":
        if len(sys.argv) != 4:
            print(json.dumps({"success": False, "error": "Socket analysis requires socket_addr parameter"}))
            sys.exit(1)
        socket_addr = sys.argv[3]
        result = analyze_socket(binary_path, socket_addr)
    elif analysis_type == "shm":
        result = analyze_shm(binary_path)
    else:
        print(json.dumps({"success": False, "error": f"Unknown analysis type: {analysis_type}"}))
        sys.exit(1)
    
    print(json.dumps(result))

if __name__ == "__main__":
    main()