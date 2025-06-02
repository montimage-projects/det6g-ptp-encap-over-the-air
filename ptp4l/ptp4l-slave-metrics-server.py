import json
import re
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import time
from collections import deque

# Regex to parse ptp4l log lines
line_pattern = re.compile(
    r"master offset\s+(-?\d+).*?freq\s+([+-]?\d+).*?path delay\s+([+-]?\d+)"
)

# Rolling buffer
MAX_METRICS = 40
metrics_history = deque(maxlen=MAX_METRICS)

def follow_log(log_path):
    try:
        with open(log_path, "r") as f:
            f.seek(0, 2)  # Seek to end of file
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue

                match = line_pattern.search(line)
                if match:
                    sample = {
                        "timestamp": time.time() * 1000,
                        "offset_ns": int(match.group(1)),
                        "frequency_offset_ppb": int(match.group(2)),
                        "path_delay_ns": int(match.group(3))
                    }
                    metrics_history.append(sample)
                else:
                    print("not found any metrics", line)
    except FileNotFoundError:
        print(f"Log file not found: {log_path}")
    except Exception as e:
        print(f"Error reading log file: {e}")

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        metrics = list(metrics_history)
        metric = self.path[1:]
        if len(metrics) > 0 and metric in metrics[0]:
            metrics = [
                {"timestamp": m["timestamp"], metric: m[metric]}
                for m in metrics_history
            ]
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(metrics).encode())

def run_server(log_path, port):
    print(f"Reading log file: {log_path}")
    print(f"Starting HTTP server on port {port}...")

    threading.Thread(target=follow_log, args=(log_path,), daemon=True).start()
    server = HTTPServer(('', port), MetricsHandler)
    server.serve_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PTP Metrics HTTP Server")
    parser.add_argument("--log", required=True, help="Path to ptp4l log file")
    parser.add_argument("--port", type=int, default=8000, help="Port to run HTTP server on (default: 8000)")

    args = parser.parse_args()
    run_server(args.log, args.port)
