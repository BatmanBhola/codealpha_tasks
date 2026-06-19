"""Simple NIDS monitor that tails an eve.json log and triggers actions.

This module watches a Suricata/Zeek-style JSON log file for alert events
and invokes `execute_block()` for high-severity alerts.
"""

import json
import time
import os
import logging

LOG_PATH = r"C:\Users\rajt4\Desktop\logs\eve.json"


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")


def monitor_alerts():
    """Tail the JSON log and trigger response actions for alerts.

    Wait for the log file to appear, then read new JSON lines and call
    `execute_block()` for high-severity alerts (severity == 1).
    """
    print("[*] Active Response Engine Running. Monitoring alerts...")

    while not os.path.exists(LOG_PATH):
        time.sleep(1)

    with open(LOG_PATH, 'r', encoding='utf-8') as f:
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                print("...waiting for new log lines...")
                time.sleep(0.5)
                continue

            action, info = process_log_line(line)

            if action == 'invalid':
                logging.debug("Skipping incomplete or invalid JSON line")
                continue
            if action == 'ignore':
                continue

            signature = info.get('signature')
            severity = info.get('severity')
            logging.info("[CRITICAL ALERT] %s | Severity: %s", signature, severity)

            if action == 'block':
                execute_block(info.get('src_ip'))
            elif action == 'warn':
                logging.warning("Alert severity 1 but src_ip missing; cannot block")


def process_log_line(line):
    """Parse a single JSON log line and decide what action to take.

    Returns a tuple (action, info) where `action` is one of:
      - 'block'  : severity == 1 and src_ip present
      - 'warn'   : severity == 1 but src_ip missing
      - 'alert'  : alert event but not severity 1
      - 'ignore' : not an alert event
      - 'invalid': JSON decode error

    `info` is a dict containing parsed fields useful for logging/tests.
    """
    try:
        if isinstance(line, dict):
            log_data = line
        else:
            log_data = json.loads(line)
    except json.JSONDecodeError:
        return ('invalid', {'reason': 'json_decode_error'})

    if log_data.get('event_type') != 'alert':
        return ('ignore', {})

    alert_info = log_data.get('alert', {})
    src_ip = log_data.get('src_ip')
    signature = alert_info.get('signature')
    severity = alert_info.get('severity')

    # Normalize severity to integer when possible
    try:
        sev_int = int(severity) if severity is not None else None
    except (ValueError, TypeError):
        sev_int = None

    info = {'src_ip': src_ip, 'signature': signature, 'severity': severity}

    if sev_int == 1:
        if src_ip:
            return ('block', info)
        else:
            return ('warn', {'reason': 'missing_src_ip', **info})

    return ('alert', info)


def execute_block(ip):
    """Perform an automated network block for the given IP.

    This is a placeholder for platform-specific commands that would update
    firewall rules (iptables, ufw, etc.). In production this should be
    implemented carefully (use subprocess with proper escaping and checks).
    """
    print(f"[ACTION] Automated block rule generated for malicious host: {ip}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--once',
        action='store_true',
        help='Process existing log file once and exit',
    )
    parser.add_argument(
        '--log',
        default=LOG_PATH,
        help='Path to eve.json log file',
    )
    args = parser.parse_args()

    if args.once:
        def iterate_json_objects(s):
            """Yield JSON objects from a string that may contain concatenated JSON."""
            decoder = json.JSONDecoder()
            idx = 0
            length = len(s)
            while idx < length:
                try:
                    obj, end = decoder.raw_decode(s, idx)
                except json.JSONDecodeError:
                    break
                yield obj
                idx = end


        def process_file_once(path):
            """Read a log file once and process each JSON object."""
            if not os.path.exists(path):
                print('Log file not found:', path)
                raise SystemExit(1)
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    found = False
                    for obj in iterate_json_objects(line):
                        found = True
                        action, info = process_log_line(obj)
                        if action == 'invalid' or action == 'ignore':
                            continue
                        signature = info.get('signature')
                        severity = info.get('severity')
                        logging.info("[CRITICAL ALERT] %s | Severity: %s", signature, severity)
                        if action == 'block':
                            execute_block(info.get('src_ip'))
                        elif action == 'warn':
                            logging.warning("Alert severity 1 but src_ip missing; cannot block")
                    if not found:
                        # line didn't contain valid JSON objects
                        continue

        process_file_once(args.log)
    else:
        monitor_alerts()
