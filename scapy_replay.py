"""Minimal, non-destructive harness to simulate alerts for `nids.py`.

By default this script runs in dry-run mode and writes simulated Suricata
`eve.json` alert lines into the `logs/eve.json` file so `monitor_alerts()`
can pick them up. If Scapy is installed and a PCAP is provided, it will
parse packets and create one alert per IP packet found.

Usage examples:
  python scapy_replay.py --out logs/eve.json
  python scapy_replay.py --pcap sample.pcap --out logs/eve.json

The script is careful not to send raw packets on the network; it only
generates JSON log lines for testing the IDS pipeline.
"""

import argparse
import json
import os
import time
from datetime import datetime, timezone

try:
    from scapy.all import rdpcap
    from scapy.layers.inet import IP
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False


def make_alert_line(src_ip, signature="Simulated Attack", severity=1):
    """Create a JSON alert line for a simulated attack event."""
    obj = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "event_type": "alert",
        "src_ip": src_ip,
        "alert": {"signature": signature, "severity": severity}
    }
    return json.dumps(obj)


def write_alerts(out_path, alerts, delay=0.1):
    """Append alert JSON lines to the output log file with an optional delay."""
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'a', encoding='utf-8') as f:
        for a in alerts:
            f.write(a + '\n')
            f.flush()
            print('Wrote alert for', json.loads(a).get('src_ip'))
            time.sleep(delay)


def pcap_to_alerts(pcap_path, severity=1):
    """Parse a PCAP file and generate alert JSON lines for each IP packet."""
    if not HAVE_SCAPY:
        raise RuntimeError('Scapy not available')

    pkts = rdpcap(pcap_path)
    alerts = []
    for p in pkts:
        if IP in p:
            src = p[IP].src
            alerts.append(make_alert_line(src, signature='PCAP-Simulated', severity=severity))
    return alerts


def main():
    """Run the alert replay harness and write simulated alerts to the log file."""
    p = argparse.ArgumentParser()
    p.add_argument('--pcap', help='Path to PCAP file to parse')
    p.add_argument('--out', default='logs/eve.json', help='Output eve.json path')
    p.add_argument('--severity', type=int, default=1, help='Severity to set on simulated alerts')
    p.add_argument('--delay', type=float, default=0.1, help='Delay between writing alerts')
    args = p.parse_args()

    alerts = []
    if args.pcap:
        if not HAVE_SCAPY:
            print('Scapy not installed; cannot parse PCAP. Install scapy or omit --pcap')
            return
        print('Parsing PCAP', args.pcap)
        alerts = pcap_to_alerts(args.pcap, severity=args.severity)
        if not alerts:
            print('No IP packets found in PCAP; generating a synthetic alert instead')

    if not alerts:
        # fallback synthetic alert
        alerts = [make_alert_line('1.2.3.4', signature='Synthetic-Test', severity=args.severity)]

    write_alerts(args.out, alerts, delay=args.delay)


if __name__ == '__main__':
    main()
