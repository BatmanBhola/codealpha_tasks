"""Unit tests for the NIDS alert processing helper.

These tests validate `process_log_line()` for alert detection, ignore
cases, warnings, and invalid JSON handling.
"""

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from nids import process_log_line  # noqa: C0413 pylint: disable=C0413


def test_block_on_severity_int():
    """Verify severity 1 as integer triggers a block action."""
    line = json.dumps({
        "event_type": "alert",
        "alert": {"signature": "TestSig", "severity": 1},
        "src_ip": "1.2.3.4",
    })
    action, info = process_log_line(line)
    assert action == 'block'
    assert info['src_ip'] == '1.2.3.4'


def test_block_on_severity_str():
    """Verify severity '1' as string also triggers a block action."""
    line = json.dumps({
        "event_type": "alert",
        "alert": {"signature": "TestSig", "severity": "1"},
        "src_ip": "5.6.7.8",
    })
    action, info = process_log_line(line)
    assert action == 'block'
    assert info['src_ip'] == '5.6.7.8'


def test_warn_missing_src_ip():
    """Verify a severity-1 alert with no source IP returns warn."""
    line = json.dumps({
        "event_type": "alert",
        "alert": {"signature": "NoSrc", "severity": 1}
    })
    action, info = process_log_line(line)
    assert action == 'warn'
    assert info.get('reason') == 'missing_src_ip'


def test_ignore_non_alert_event():
    """Verify non-alert events are ignored."""
    line = json.dumps({
        "event_type": "flow",
        "some": "data"
    })
    action, _ = process_log_line(line)
    assert action == 'ignore'


def test_invalid_json_line():
    """Verify invalid JSON returns the invalid action."""
    line = '{not a json}\n'
    action, _ = process_log_line(line)
    assert action == 'invalid'
