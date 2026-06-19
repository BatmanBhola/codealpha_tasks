# IDS Validation Tools

This workspace includes a simple Suricata-style alert monitor and validation tools.

## Files

- `nids.py`: tails `logs/eve.json` and triggers `execute_block()` for severity `1` alerts.
- `scapy_replay.py`: simulates alert generation by appending JSON alert lines to a log file.
- `evaluate_ids.py`: computes TP/FP/TN/FN metrics from a labeled JSON log.
- `tests/test_nids.py`: unit tests for `process_log_line()`.
- `tests/sample_eve.jsonl`: sample labeled log for evaluation.
- `run_tests.py`: simple test runner if `pytest` is not installed.

## Usage

Run the IDS monitor once against the current log file:

```bash
python nids.py --once --log logs/eve.json
```

Simulate an alert into a log file:

```bash
python scapy_replay.py --out logs/eve.json
```

Evaluate detection metrics from a labeled JSON log:

```bash
python evaluate_ids.py --log tests/sample_eve.jsonl
```

Run unit tests without `pytest`:

```bash
python run_tests.py
```
