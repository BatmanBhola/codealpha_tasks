"""Evaluate IDS detection metrics from labeled JSON logs.

This module reads a JSON log file and computes basic detection metrics
(true positive, false positive, recall, precision, accuracy, F1).
"""

import argparse
import json
import os
from typing import Iterable

from nids import process_log_line


def parse_label_file(label_path):
    """Read a separate label file with one label per line."""
    with open(label_path, 'r', encoding='utf-8') as f:
        for line in f:
            yield line.strip()


def read_lines(path: str) -> Iterable[str]:
    """Yield non-empty stripped lines from a text file."""
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            yield line.strip()


def compute_metrics(predictions, truths):
    """Compute TP/FP/TN/FN counts for binary IDS predictions."""
    tp = fp = tn = fn = 0
    for pred, truth in zip(predictions, truths):
        positive = pred
        malicious = truth.lower() in ('malicious', 'true', '1', 'yes', 'attack')
        if positive and malicious:
            tp += 1
        elif positive and not malicious:
            fp += 1
        elif not positive and malicious:
            fn += 1
        else:
            tn += 1
    return tp, fp, tn, fn


def choose_truth(expected_labels, idx, parsed, expected_field):
    """Choose the expected label for a log line from labels or JSON content."""
    if expected_labels is not None:
        return expected_labels[idx] if idx < len(expected_labels) else 'benign'
    return str(parsed.get(expected_field, 'benign'))


def evaluate(log_path, expected_field, label_path):
    """Evaluate IDS predictions against labeled ground truth.

    Returns a metrics dictionary describing precision, recall, accuracy,
    and F1 score for the current log file.
    """
    if not os.path.exists(log_path):
        raise FileNotFoundError(log_path)

    predictions = []
    truths = []
    expected_labels = list(parse_label_file(label_path)) if label_path else None

    for idx, line in enumerate(read_lines(log_path)):
        if not line:
            continue

        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue

        action, _ = process_log_line(parsed)
        predictions.append(action == 'block')
        truths.append(choose_truth(expected_labels, idx, parsed, expected_field))

    if not truths:
        raise ValueError('No labeled examples found')

    tp, fp, tn, fn = compute_metrics(predictions, truths)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return {
        'true_positive': tp,
        'false_positive': fp,
        'true_negative': tn,
        'false_negative': fn,
        'precision': precision,
        'recall': recall,
        'accuracy': accuracy,
        'f1_score': f1,
    }


def main():
    """Parse command-line arguments and print IDS evaluation metrics."""
    parser = argparse.ArgumentParser(
        description='Evaluate IDS detection metrics from a labeled JSON log.'
    )
    parser.add_argument(
        '--log',
        default='tests/sample_eve.jsonl',
        help='Input JSON log file path',
    )
    parser.add_argument(
        '--expected-field',
        default='expected_label',
        help='JSON field containing the true label',
    )
    parser.add_argument(
        '--label-file',
        help='Optional separate line-by-line label file',
    )
    args = parser.parse_args()

    metrics = evaluate(args.log, args.expected_field, args.label_file)
    print('Detection metrics for', args.log)
    for key, value in metrics.items():
        if isinstance(value, float):
            print(f'{key}: {value:.3f}')
        else:
            print(f'{key}: {value}')


if __name__ == '__main__':
    main()
