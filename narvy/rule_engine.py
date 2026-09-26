import yaml
import re
import os
from typing import List, Dict, Any

from .android_rule_context import apply_gate
from . import comment_filter

def load_rules_from_dir(rules_directory: str) -> List[Dict[str, Any]]:
    """Load rules from a directory of YAML files."""
    all_rules = []
    for filename in os.listdir(rules_directory):
        if filename.endswith(('.yml', '.yaml')):
            with open(os.path.join(rules_directory, filename), 'r') as f:
                rules_in_file = yaml.safe_load(f)
                if isinstance(rules_in_file, list):
                    all_rules.extend(rules_in_file)
    # YAML `|` block scalars keep a trailing newline; strip it off patterns.
    for rule in all_rules:
        pattern = rule.get('pattern')
        if isinstance(pattern, str):
            rule['pattern'] = pattern.strip()
    return all_rules

def run_rules_on_file(file_path: str, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run the rules against a single file, one finding per occurrence."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Comment-aware post-filter, built only when a comment opener is present.
        comment_mask = None
        if '//' in content or '/*' in content:
            comment_mask = comment_filter.build_comment_mask(content)

        for rule in rules:
            for match in re.finditer(rule['pattern'], content, re.MULTILINE):
                if comment_mask is not None and comment_mask[match.start()]:
                    continue
                line = content.count('\n', 0, match.start()) + 1
                finding = {
                    "rule_id": rule['id'],
                    "file_path": file_path,
                    "name": rule['name'],
                    "severity": rule['severity'],
                    "confidence": rule.get('confidence', 'MEDIUM'),
                    "details": rule['details'],
                    "line": line,
                }
                # Fail-open: any gate error keeps the finding.
                finding = apply_gate(rule['id'], content, match, finding)
                if finding is not None:
                    findings.append(finding)
    except Exception as e:
        print(f"Could not analyze file {file_path}: {e}")
    return findings