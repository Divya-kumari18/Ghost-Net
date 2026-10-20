"""Native YARA scanning. Compilation failures never become clean verdicts."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import hashlib
import yara

@dataclass(frozen=True)
class CompiledRules:
    engine: object
    source_count: int
    def __len__(self):
        return self.source_count

def parse_rules(text: str) -> CompiledRules:
    return CompiledRules(yara.compile(source=text), 1)

def load_rules_from_file(path: str | Path) -> CompiledRules:
    return CompiledRules(yara.compile(filepath=str(Path(path).resolve())), 1)

def load_rules_from_dir(directory: str | Path) -> CompiledRules:
    root = Path(directory).resolve(strict=True)
    paths = sorted(p for p in root.rglob('*') if p.is_file() and p.suffix.lower() in {'.yar', '.yara', '.rule'})
    if not paths:
        raise ValueError('No YARA rule files found')
    files = {'file_' + hashlib.sha256(str(p.relative_to(root)).encode()).hexdigest()[:20]: str(p) for p in paths}
    return CompiledRules(yara.compile(filepaths=files), len(files))

def match_rules(rules: CompiledRules, data: bytes) -> dict:
    output = {}
    for match in rules.engine.match(data=data, timeout=15):
        name = match.rule if match.namespace == 'default' else f'{match.namespace}:{match.rule}'
        meta = dict(match.meta)
        output[name] = {'match': True, 'matched_strings': [s.identifier for s in match.strings],
                        'label': meta.get('category') or meta.get('family') or match.rule,
                        'tags': list(match.tags), 'meta': meta}
    return output

def scan_file(rules: CompiledRules, file_path: str | Path, max_bytes: int = 25_000_000) -> dict:
    path = Path(file_path).resolve(strict=True)
    if max_bytes <= 0:
        raise ValueError('max_bytes must be positive')
    with path.open('rb') as stream:
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f'File exceeds the {max_bytes} byte scan limit; no verdict issued')
    matches = match_rules(rules, data)
    return {'path': str(path), 'matched_rules': list(matches), 'matches': matches, 'complete': True}

def scan_dir(rules: CompiledRules, directory: str | Path, max_bytes: int = 25_000_000) -> list:
    return [scan_file(rules, p, max_bytes) for p in sorted(Path(directory).rglob('*')) if p.is_file()]
