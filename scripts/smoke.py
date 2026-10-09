"""Offline documentation/bootstrap smoke. Does not read environment secrets."""
import re
import sys
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent.parent
    if sys.version_info < (3, 12):
        raise SystemExit('Expected Python 3.12 or newer')
    documents = (
        'README.md', 'ROADMAP.md', 'INSTALL.md', 'CHANGELOG.md', 'LICENSE',
        'SECURITY.md', 'ARCHITECTURE.md', 'CONTRIBUTING.md', 'TECH-STACK.md',
    )
    for name in documents:
        content = (root / name).read_text(encoding='utf-8')
        if not content.strip() or content.count('```') % 2:
            raise SystemExit(f'Invalid document: {name}')
        for target in re.findall(r'\]\(([^)]+)\)', content):
            if '://' not in target and not (root / target.split('#')[0]).is_file():
                raise SystemExit(f'Broken local link in {name}')
    print('PASS: runtime, required documents, local links, code fences; offline')
    print('Parser and backend verification: uv run --locked pytest -q')


if __name__ == '__main__':
    main()
