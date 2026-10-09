# Стек и воспроизводимость

Python 3.12+; argparse/JSON/pathlib/dataclasses из stdlib; PyYAML 6.0.3 SafeLoader; setuptools для packaging; pytest и Ruff для проверки. Конкретные версии и hashes зависимостей закреплены `uv.lock`.

Python подходит для офлайн CLI и проверки Sigma; собственный ограниченный condition AST делает профиль явным. PyYAML заменяет планировавшийся ruamel.yaml: позиции синтаксических ошибок доступны, duplicate keys и resource limits реализованы отдельно. Source map семантических ошибок — дальнейшее развитие. pySigma, Docker, web server, база данных и cloud credentials не используются.

```bash
uv sync --locked
uv run --locked pytest -q
uv run --locked ruff check src tests
uv run --locked ruff format --check src tests
uv build
```

CI проверяет Python 3.12 и 3.14 на Ubuntu/Windows, fixtures, lint, packaging. Actions имеют `contents: read` и закреплены commit SHA. Runtime security patch определяется установленной поддерживаемой версией Python; устаревшая точная patch больше не требуется bootstrap-скриптом. Зависимости обновляются с повторными тестами и review lock diff. OCI image и CVE-аудит не заявляются.
