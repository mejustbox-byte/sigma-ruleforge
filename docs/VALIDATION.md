# Проверка выпуска 0.1.1

## Локально — 2026-10-09

- 50 unit/negative/regression tests: YAML limits/tags/duplicates, condition AST, modifiers, UUID, позиции ошибок, JSON limits/duplicates, большие STIX datasets, tactic tags и release publisher с fake HTTP service.
- Ruff lint и format check, документационный smoke.
- Golden и synthetic events: `examples/manifest.json`, четыре проверки.
- Pip-audit: известные уязвимости не обнаружены в применимых к платформе закреплённых runtime/dev/build/audit зависимостях на момент проверки. Аудит повторяется в CI и блокирует публикацию при ошибке.
- Официальный Enterprise ATT&CK 17.1 STIX bundle: 44 879 463 bytes, SHA-256 `0d1c347a4d584cf7e11ef46556c33b7689341443bf86299188d46c307274323b`. `attack-map` успешно сопоставил T1059.003 с Windows Command Shell в strict режиме. Это фиксированный совместимый набор, не заявление о самой свежей версии ATT&CK.

Источник snapshot: [официальный release-файл MITRE](https://github.com/mitre-attack/attack-stix-data/blob/master/enterprise-attack/enterprise-attack-17.1.json). Dataset скачивается отдельно, не включён в пакет. Перед использованием соблюдайте [условия MITRE ATT&CK](https://attack.mitre.org/resources/terms-of-use/).

## Воспроизводимость

```bash
uv sync --locked
uv run --locked pytest -q
uv run --locked ruff check src tests scripts/publish_release.py scripts/package_smoke.py
uv run --locked ruff format --check src tests scripts/publish_release.py scripts/package_smoke.py
python scripts/smoke.py
uv build
python scripts/package_smoke.py
uv export --locked --all-groups --no-hashes --no-emit-project --format requirements-txt -o audit-requirements.txt
uv run --locked --group audit pip-audit --no-deps --disable-pip -r audit-requirements.txt --format json
```

Аудит требует сети; CLI после установки работает офлайн. CI проверяет Python 3.12/3.14 на Linux/Windows. Фактический итог каждой сборки смотрите в GitHub Actions. Release job запускается только в upstream main после успешных verify и audit; создаёт draft, загружает wheel/sdist/SHA256SUMS и только затем публикует. Опубликованные assets автоматически не перезаписываются.

## Не выполнено

Реальная Splunk acceptance, Unicode/type/multivalue integration, контейнерный CVE-аудит и OCI isolation. Процедура Splunk: [SPLUNK-ACCEPTANCE.md](SPLUNK-ACCEPTANCE.md). Наличие успешных локальных fixtures не заменяет результат этих проверок.
