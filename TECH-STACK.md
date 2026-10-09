# Выбор стека

Решение от 2026-10-09. Стек выбран; полная установка пакета и отдельная Codex Cloud среда ещё не проверены. Этот документ не объявляет проект готовым.

## Стек и обоснование

| Слой | Выбор и версия | Причина |
| --- | --- | --- |
| Runtime | CPython 3.12.14; профиль MVP `>=3.12,<3.13` | Зрелая экосистема YAML/Sigma, простой CLI; базовый runtime доступен и проверен локально |
| Пакетный менеджер | uv 0.12.23 | Единый workflow virtualenv, resolver и lock; эта версия доступна локально |
| Packaging | pyproject.toml, setuptools `>=80,<81` | Стандартный Python packaging; конкретная patch будет закреплена в lock |
| YAML | ruamel.yaml `>=0.18,<0.19`, safe loader | Source positions и контроль duplicate keys; unsafe loading запрещён |
| Тесты | pytest `>=9,<10`; stdlib smoke без зависимостей | Параметризованные negative/golden fixtures без отдельного snapshot framework |
| Lint / формат | Ruff `>=0.14,<0.15` | Одна утилита для lint и formatting; фиксировать patch в lock |
| Контейнеризация | Docker Engine 28.x, OCI Linux; CPython 3.12.14 slim | Изолированный воспроизводимый CLI; digest образа выбирается и проверяется перед build |
| CI | GitHub Actions, Linux runner `ubuntu-24.04` | Нативная интеграция с единственным репозиторием проекта |

Диапазоны зависимостей — выбранные совместимые линии, а не воспроизводимый lock. Их доступность, совместимость и security advisories проверяются перед первой установкой. Exact pins и hashes появятся в uv.lock; до этого dependency stack остаётся непроверенным. Изменения patch runtime/uv — отдельный review для обновлений безопасности, а не автоматическое использование latest.

## Архитектурные решения

CLI — стандартный argparse, JSON — stdlib, IR — dataclasses и типизированные структуры. Не нужны web server, база данных или облачные ключи. Сначала один backend. pySigma — кандидат последующей интеграции, не текущая dependency: перед её добавлением проверить source positions, возможности backend и лицензии. Custom eval и исполнение YAML запрещены.

Python выбран ради простоты поддержки и зрелой Sigma-экосистемы. Go/Rust дают удобные standalone binaries, но потребовали бы больше собственной работы по совместимости Sigma. Сложность distribution Python ограничивается uv и будущим OCI image.

## Воспроизводимость и CI — план реализации

После добавления pyproject.toml и uv.lock использовать `uv sync --locked` и `uv run --locked`: несоответствие metadata должно быть ошибкой, а не автоматическим обновлением lock. CI запускает smoke, Ruff check/format check, pytest, negative и golden tests; lock обновляется только отдельным PR.

GitHub Actions получают только `contents: read`; сторонние actions закрепляются полным commit SHA после проверки. Не применять pull_request_target для запуска чужого кода. Публикация и credentials не нужны. Workflow пока не добавлен, CI run не заявляется.

Контейнер запускается non-root, с read-only rootfs, временным tmpfs, удалёнными capabilities, no-new-privileges, network none и лимитами CPU/memory/PIDs. Не монтировать Docker socket или production filesystem. Dockerfile и проверка реального контейнера предстоят; контейнер не считается самостоятельной границей для исполнения произвольного вредоносного кода.

## Отдельная Codex Cloud среда — обязательный незавершённый шаг

Среда должна быть связана только с `mejustbox-byte/sigma-ruleforge`; repository access ограничивается этим репозиторием. Не добавлять secrets, SIEM endpoints и customer datasets. После фиксации этого документа создать/выбрать среду в интерфейсе Codex Cloud, выбрать ветку с документацией и записать environment ID и проверенный commit без токенов.

Setup: проверить CPython 3.12.14 и uv 0.12.23; запустить `python3 scripts/smoke.py`. После появления lock — добавить `uv sync --locked`. Agent internet отключён; setup network только для проверенных источников dependencies. Не устанавливать пакеты через непроверенный curl-to-shell.

Проверка среды: smoke должен завершиться кодом 0; список настроенных secrets должен быть пустым; проверить отсутствие credentials в настройках и tracked files без вывода их значений. Не путать отсутствие секретов в Git с отсутствием секретов в самой среде. Публично сохранять только безопасный результат проверки, commit и runtime versions.

Из текущего чата инструмента создания/привязки Codex Cloud среды нет. Клонирование GitHub и локальный smoke не заменяют эту операцию. Environment ID, Cloud smoke и проверка Cloud secrets сейчас не подтверждены.

## Источники

- [Поддержка Python](https://devguide.python.org/versions/)
- [uv locking/sync](https://docs.astral.sh/uv/concepts/projects/sync/)
- [pytest compatibility](https://docs.pytest.org/en/stable/backwards-compatibility.html)
- [Ruff](https://docs.astral.sh/ruff/formatter/)
