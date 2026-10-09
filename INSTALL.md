# Установка и эксплуатация

Нужны Python 3.12+ и uv. Зависимости фиксируются в `uv.lock`; пакет устанавливается из checkout. Публикация в PyPI не заявляется.

```bash
git clone https://github.com/mejustbox-byte/sigma-ruleforge.git
cd sigma-ruleforge
uv sync --locked
uv run --locked ruleforge --help
uv run --locked ruleforge --version
```

После установки CLI работает без сети, credentials и доступа к SIEM.

```bash
uv run --locked ruleforge validate examples/process_creation.yml --format json --strict
uv run --locked ruleforge backends --format json
uv run --locked ruleforge convert examples/process_creation.yml --backend splunk --pipeline examples/splunk.yml --output result.spl
uv run --locked ruleforge test --manifest examples/manifest.json
uv run --locked ruleforge attack-map examples/process_creation.yml --dataset /path/to/enterprise-attack.json --format json
```

`validate` рекурсивно обрабатывает `.yml`/`.yaml` в каталоге. `--strict` переводит предупреждения в неуспешный результат. Для `--output` нужно одно правило; существующий файл сохраняется, если не указан `--overwrite`. Перезапись использует временный файл и atomic replace. JSON-вывод конвертации содержит digest правила и pipeline.

Коды выхода: 0 — успех; 1 — ошибка правила, pipeline или провал fixtures; 2 — неправильные CLI-аргументы/JSON-конфигурация; 3 — ошибка ввода/вывода. YAML-ошибки и семантические ошибки mapping-профиля содержат строки и колонки; ошибки condition указывают начало YAML-значения condition.

Pipeline содержит `version: 1`, точный `logsource`, `scope` и `fields`. Scope поддерживает literal `index`, `sourcetype`, `source`, `host`; вставка произвольного SPL запрещена. Имена целевых полей ограничены буквами ASCII, цифрами и underscore. У каждого используемого Sigma-поля должен быть mapping. [Рабочий пример](examples/splunk.yml).

Manifest содержит список `cases`: путь `rule`, `events` с `event` и boolean `match`, а для golden-проверки — `pipeline` и `golden`. Пути разрешаются относительно manifest. [Пример](examples/manifest.json). Fixtures и manifest должны быть доверенными локальными файлами.

## Локальная приёмка Splunk

В отдельной лаборатории подготовьте index и sourcetype для синтетических событий, проверьте extraction и типы полей. Сопоставьте каждое событие из manifest с результатом сгенерированного запроса. Отдельно проверьте missing/null/empty, отрицания, escaping, Unicode, числовые/boolean и multivalue значения. Зафиксируйте версию Splunk и pipeline. Успех Python fixtures не заменяет эту проверку.
