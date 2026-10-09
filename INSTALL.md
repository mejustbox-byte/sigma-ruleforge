# Установка и CLI

## Что доступно сейчас

Сейчас доступны только документы. Исполняемого пакета, CLI, lock-файла и тестового runner в репозитории ещё нет. Не выполняйте `pip install sigma-ruleforge`: публикация пакета проектом не подтверждена.

Получить документацию:

```bash
git clone https://github.com/mejustbox-byte/sigma-ruleforge.git
cd sigma-ruleforge
git status --short --branch
```

## План установки MVP

Выбран CPython 3.12.14 и uv 0.12.23 с отдельным virtualenv; обоснование и остальные версии — в [TECH-STACK.md](TECH-STACK.md). Затем появятся packaging metadata, lock-файл с проверяемыми версиями и команды установки из checkout. До этого нельзя обещать воспроизводимую установку зависимостей.

Не нужны SIEM credentials, cloud keys или production-логи. Зависимости и snapshots ATT&CK устанавливаются отдельно; обычный запуск планируется офлайн. Backend-зависимости должны быть optional и явно перечислены.

## Проект CLI — пока не реализован

Ниже показан будущий интерфейс; эти команды сейчас не работают:

```text
ruleforge validate rules/ --format json --strict
ruleforge convert rules/example.yml --backend splunk --pipeline mappings/lab.yml --output build/example.spl
ruleforge test --manifest tests/manifests/splunk.json
ruleforge attack-map rules/ --dataset datasets/attack.json --format json
ruleforge backends --format json
```

`validate` проверяет YAML и семантику; `convert` только создаёт запрос; `test` сравнивает fixtures с ожиданиями; `attack-map` сверяет теги с локальным snapshot; `backends` показывает capabilities. Пути в примерах также появятся только вместе с реализацией.

Планируемые exit codes: 0 — успешная обработка, 1 — ошибки правила/конвертации/теста, 2 — неправильные аргументы или конфигурация, 3 — IO/внутренняя ошибка. `--strict` переводит предупреждения в ошибки; `--format json` даёт машиночитаемый вывод. Для перезаписи output потребуется явный `--overwrite`. Окончательный интерфейс должен сопровождаться `--help` и smoke-тестами.

## Проверка после реализации

Сверить runtime и lock-файл; установить зависимости в изолированное окружение; запустить unit, negative, golden и CLI smoke tests согласно будущему CONTRIBUTING.md. На текущем этапе проверяются ссылки, достоверность статуса и отсутствие чувствительных данных в документах.

Ошибки и limitations описаны в [ARCHITECTURE.md](ARCHITECTURE.md). Уязвимости сообщайте согласно [SECURITY.md](SECURITY.md).

## Доступный smoke документации

В CPython 3.12.14 из корня репозитория выполните `python3 scripts/smoke.py`. Скрипт не устанавливает зависимости, не читает secrets и не обращается к сети. Cloud-проверка остаётся отдельным обязательным шагом.
