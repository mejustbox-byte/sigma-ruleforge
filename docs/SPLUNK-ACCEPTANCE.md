# Приёмка на Splunk

## Назначение

Проверить эквивалентность offline event runner и Splunk SPL1 на синтетических событиях. Это отдельная лабораторная проверка; статус — **не выполнена**. Для неё нужен действующий авторизованный Splunk-стенд. Установка Splunk, ingestion и изменение его конфигурации этим CLI не выполняются.

## Подготовка

1. Запишите версию Splunk, ОС, extraction-конфигурацию, выбранные index/sourcetype и commit RuleForge.
2. Создайте отдельный index для синтетических данных. Настройте JSON extraction и строковые скалярные поля Image, CommandLine, User. Не используйте production-логи.
3. Скопируйте `examples/splunk.yml`; задайте буквальные scope и mapping для лаборатории.
4. Сверьте SHA-256 правила и pipeline из `ruleforge convert --format json`.

## Основная проверка

```bash
uv run --locked ruleforge test --manifest examples/manifest.json
uv run --locked ruleforge convert examples/process_creation.yml --pipeline examples/splunk.yml --output lab.spl
```

Отправьте три события из `examples/manifest.json` в отдельный index и выполните запрос из lab.spl вручную в Splunk Search. Ожидается совпадение только первого события. Значения `scope` должны соответствовать загруженным событиям; не добавляйте к запросу другие фильтры, меняющие логику.

## Матрица дополнительных случаев

| Случай | Что проверить |
| --- | --- |
| Missing/null/empty | isnull, exists, пустая строка; реальные extraction semantics |
| NOT | Отрицание селектора, в котором поле отсутствует |
| Escaping | Backslash, кавычки, literal `*`/`?`, переводы строк |
| Lists/all | OR и AND для нескольких значений одного поля |
| Numeric/boolean | Преобразование фактического типа Splunk в строку |
| Unicode | Различия case folding PCRE/Python, включая не-ASCII |
| Multivalue | Не поддерживается offline runner; не считать совместимым без отдельного adapter |
| Logsource | Scope отбирает ровно нужный набор telemetry |

Для каждого случая создайте новое синтетическое правило и labeled events, выполните offline runner и Splunk query, сравните ID совпавших событий. Любое несовпадение — блокирующий результат для соответствующего профиля: ограничьте профиль или исправьте adapter и повторите проверку. Golden diff сам по себе не является приёмкой.

## Результат

Сохраните локально таблицу: case, expected IDs, offline IDs, Splunk IDs, pass/fail, версия Splunk, commit, pipeline hash. Итог PASS допустим только после совпадения всех случаев заявленного профиля. Публично публикуйте лишь синтетические fixtures и очищенный результат; не добавляйте адреса стенда, credentials или реальные события.
