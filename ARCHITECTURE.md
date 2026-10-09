# Архитектура и профиль 0.1.1

Поток: bounded UTF-8 → YAML loader → профиль валидации → condition AST → backend или synthetic event runner. Реализация находится в `src/ruleforge/core.py`; CLI и manifest runner — в `src/ruleforge/cli.py`.

## Безопасность входа

Максимум 1 MiB на YAML, manifest и golden; ATT&CK JSON — до 128 MiB, 20 000 YAML-токенов, глубина YAML 40. Condition: максимум 512 токенов и вложенность 40; максимум 128 селекторов и 128 значений в списке. SafeLoader не создаёт произвольные объекты; anchors, aliases, explicit tags, duplicate keys и multiple documents запрещены до обработки правила. Mapping keys — строки. Это защита ресурсов, а не sandbox для произвольного недоверенного кода.

## Профиль Sigma

Нормативная основа: [Sigma Rules Specification 2.1.0](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html). Профиль требует title длиной 1..256, UUID id, непустой string-map logsource и detection.condition. Поддерживаются map selectors; поля внутри map соединяются AND, списки значений — OR, modifier all заменяет OR на AND. Неизвестные metadata сохраняются с предупреждением. Это частичная профильная валидация, не полная JSON Schema-проверка всех metadata.

Условия: NOT имеет приоритет над AND, AND над OR; скобки меняют порядок. `1 of pattern` и `all of pattern` расширяются по именам селекторов. Неизвестные имена и пустое расширение — ошибка. Операторы aggregation, correlation, filters, keyword selectors и lists-of-maps не поддерживаются.

Значения: строки, целые числа и booleans сравниваются как строки без учёта регистра. `*` обозначает любую последовательность, `?` один символ, backslash перед wildcard экранирует его. Contains/startswith/endswith меняют границы шаблона; преобразующие modifiers не комбинируются. `exists` принимает scalar boolean. Null совпадает с missing/null, пустая строка — только с пустой строкой. Event runner принимает только плоские scalar mapping.

## Splunk

Dialect: SPL1 search + where/match. Шаблоны преобразуются в экранированные PCRE с `(?is)`, `\A`/`\z`. `coalesce(..., false())` задаёт двухзначную логику при отсутствии поля, так что NOT применим к missing field. Null использует isnull, exists — isnull/isnotnull. Pipeline точно сопоставляет logsource и задаёт scope и fields; raw SPL во входе не исполняется и не вставляется.

Unicode case folding, field extraction, boolean string representation и multivalue fields зависят от Splunk: соответствие требует интеграционной проверки. Golden фиксирует текст запроса, а не доказывает его обнаруживающую способность. Backend не обращается к сети.

## ATT&CK

`attack-map` принимает локальный STIX bundle, сопоставляет external_id из references с source_name `mitre-attack`, сообщает revoked/deprecated/unknown и SHA-256 входного bundle. Встроенного snapshot нет; tactic shortnames сопоставляются с x-mitre-tactic, techniques/sub-techniques — с attack-pattern. Дубли внешних идентификаторов отклоняются. Версию, domain, provenance URL и условия использования dataset следует хранить рядом с локальным bundle. Синтетический unit fixture не является настоящим ATT&CK dataset.

## Модель угроз

Недоверенный YAML может содержать вредоносные tags, aliases, duplicate keys или ресурсоёмкие выражения; они ограничены loader и profile. Pipeline не допускает command injection через поля и scope. Нет eval, shell, plugin loading или сетевой отправки. Output защищён от случайной перезаписи. CLI читает пути manifest, указанные оператором: manifest не является изолированным sandbox. Ошибки IO могут содержать локальные пути; публично публикуйте отчёты после проверки. Зависимости закреплены lock-файлом; Dependency audit включён в CI; контейнерная изоляция не реализована.
