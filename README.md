# Sigma RuleForge

Офлайн CLI для проверки Sigma-правил, генерации Splunk SPL и тестирования правил на синтетических событиях. Версия 0.1.0 реализует ограниченный профиль Sigma Rules Specification 2.1.0.

## Быстрый старт

```bash
git clone https://github.com/mejustbox-byte/sigma-ruleforge.git
cd sigma-ruleforge
uv sync --locked
uv run --locked ruleforge validate examples/ --format json
uv run --locked ruleforge convert examples/process_creation.yml --pipeline examples/splunk.yml
uv run --locked ruleforge test --manifest examples/manifest.json
```

## Возможности

- Безопасный YAML: запрет дублирующихся ключей, anchors/aliases и explicit tags; ограничение размера, глубины и числа токенов.
- Проверка обязательных полей профиля, UUID, logsource, selectors и condition; дубликаты ID в пакете — ошибка.
- `and`, `or`, `not`, скобки, `1 of` и `all of` с wildcard-именами селекторов.
- Map selectors, списки значений, wildcards, contains/startswith/endswith/all/exists.
- Splunk SPL1 `where/match` с обязательным локальным pipeline и явным mapping каждого поля.
- Отдельные golden-проверки текста и поведенческие проверки синтетических событий.
- `attack-map` сверяет теги техник с предоставленным локальным STIX bundle; сохраняет digest, сообщает unknown/deprecated/revoked.

## Ограничения

Это профиль совместимости, а не полная реализация Sigma. Keyword/list-of-map selectors, regex/base64/cidr modifiers, float, correlation, filters, aggregation и multi-document YAML отклоняются. Backend только Splunk. ATT&CK bundle не включён: его происхождение и версию необходимо фиксировать при подготовке локального набора. Tactic-name теги пока выводятся как unknown.

Запросы не выполняются в SIEM. Локальный event runner использует плоские события со скалярными полями; он не моделирует Splunk extraction, multivalue fields и различия Unicode case folding. Интеграционная проверка на реальном Splunk ещё не выполнена. Готовность ограничена офлайн CLI и проверенным профилем.

## Документация

- [Установка и эксплуатация](INSTALL.md)
- [Архитектура и профиль](ARCHITECTURE.md)
- [Стек и воспроизводимость](TECH-STACK.md)
- [Разработка](CONTRIBUTING.md)
- [Roadmap](ROADMAP.md)
- [Изменения](CHANGELOG.md)
- [Безопасность](SECURITY.md)
- [MIT](LICENSE)

В публичных fixtures используются только синтетические данные. Не публикуйте production-логи, секреты или конфигурации клиентов.
