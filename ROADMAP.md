# Roadmap

Статус на 2026-10-09: документация подготовлена, runtime ещё не реализован. Чекбоксы отражают проверяемые результаты; даты релизов не обещаются.

## Этап 0 — контракт проекта

- [x] README, INSTALL, CHANGELOG, LICENSE и SECURITY.
- [x] Архитектура и contribution guide.
- [x] План CLI, диагностики, golden-наборов и ATT&CK mapping.
- [x] Выбрать runtime и стек; обоснование в TECH-STACK.md.
- [ ] Зафиксировать версию Sigma specification и окончательный профиль MVP.
- [ ] Проверить dependency lock и контейнер.

## Этап 1 — безопасный парсер и валидация

- [ ] Packaging, lock-файл, offline CLI skeleton и CI.
- [ ] Безопасный YAML loader, source positions, duplicate-key detection и resource limits.
- [ ] Schema/profile validation, selectors, condition AST и rule-id uniqueness.
- [ ] Negative fixtures и структурированная диагностика.

Приёмка: опасные YAML-конструкции отклоняются, некорректные правила имеют стабильные коды ошибок, тесты воспроизводимы без сети.

## Этап 2 — первый конвертер

- [ ] IR и версионированный field pipeline.
- [ ] Splunk SPL adapter с опубликованными capabilities.
- [ ] Golden-пары для поддержанных операторов и отказ для unsupported cases.
- [ ] CLI validate/convert/backends, atomic output и smoke tests.

Приёмка: отсутствуют молчаливые упрощения; quoting, mapping и логические edge cases проверены. Генерация запросов не выполняет их в SIEM.

## Этап 3 — поведение и MITRE ATT&CK

- [ ] Синтетические match/non-match fixtures и CLI test.
- [ ] Локальный STIX snapshot с version/provenance/digest.
- [ ] Technique/sub-technique resolver и diagnostics для unknown/deprecated/revoked IDs.
- [ ] CLI attack-map и отчёт с явно описанной методикой.

Приёмка: golden и поведенческие проверки разделены; mapping не называется доказанной эффективностью детектирования.

## Этап 4 — расширение

- [ ] Elastic adapter с явно выбранным dialect и QRadar AQL adapter.
- [ ] Матрица совместимости backend и интеграционные тесты в авторизованной лаборатории.
- [ ] Оценка pySigma и расширений: correlation, filters, multi-document YAML.
- [ ] Метрики FP/FN только для определённого labeled dataset с описанными ограничениями.

## Перед первым релизом

- [ ] Реальная инструкция установки, lock-файл, тестовые команды и CI.
- [ ] Threat model входных YAML/fixtures, зависимостей и output.
- [ ] Проверка лицензий fixtures/datasets и публичного OPSEC.
- [ ] Версия, release notes и документированные breaking changes.
