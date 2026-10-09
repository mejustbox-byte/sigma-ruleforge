# История изменений

## 0.1.1 — 2026-10-09

Позиции семантических YAML-ошибок, ограниченный JSON parser, большие ATT&CK bundles и tactic tags. Pipeline и dataset загружаются один раз на пакет правил. Добавлены dependency audit, проверяемый release workflow, SHA-256 assets и процедура Splunk-лаборатории. Golden reader нормализует LF/CRLF для Windows; Actions обновлены на закреплённые Node 24 версии. Исправлены команды быстрого старта для каталога с rules и pipelines.

## 0.1.0 — 2026-10-09

Первый исполняемый офлайн выпуск: CLI validate/convert/test/attack-map/backends, bounded YAML loader, condition AST, Splunk SPL1 и строгий pipeline, synthetic event fixtures и golden-проверки. Добавлены packaging, dependency lock, CI workflow и рабочие инструкции.

Ограничения: один backend и частичный профиль Sigma 2.1.0; без встроенного ATT&CK snapshot, контейнера и реальной Splunk integration acceptance.
