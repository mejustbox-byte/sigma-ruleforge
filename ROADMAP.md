# Roadmap

## Реализовано в 0.1.0

- [x] Устанавливаемый пакет, offline CLI, lock-файл.
- [x] Bounded SafeLoader, duplicate/alias/tag protection.
- [x] Профиль валидации и condition AST.
- [x] Splunk adapter, строгий field pipeline.
- [x] Synthetic event runner и golden manifest.
- [x] Проверка ATT&CK external_id по локальному STIX bundle.
- [x] Unit/negative tests, инструкции и CI workflow.

## Следующие этапы

- [ ] Реальная Splunk-лаборатория и матрица типов/Unicode/multivalue.
- [ ] Полный source map семантических диагностик.
- [ ] Версионированный ATT&CK snapshot с provenance и tactic resolver.
- [ ] Расширение metadata schema и Sigma selectors/modifiers.
- [ ] Elastic и QRadar с собственными integration suites.
- [ ] OCI image и CVE-аудит зависимостей/образа.

Офлайн профиль пригоден для локальной работы; полная Sigma-совместимость и production SIEM acceptance пока не заявляются.
