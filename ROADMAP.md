# Roadmap

## Реализовано в 0.1.1

- [x] Устанавливаемый пакет, offline CLI, lock-файл.
- [x] Bounded SafeLoader, duplicate/alias/tag protection.
- [x] Профиль валидации и condition AST.
- [x] Splunk adapter, строгий field pipeline.
- [x] Synthetic event runner и golden manifest.
- [x] Проверка ATT&CK external_id по локальному STIX bundle.
- [x] Unit/negative tests, инструкции и CI workflow.
- [x] Позиции YAML-ошибок, bounded JSON и полноразмерные STIX bundles.
- [x] Dependency audit и публикация wheel/sdist/SHA-256 после успешного CI.

## Следующие этапы

- [ ] Реальная Splunk-лаборатория и матрица типов/Unicode/multivalue.
- [ ] Точная позиция токенов внутри condition и source map pipeline-ошибок.
- [ ] Встроенный компактный ATT&CK snapshot с provenance; локальные bundles и tactic resolver уже поддерживаются.
- [ ] Расширение metadata schema и Sigma selectors/modifiers.
- [ ] Elastic и QRadar с собственными integration suites.
- [ ] OCI image и CVE-аудит образа; dependency audit включён в CI.

Офлайн профиль пригоден для локальной работы; полная Sigma-совместимость и production SIEM acceptance пока не заявляются.
