# Sigma RuleForge 0.1.1

Рабочий офлайн инструмент для валидации ограниченного профиля Sigma, конвертации в Splunk SPL1 и проверки синтетических событий.

## Изменения

- YAML-диагностики структуры, selectors и condition содержат строки и колонки.
- JSON-вход ограничен размером, глубиной и числом узлов; duplicate keys и NaN/Infinity запрещены.
- ATT&CK STIX bundle имеет отдельный лимит 128 MiB; поддерживаются techniques, sub-techniques и tactic shortnames.
- Неоднозначные ATT&CK IDs отклоняются; revoked/deprecated/unknown отображаются явно.
- Исправлена нормализация UUID для проверки дубликатов.
- Добавлены dependency audit и публикация wheel/sdist с SHA-256 после успешного CI.

## Установка

Установите wheel из Assets в Python 3.12+ virtualenv либо используйте checkout и `uv sync --locked`. PyYAML 6.0.3 — единственная runtime-зависимость.

## Проверки и границы

CI проверяет Linux/Windows и Python 3.12/3.14, отрицательные входы, conditions/modifiers, golden и synthetic events, lint, форматирование и сборку. Dependency audit проверяет известные уязвимости по публичной базе на момент запуска; это не доказательство отсутствия неизвестных уязвимостей.

Поддерживается один backend и частичный профиль Sigma 2.1.0. Сгенерированные запросы не выполняются автоматически. Реальная Splunk integration acceptance не выполнена; локальная процедура описана в `docs/SPLUNK-ACCEPTANCE.md`. Полный ATT&CK snapshot не включён в пакет. OCI image, Elastic и QRadar в этот выпуск не входят.
