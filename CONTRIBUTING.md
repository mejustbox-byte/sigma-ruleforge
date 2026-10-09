# Разработка

Установка описана в [INSTALL.md](INSTALL.md). Из корня checkout:

```bash
uv sync --locked
uv run --locked pytest -q
uv run --locked ruff check src tests
uv run --locked ruff format --check src tests
uv run --locked ruleforge test --manifest examples/manifest.json
python scripts/smoke.py
uv build
```

Изменения семантики требуют положительных и отрицательных fixtures; конвертация — golden и отдельные поведенческие проверки. Golden обновляется после проверки логики, а не автоматически для подавления ошибки. Новая конструкция должна быть либо поддержана и документирована, либо явно отклонена.

Документы продукта оформляются на русском. PR описывает изменение поведения и результаты проверки. Публичные fixtures содержат только синтетические данные. Политика сообщения об уязвимостях: [SECURITY.md](SECURITY.md).
