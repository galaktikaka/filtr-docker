# filtr-docker — фильтр образов перед prod

## Запуск

```bash
# собрать эталонный «плохой» образ
docker build -t bad-container:test ../bad-container

# сканирование
./scan-image.sh bad-container:test
# или
python3 scanner.py bad-container:test --report reports/scan.json
python3 scanner.py bad-container:test --guidance reports/how-to-fix.txt
```

Коды выхода: `0` — ок, `1` — нарушения, `2` — ошибка docker/распаковки.

При **FAILED** в консоль выводятся рекомендации: дежурные фразы, ссылки на документацию Docker, советы по типу нарушения, примеры `.dockerignore` и Dockerfile. Отключить: `--no-hints`. Сохранить только в файл: `--guidance PATH`.

## Модули

| Файл | Назначение |
|------|------------|
| `scan-image.sh` | CI-обёртка, `trap` cleanup |
| `scanner.py` | `docker save`, распаковка слоёв, обход |
| `rules.py` | списки правил и `check_file()` |
| `report.py` | stdout + JSON |
| `dashboard_server.py` | локальный веб-сервер Control Tower |
| `webui/*` | фронтенд (история, KPI, детали findings) |

## Веб-оболочка (Control Tower MVP)

```bash
cd filtr-docker
python3 dashboard_server.py --host 127.0.0.1 --port 8765
```

После запуска открыть в браузере: `http://127.0.0.1:8765`

Что уже есть в MVP:

- запуск сканирования образа из UI (`POST /api/scan`);
- live-статус сервера и блокировка параллельного запуска;
- история сканов (до 100 последних) в `reports/web/history.jsonl`;
- KPI по всем проверкам (сканы, fail, critical, warning);
- детальная карточка скана (findings, рекомендации, stdout/stderr);
- вывод номера строки и фрагмента строки для контентных нарушений.

## Заметки

- Симлинки при обходе не следуем (`followlinks=False`).
- Бинарники не читаем для regex (см. `rules.is_binary_file`).
- Правила по содержимому — только в слое приложения (`/app`, `/opt`, …), не по всему Debian base (см. `rules.in_application_layer`).
- `CONTAINER_SCAN_WORKDIR` — каталог распаковки (задаёт `scan-image.sh`).
