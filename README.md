# SNI Checker

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/renkagod/sni-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/renkagod/sni-checker/actions/workflows/ci.yml)
[![Donate](https://img.shields.io/badge/Donate-crypto-ea4aaa?logo=githubsponsors&logoColor=white)](https://github.com/renkagod/.github/blob/main/DONATE.md)

Инструмент для проверки SNI (Server Name Indication) против вашего сервера Xray/Reality: устанавливает TLS-соединение с подменой SNI и сохраняет рабочие домены.

Скрипт дополнен на основе исходника из открытых источников; доработки в этом репозитории распространяются под [MIT License](LICENSE).

> **Важно:** инструмент предназначен только для образовательных целей и тестирования собственной инфраструктуры. Вы несёте ответственность за соблюдение законодательства и правил провайдеров при использовании списков доменов и результатов сканирования.

## Особенности

- Параллельная асинхронная проверка SNI против IP/порта Xray/Reality
- Результаты в `scan_out/` (JSONL + `working.txt`)
- Настраиваемые таймаут, concurrency, strict-режим

## Быстрый старт

Требования: Python 3.10+.

```bash
git clone https://github.com/renkagod/sni-checker.git
cd sni-checker
python -m venv venv
```

Активация окружения:

- **Windows:** `venv\Scripts\activate`
- **Linux/macOS:** `source venv/bin/activate`

```bash
pip install -r requirements.txt
```

## Использование

Положите домены в `sni.txt` (по одному на строку) или укажите каталог с несколькими `.txt` файлами. Строки, начинающиеся с `#`, игнорируются. В репозитории уже есть примерный список `sni.txt` — при необходимости замените его своим.

```bash
python sni_checker.py -i 1.2.3.4
```

### Аргументы

| Флаг | Описание |
|------|----------|
| `-i`, `--ip` | IP сервера (**обязательно**) |
| `-p`, `--port` | Порт Xray/Reality (по умолчанию: `443`) |
| `-t`, `--timeout` | Таймаут соединения, сек (по умолчанию: `5.0`) |
| `-c`, `--concurrency` | Параллельных проверок (по умолчанию: `100`) |
| `-f`, `--sni-path` | Файл или папка со списками SNI (по умолчанию: `sni.txt`) |
| `-o`, `--out-dir` | Базовая папка для результатов (по умолчанию: `scan_out`) |
| `-s`, `--strict` | Требовать корректный HTTP-ответ |
| `--shuffle` | Перемешать список перед проверкой |
| `--no-color` | Отключить цветной вывод |
| `--no-fsync` | Не вызывать `fsync` после каждой записи |

### Примеры

```bash
python sni_checker.py -i 1.2.3.4 -p 8443
python sni_checker.py -i 1.2.3.4 -t 2.5 -c 200 --shuffle
```

## Результаты

Каждый запуск создаёт каталог `scan_out/run_YYYY-MM-DD_HH-MM-SS/`:

- `working.txt` — только рабочие SNI
- `results.jsonl` — полный лог (JSON Lines)

Статусы в логе: `WORKING` (TLS прошёл), `BLOCKED` (таймаут/сброс/SSL-ошибка), `INCONCLUSIVE` (прочие случаи).

## Поддержать проект

Если проект оказался полезен, можно поддержать его криптой: [адреса для доната](https://github.com/renkagod/.github/blob/main/DONATE.md).

## Лицензия

[MIT](LICENSE) — Copyright (c) 2026 [renkagod](https://github.com/renkagod).
