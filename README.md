# SNI Checker

Инструмент для проверки SNI. Данный скрипт не является моей разработкой и был взят из открытых источников в интернете.

## Установка

1. Создайте виртуальное окружение:
   ```bash
   python -m venv venv
   ```
2. Активируйте его:
   - Windows: `venv\Scripts\activate`
   - Linux/macOS: `source venv/bin/activate`
3. Установите зависимости:
   ```bash
   pip install -r reqs.txt
   ```

## Настройка и запуск

1. Отредактируйте `CONFIG` в файле `vless_tcp_reality.py`:
   - `server_ip`: IP вашего сервера.
   - `port`: Порт, на котором слушает xray (обычно 443).
2. Подготовьте список доменов в файле `sni.txt` (по одному на строку).
3. Запустите скрипт:
   ```bash
   python vless_tcp_reality.py
   ```
