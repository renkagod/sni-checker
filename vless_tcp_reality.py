#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import asyncio
import json
import os
import random
import signal
import ssl
import sys
import time
import traceback
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
    USE_COLOR = True
except Exception:
    class _F: GREEN=""; RED=""; YELLOW=""
    class _S: RESET_ALL=""
    Fore = _F(); Style = _S()
    USE_COLOR = False

from tqdm import tqdm

CONFIG = {
    "server_ip": "",                 # Без хардкода
    "port": 443,                     # Дефолт 443
    "health_path": "/",
    "timeout": 5.0,                  # Таймаут по умолчанию
    "concurrency": 100,              # Параллельность по умолчанию
    "strict_http": False,
}

@dataclass
class ProbeResult:
    sni: str
    status: str
    detail: str
    rtt_ms: Optional[int]
    ts: float

async def probe_sni(sni: str, cfg: dict) -> ProbeResult:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=cfg["server_ip"],
                port=cfg["port"],
                ssl=ctx,
                server_hostname=sni
            ),
            timeout=cfg["timeout"]
        )

        req = (
            f"HEAD {cfg['health_path']} HTTP/1.1\r\n"
            f"Host: {sni}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii", "ignore")
        writer.write(req)
        await writer.drain()

        try:
            data = await asyncio.wait_for(reader.read(256), timeout=cfg["timeout"])
        except asyncio.TimeoutError:
            data = b""

        elapsed_ms = int((time.perf_counter() - start) * 1000)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if cfg["strict_http"]:
            if data.startswith(b"HTTP/1."):
                status = "WORKING"; detail = f"HTTP OK, {len(data)} bytes"
            elif data == b"":
                status = "INCONCLUSIVE"; detail = "TLS OK, no HTTP bytes"
            else:
                status = "INCONCLUSIVE"; detail = f"Non-HTTP bytes: {data[:20]!r}"
        else:
            status = "WORKING"; detail = "TLS OK"

        return ProbeResult(sni, status, detail, elapsed_ms, time.time())

    except asyncio.TimeoutError:
        return ProbeResult(sni, "BLOCKED", "Timeout", None, time.time())
    except ssl.SSLError as e:
        return ProbeResult(sni, "BLOCKED", f"SSL error: {e.__class__.__name__}: {e}", None, time.time())
    except ConnectionResetError:
        return ProbeResult(sni, "BLOCKED", "TCP reset", None, time.time())
    except Exception as e:
        tb = traceback.format_exc(limit=1)
        return ProbeResult(sni, "INCONCLUSIVE", f"Other error: {e.__class__.__name__}: {e} | {tb.strip()}", None, time.time())

def fmt_status(status: str) -> str:
    if not USE_COLOR:
        return status
    if status == "WORKING":
        return f"{Fore.GREEN}{status}{Style.RESET_ALL}"
    if status == "BLOCKED":
        return f"{Fore.RED}{status}{Style.RESET_ALL}"
    return f"{Fore.YELLOW}{status}{Style.RESET_ALL}"

def load_sni_sources(sni_path: Path) -> List[str]:
    snis: List[str] = []
    if sni_path.is_dir():
        txt_files = sorted([p for p in sni_path.iterdir() if p.suffix.lower() == ".txt" and p.is_file()])
        for f in txt_files:
            snis.extend(_read_one_list(f))
    elif sni_path.is_file():
        snis = _read_one_list(sni_path)
    else:
        print(f"Не найдено ни файла, ни папки: {sni_path}", file=sys.stderr)
        return []
    
    seen = set()
    uniq = []
    for s in snis:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq

def _read_one_list(path: Path) -> List[str]:
    try:
        return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")]
    except Exception as e:
        print(f"Не удалось прочитать {path}: {e}", file=sys.stderr)
        return []

async def run_scan(domains: List[str], cfg: dict, out_dir: Path, fsync_enabled: bool, 
                   concurrency: int, no_color: bool, shuffle: bool):

    global USE_COLOR
    if no_color:
        USE_COLOR = False

    if shuffle:
        random.shuffle(domains)

    results_jsonl = out_dir / "results.jsonl"
    working_txt = out_dir / "working.txt"
    out_dir.mkdir(parents=True, exist_ok=True)

    f_json = results_jsonl.open("a", encoding="utf-8", buffering=1)
    f_work = working_txt.open("a", encoding="utf-8", buffering=1)

    def safe_write_json(line: str):
        f_json.write(line + "\n")
        f_json.flush()
        if fsync_enabled:
            os.fsync(f_json.fileno())

    def safe_write_work(sni: str):
        f_work.write(sni + "\n")
        f_work.flush()
        if fsync_enabled:
            os.fsync(f_work.fileno())

    total = len(domains)
    ok = blocked = inc = 0
    start_ts = time.perf_counter()

    stop_flag = False
    loop = asyncio.get_running_loop()

    def _handle_sig():
        nonlocal stop_flag
        stop_flag = True

    try:
        loop.add_signal_handler(signal.SIGTERM, _handle_sig)
        loop.add_signal_handler(signal.SIGINT, _handle_sig)
    except NotImplementedError:
        pass

    sem = asyncio.Semaphore(concurrency)
    lock = asyncio.Lock()

    async def process_one(s: str, pbar: "tqdm"):
        nonlocal ok, blocked, inc, stop_flag
        async with sem:
            if stop_flag:
                return
            res = await probe_sni(s, cfg)
            jl = json.dumps(asdict(res), ensure_ascii=False)
            
            async with lock:
                safe_write_json(jl)
                if res.status == "WORKING":
                    safe_write_work(s)

            status_str = f"[{res.status:10}]"
            if USE_COLOR:
                status_str = f"[{fmt_status(res.status):10}]"
            rtt = "" if res.rtt_ms is None else f"{res.rtt_ms} ms"
            tqdm.write(f"{status_str} {s:40} {rtt:>7}  {res.detail}")

            if res.status == "WORKING": ok += 1
            elif res.status == "BLOCKED": blocked += 1
            else: inc += 1
            pbar.set_postfix(ok=ok, blocked=blocked, inc=inc, refresh=False)
            pbar.update(1)

    try:
        with tqdm(total=total, unit="sni", dynamic_ncols=True, leave=True) as pbar:
            tasks = [asyncio.create_task(process_one(s, pbar)) for s in domains]
            await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        stop_flag = True
        tqdm.write("Получен сигнал, завершаю…")
    finally:
        f_json.close()
        f_work.close()

    dt = time.perf_counter() - start_ts
    print("\n=== ИТОГИ ===")
    print(f"WORKING: {ok} | BLOCKED: {blocked} | INCONCLUSIVE: {inc} | total: {ok+blocked+inc}/{total} | time: {dt:.1f}s")
    print(f"Полные логи: {results_jsonl}")
    print(f"Список рабочих SNI: {working_txt}")

def main():
    ap = argparse.ArgumentParser(description="SNI watcher: проверка доменов через Reality")
    ap.add_argument("-i", "--ip", required=True, help="IP сервера (обязательно)")
    ap.add_argument("-p", "--port", type=int, default=443, help="Порт сервера (по умолчанию: 443)")
    ap.add_argument("-t", "--timeout", type=float, default=5.0, help="Таймаут соединения (по умолчанию: 5.0)")
    ap.add_argument("-f", "--sni-path", default="sni.txt", help="Путь к файлу или папке со списками SNI")
    ap.add_argument("-o", "--out-dir", default="scan_out", help="Каталог для результатов")
    ap.add_argument("-s", "--strict", action="store_true", help="Требовать корректный HTTP-ответ")
    ap.add_argument("-c", "--concurrency", type=int, default=100, help="Кол-во одновременных проверок")
    ap.add_argument("--shuffle", action="store_true", help="Перемешать список доменов перед проверкой")
    ap.add_argument("--no-color", action="store_true", help="Отключить цветной вывод")
    ap.add_argument("--no-fsync", action="store_true", help="Отключить принудительную запись на диск")
    args = ap.parse_args()

    cfg = dict(CONFIG)
    cfg["server_ip"] = args.ip
    cfg["port"] = args.port
    cfg["timeout"] = args.timeout
    cfg["concurrency"] = max(1, args.concurrency)
    if args.strict: cfg["strict_http"] = True

    sni_path = Path(args.sni_path)
    domains = load_sni_sources(sni_path)
    if not domains:
        print("Список SNI пуст.", file=sys.stderr)
        sys.exit(1)

    print(f"Запуск: {len(domains)} SNI | цель {cfg['server_ip']}:{cfg['port']} | таймаут {cfg['timeout']}с")
    
    try:
        asyncio.run(run_scan(
            domains=domains,
            cfg=cfg,
            out_dir=Path(args.out_dir),
            fsync_enabled=not args.no_fsync,
            concurrency=cfg["concurrency"],
            no_color=args.no_color,
            shuffle=args.shuffle
        ))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
