#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Wazuh Indexer Forensic Exporter Generic
Version: v0.1
Author: Enrique de Clerck

Exporta eventos desde Wazuh Indexer/OpenSearch por mes hacia NDJSON.GZ y ZIP.

Características:
- Interactivo.
- Genérico para distintos Wazuh Indexer.
- Soporta certificado admin o usuario/password.
- Exporta wazuh-alerts, wazuh-archives, ambos o patrón manual.
- Soporta campo temporal auto, timestamp, @timestamp o manual.
- Calcula eventos esperados con POST _count.
- Calcula tamaño de índices del mes.
- Valida espacio antes de exportar.
- Exporta en slices paralelos.
- Muestra progreso, velocidad y ETA.
- Genera backup.log dentro de la carpeta del respaldo.
- Genera manifest JSON.
- Genera sha256.txt.
- Crea ZIP final opcional.
- No borra eventos del Indexer.
- No elimina respaldos locales automáticamente.
"""

import base64
import getpass
import gzip
import hashlib
import json
import os
import re
import shutil
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone


TOOL_NAME = "Wazuh Indexer Forensic Exporter Generic"
TOOL_VERSION = "v0.1"
TOOL_AUTHOR = "Enrique de Clerck"

RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
GRAY = "\033[90m"

LOG_FILE_HANDLE = None


def color(text, code):
    return f"{code}{text}{RESET}"


def clean_ansi(text):
    return re.sub(r"\033\[[0-9;]*m", "", str(text))


def emit(text="", code=None):
    global LOG_FILE_HANDLE
    out = color(text, code) if code else str(text)
    print(out, flush=True)
    if LOG_FILE_HANDLE:
        LOG_FILE_HANDLE.write(clean_ansi(text) + "\n")
        LOG_FILE_HANDLE.flush()


def banner():
    emit(r"""
 __        __             _       _____
 \ \      / /_ _ _____  _| |__   |  ___|__  _ __ ___ _ __  ___  ___
  \ \ /\ / / _` |_  / | | '_ \  | |_ / _ \| '__/ _ \ '_ \/ __|/ _ \
   \ V  V / (_| |/ /| |_| | | | |  _| (_) | | |  __/ | | \__ \  __/
    \_/\_/ \__,_/___|\__,_|_| |_| |_|  \___/|_|  \___|_| |_|___/\___|

        Wazuh Indexer Forensic Exporter Generic - NDJSON.GZ + ZIP
        By Enrique de Clerck | v0.1
""", CYAN)


def ask(prompt, default=None, secret=False):
    suffix = f" [{default}]" if default not in (None, "") else ""
    while True:
        if secret:
            value = getpass.getpass(color(f"{prompt}{suffix}: ", BLUE))
        else:
            value = input(color(f"{prompt}{suffix}: ", BLUE)).strip()

        if value == "" and default is not None:
            return str(default)

        if value != "":
            return value


def ask_yes_no(prompt, default=True):
    default_text = "S/n" if default else "s/N"

    while True:
        value = input(color(f"{prompt} [{default_text}]: ", BLUE)).strip().lower()

        if value == "":
            return default

        if value in ("s", "si", "sí", "y", "yes"):
            return True

        if value in ("n", "no"):
            return False


def print_section(title):
    emit(f"\n===== {title} =====", CYAN)


def print_ok(text):
    emit(text, GREEN)


def print_warn(text):
    emit(text, YELLOW)


def print_error(text):
    emit(text, RED)


def safe_int(value, default):
    try:
        return int(value)
    except Exception:
        return default


def safe_float(value, default):
    try:
        return float(value)
    except Exception:
        return default


def parse_month(value):
    if not re.match(r"^\d{4}-(0[1-9]|1[0-2])$", value):
        raise SystemExit(color("ERROR: el mes debe venir en formato YYYY-MM. Ejemplo: 2026-05", RED))

    year, month = map(int, value.split("-"))
    start = datetime(year, month, 1, tzinfo=timezone.utc)

    if month == 12:
        end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(year, month + 1, 1, tzinfo=timezone.utc)

    return start, end


def month_label_es(month):
    names = {
        "01": "enero",
        "02": "febrero",
        "03": "marzo",
        "04": "abril",
        "05": "mayo",
        "06": "junio",
        "07": "julio",
        "08": "agosto",
        "09": "septiembre",
        "10": "octubre",
        "11": "noviembre",
        "12": "diciembre",
    }
    year, mon = month.split("-")
    return f"{names[mon]}{year}"


def free_bytes(path):
    os.makedirs(path, exist_ok=True)
    stat = os.statvfs(path)
    return stat.f_bavail * stat.f_frsize


def free_gb(path):
    return free_bytes(path) / (1024 ** 3)


def dir_size_bytes(path):
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            full_path = os.path.join(root, name)
            try:
                total += os.path.getsize(full_path)
            except FileNotFoundError:
                pass
    return total


def fmt_seconds(seconds):
    seconds = max(0, int(seconds))
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def quote_index(pattern):
    return urllib.parse.quote(pattern, safe="*._-,")


class WazuhExporter:
    def __init__(self, cfg):
        self.cfg = cfg
        self.base = f"https://{cfg['host']}:{cfg['port']}"
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        self.lock = threading.Lock()
        self.results = []
        self.errors = []
        self.progress = {i: 0 for i in range(cfg["slices"])}
        self.started = time.time()
        self.expected_count = 0
        self.detected_time_field = None

        if cfg["ca"]:
            self.ctx = ssl.create_default_context(cafile=cfg["ca"])
        else:
            self.ctx = ssl._create_unverified_context()

        if cfg["auth_mode"] == "cert":
            self.ctx.load_cert_chain(certfile=cfg["cert"], keyfile=cfg["key"])
        else:
            token = base64.b64encode(f"{cfg['username']}:{cfg['password']}".encode()).decode()
            self.headers["Authorization"] = f"Basic {token}"

    def req(self, method, path, payload=None, params=None, timeout=300):
        if not path.startswith("/"):
            path = "/" + path

        url = self.base + path

        if params:
            url += "?" + urllib.parse.urlencode(params)

        data = json.dumps(payload).encode("utf-8") if payload is not None else None

        request = urllib.request.Request(
            url,
            data=data,
            headers=self.headers,
            method=method,
        )

        try:
            with urllib.request.urlopen(request, context=self.ctx, timeout=timeout) as response:
                body = response.read().decode(errors="replace")
                return json.loads(body) if body else {}

        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            raise RuntimeError(f"HTTP_ERROR {e.code} {method} {url}\n{body[:3000]}")

        except Exception as e:
            raise RuntimeError(f"ERROR_REQUEST {method} {url}: {e}")

    def print_progress(self):
        total = sum(self.progress.values())
        elapsed = time.time() - self.started
        rate = total / elapsed if elapsed > 0 else 0
        percent = (total / self.expected_count * 100) if self.expected_count else 0
        remaining = max(0, self.expected_count - total)
        eta = remaining / rate if rate > 0 else 0

        bar_len = 35
        filled = int(bar_len * min(percent, 100) / 100)
        bar = "█" * filled + "░" * (bar_len - filled)

        line = (
            f"[{bar}] {percent:6.2f}% | "
            f"{total:,}/{self.expected_count:,} eventos | "
            f"{rate:,.0f} ev/s | ETA {fmt_seconds(eta)} | "
            f"libre {free_gb(self.cfg['outdir']):.2f} GB"
        ).replace(",", ".")

        emit(line, GREEN)

    def validate_auth(self):
        print_section("VALIDANDO AUTENTICACION")

        try:
            auth = self.req("GET", "/_plugins/_security/authinfo")
            user = auth.get("user_name") or auth.get("user") or "UNKNOWN"
            print_ok("AUTH_OK=" + str(user))
        except Exception as e:
            print_warn(f"WARNING: no se pudo consultar authinfo: {e}")
            root = self.req("GET", "/")
            print_ok("INDEXER_OK=" + json.dumps({
                "cluster_name": root.get("cluster_name"),
                "version": (root.get("version") or {}).get("number"),
            }, ensure_ascii=False))

    def detect_time_field(self):
        if self.cfg["time_field"].lower() != "auto":
            self.detected_time_field = self.cfg["time_field"]
            print_ok(f"TIME_FIELD_MANUAL={self.detected_time_field}")
            return self.detected_time_field

        print_section("DETECTANDO CAMPO TEMPORAL")

        candidates = ["timestamp", "@timestamp", "event.created", "data.timestamp"]
        fields_query = ",".join(candidates)

        try:
            caps = self.req(
                "GET",
                f"/{quote_index(self.cfg['index_pattern'])}/_field_caps",
                params={
                    "fields": fields_query,
                    "ignore_unavailable": "true",
                    "allow_no_indices": "true",
                },
            )

            fields = caps.get("fields", {}) or {}

            for candidate in candidates:
                if candidate in fields:
                    types = fields[candidate]
                    if "date" in types or "date_nanos" in types:
                        self.detected_time_field = candidate
                        print_ok(f"TIME_FIELD_AUTO={candidate}")
                        return candidate

            print_warn("WARNING: no se detectó campo date por field_caps. Se probará timestamp.")
            self.detected_time_field = "timestamp"
            return "timestamp"

        except Exception as e:
            print_warn(f"WARNING: field_caps falló: {e}")
            self.detected_time_field = "timestamp"
            print_warn("TIME_FIELD_FALLBACK=timestamp")
            return "timestamp"

    def validate_indices_and_count(self):
        print_section("VALIDANDO INDICES")

        indices = self.req(
            "GET",
            f"/_cat/indices/{quote_index(self.cfg['index_pattern'])}",
            params={
                "format": "json",
                "bytes": "b",
                "h": "health,status,index,docs.count,store.size,pri.store.size",
                "s": "index",
                "ignore_unavailable": "true",
                "allow_no_indices": "true",
            },
        )

        if not indices:
            raise SystemExit(color("STOP: no se encontraron índices para el patrón indicado.", RED))

        total_store = 0
        total_docs_by_cat = 0

        for item in indices:
            total_store += safe_int(item.get("store.size") or 0, 0)
            total_docs_by_cat += safe_int(item.get("docs.count") or 0, 0)

        print_ok(f"Indices encontrados: {len(indices)}")
        print_ok(f"Docs por _cat: {total_docs_by_cat:,}".replace(",", "."))
        print_ok(f"Store size aprox: {total_store / 1024**3:.2f} GB")

        for item in indices[:80]:
            idx = item.get("index")
            docs = item.get("docs.count")
            size_gb = safe_int(item.get("store.size") or 0, 0) / 1024**3
            emit(f"  {idx} | docs={docs} | size={size_gb:.2f} GB")

        if len(indices) > 80:
            emit(f"  ... {len(indices) - 80} índices adicionales omitidos en pantalla", GRAY)

        time_field = self.detect_time_field()

        print_section("CONTANDO EVENTOS POR RANGO DE TIEMPO")

        count_payload = {
            "query": {
                "range": {
                    time_field: {
                        "gte": self.cfg["gte"],
                        "lt": self.cfg["lt"],
                    }
                }
            }
        }

        count_result = self.req(
            "POST",
            f"/{quote_index(self.cfg['index_pattern'])}/_count",
            count_payload,
            params={
                "ignore_unavailable": "true",
                "allow_no_indices": "true",
            },
        )

        self.expected_count = int(count_result.get("count", 0))

        print_ok(f"Campo temporal usado: {time_field}")
        print_ok(f"Eventos esperados: {self.expected_count:,}".replace(",", "."))

        if self.expected_count == 0:
            raise SystemExit(color("STOP: no hay eventos para exportar en el mes seleccionado.", RED))

        return total_store, indices

    def preflight_space_guard(self, store_total_bytes):
        print_section("CONTROL DE ESPACIO PREVIO")

        os.makedirs(self.cfg["outdir"], exist_ok=True)

        free_now = free_bytes(self.cfg["outdir"])
        safety_factor = float(self.cfg["space_safety_factor"])
        min_free_after = int(self.cfg["min_free_gb"]) * 1024**3

        estimated_export = int(store_total_bytes * safety_factor)

        if self.cfg["create_zip"]:
            required = (estimated_export * 2) + min_free_after
            mode = "carpeta exportada + ZIP final + margen libre"
        else:
            required = estimated_export + min_free_after
            mode = "carpeta exportada + margen libre"

        emit(f"Modo cálculo: {mode}")
        emit(f"store.size del mes: {store_total_bytes / 1024**3:.2f} GB")
        emit(f"factor seguridad: {safety_factor:.2f}x")
        emit(f"export estimado: {estimated_export / 1024**3:.2f} GB")
        emit(f"crear ZIP final conservando carpeta: {'SI' if self.cfg['create_zip'] else 'NO'}")
        emit(f"margen libre final requerido: {self.cfg['min_free_gb']} GB")
        emit(f"espacio libre actual: {free_now / 1024**3:.2f} GB")
        emit(f"espacio requerido total: {required / 1024**3:.2f} GB")

        if free_now < required:
            missing = required - free_now
            raise SystemExit(color(
                "\nABORTADO POR SEGURIDAD:\n"
                "No hay espacio suficiente para exportar sin riesgo.\n"
                f"Libre actual: {free_now / 1024**3:.2f} GB\n"
                f"Requerido: {required / 1024**3:.2f} GB\n"
                f"Faltante: {missing / 1024**3:.2f} GB\n"
                "\nNo se exportó nada.\n"
                "Opciones: liberar espacio, usar destino externo, desactivar ZIP final o aumentar disco.",
                RED
            ))

        print_ok("OK: espacio suficiente para exportar con margen de seguridad.")

    def export_slice(self, slice_id):
        scroll_id = None

        try:
            exported = 0
            by_index = {}
            by_level = {}
            sha_content = hashlib.sha256()

            out_file = os.path.join(
                self.cfg["outdir"],
                f"wazuh-eventos-{self.cfg['label']}_slice{slice_id}_of{self.cfg['slices']}_{self.cfg['ts']}.ndjson.gz",
            )

            summary_file = os.path.join(
                self.cfg["outdir"],
                f"wazuh-eventos-{self.cfg['label']}_slice{slice_id}_of{self.cfg['slices']}_{self.cfg['ts']}_summary.json",
            )

            query = {
                "size": self.cfg["batch_size"],
                "sort": ["_doc"],
                "slice": {
                    "id": slice_id,
                    "max": self.cfg["slices"],
                },
                "query": {
                    "range": {
                        self.detected_time_field: {
                            "gte": self.cfg["gte"],
                            "lt": self.cfg["lt"],
                        }
                    }
                },
            }

            first = self.req(
                "POST",
                f"/{quote_index(self.cfg['index_pattern'])}/_search",
                query,
                params={
                    "scroll": self.cfg["scroll"],
                    "ignore_unavailable": "true",
                    "allow_no_indices": "true",
                },
            )

            scroll_id = first.get("_scroll_id")

            with gzip.open(out_file, "wt", encoding="utf-8") as f:
                batch = first.get("hits", {}).get("hits", [])

                while batch:
                    for hit in batch:
                        line = json.dumps(hit, ensure_ascii=False, separators=(",", ":"))
                        f.write(line + "\n")
                        sha_content.update((line + "\n").encode("utf-8"))
                        exported += 1

                        idx = hit.get("_index", "UNKNOWN")
                        by_index[idx] = by_index.get(idx, 0) + 1

                        src = hit.get("_source", {}) or {}
                        level = ((src.get("rule") or {}).get("level"))
                        level = str(level) if level is not None else "NO_RULE_LEVEL"
                        by_level[level] = by_level.get(level, 0) + 1

                    with self.lock:
                        self.progress[slice_id] = exported
                        self.print_progress()

                    if free_gb(self.cfg["outdir"]) < self.cfg["min_free_gb"]:
                        raise RuntimeError(
                            f"STOP: espacio libre bajo umbral durante export: "
                            f"{free_gb(self.cfg['outdir']):.2f} GB < {self.cfg['min_free_gb']} GB"
                        )

                    if not scroll_id:
                        break

                    nxt = self.req(
                        "POST",
                        "/_search/scroll",
                        {
                            "scroll": self.cfg["scroll"],
                            "scroll_id": scroll_id,
                        },
                    )

                    scroll_id = nxt.get("_scroll_id")
                    batch = nxt.get("hits", {}).get("hits", [])

            if scroll_id:
                try:
                    self.req("DELETE", "/_search/scroll", {"scroll_id": [scroll_id]})
                except Exception:
                    pass

            item = {
                "slice_id": slice_id,
                "slices": self.cfg["slices"],
                "month": self.cfg["month"],
                "range": {
                    "gte": self.cfg["gte"],
                    "lt": self.cfg["lt"],
                },
                "time_field": self.detected_time_field,
                "index_pattern": self.cfg["index_pattern"],
                "exported": exported,
                "file": out_file,
                "file_name": os.path.basename(out_file),
                "sha256_ndjson_content": sha_content.hexdigest(),
                "sha256_file_gzip": sha256_file(out_file),
                "by_index": dict(sorted(by_index.items())),
                "by_rule_level": dict(sorted(
                    by_level.items(),
                    key=lambda kv: (
                        999 if kv[0] == "NO_RULE_LEVEL"
                        else int(kv[0]) if kv[0].isdigit()
                        else 998,
                        kv[0],
                    ),
                )),
                "free_gb_after": round(free_gb(self.cfg["outdir"]), 2),
            }

            with open(summary_file, "w", encoding="utf-8") as sf:
                json.dump(item, sf, ensure_ascii=False, indent=2)

            item["summary_file"] = summary_file
            item["summary_file_name"] = os.path.basename(summary_file)
            item["sha256_summary_file"] = sha256_file(summary_file)

            with self.lock:
                self.results.append(item)

        except Exception as e:
            with self.lock:
                self.errors.append(f"slice {slice_id}: {e}")

            if scroll_id:
                try:
                    self.req("DELETE", "/_search/scroll", {"scroll_id": [scroll_id]})
                except Exception:
                    pass

    def run_export(self, store_total_bytes, indices):
        print_section("INICIANDO EXPORTACION")

        threads = []

        for i in range(self.cfg["slices"]):
            thread = threading.Thread(target=self.export_slice, args=(i,), daemon=False)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        if self.errors:
            raise SystemExit(color("ERRORES EN EXPORT:\n" + "\n".join(self.errors), RED))

        total_exported = sum(item["exported"] for item in self.results)
        exact_match = total_exported == self.expected_count

        manifest = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "author": TOOL_AUTHOR,
            "timestamp": self.cfg["ts"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "mode": "generic_monthly_parallel_sliced_scroll_to_folder_and_zip",
            "host": self.cfg["host"],
            "port": self.cfg["port"],
            "month": self.cfg["month"],
            "index_pattern": self.cfg["index_pattern"],
            "time_field": self.detected_time_field,
            "range": {
                "gte": self.cfg["gte"],
                "lt": self.cfg["lt"],
            },
            "expected_count": self.expected_count,
            "total_exported": total_exported,
            "count_difference": total_exported - self.expected_count,
            "slices": self.cfg["slices"],
            "batch_size": self.cfg["batch_size"],
            "store_size_gb": round(store_total_bytes / 1024**3, 2),
            "free_gb_after_export": round(free_gb(self.cfg["outdir"]), 2),
            "duration_seconds": round(time.time() - self.started, 2),
            "complete": exact_match,
            "indices": indices,
            "parts": sorted(self.results, key=lambda x: x["slice_id"]),
            "notes": [
                "If exporting a live/current month, expected_count may drift while events are still being indexed.",
                "For final forensic evidence, prefer exporting closed months."
            ],
            "safety": {
                "delete_indexer_events": False,
                "delete_local_backups": False,
                "snapshot": False,
                "read_only_export": True,
            },
        }

        manifest_path = os.path.join(
            self.cfg["outdir"],
            f"wazuh-eventos-{self.cfg['label']}_manifest_{self.cfg['ts']}.json",
        )

        with open(manifest_path, "w", encoding="utf-8") as mf:
            json.dump(manifest, mf, ensure_ascii=False, indent=2)

        sha_path = os.path.join(
            self.cfg["outdir"],
            f"wazuh-eventos-{self.cfg['label']}_sha256_{self.cfg['ts']}.txt",
        )

        sha_lines = []

        for item in sorted(self.results, key=lambda x: x["slice_id"]):
            sha_lines.append(f"{item['sha256_file_gzip']}  {item['file_name']}")
            sha_lines.append(f"{item['sha256_summary_file']}  {item['summary_file_name']}")

        sha_lines.append(f"{sha256_file(manifest_path)}  {os.path.basename(manifest_path)}")

        with open(sha_path, "w", encoding="utf-8") as sf:
            sf.write("\n".join(sha_lines) + "\n")

        print_section("MANIFEST EXPORT")
        emit(json.dumps({
            "expected_count": manifest["expected_count"],
            "total_exported": manifest["total_exported"],
            "count_difference": manifest["count_difference"],
            "complete": manifest["complete"],
            "duration_seconds": manifest["duration_seconds"],
            "free_gb_after_export": manifest["free_gb_after_export"],
            "manifest": manifest_path,
            "sha256": sha_path,
        }, ensure_ascii=False, indent=2))

        if not exact_match:
            print_warn(
                "WARNING: total_exported es distinto a expected_count. "
                "Esto puede ocurrir si se exporta un mes en curso mientras el Indexer sigue recibiendo eventos. "
                "Para evidencia final, exporta meses cerrados."
            )

        return manifest_path, sha_path

    def create_zip(self):
        if not self.cfg["create_zip"]:
            return None

        folder_size = dir_size_bytes(self.cfg["outdir"])
        zip_path = self.cfg["zipfile"]
        free_now = free_bytes(os.path.dirname(zip_path))
        min_free_after = self.cfg["min_free_gb"] * 1024**3

        print_section("VALIDANDO ESPACIO PARA ZIP FINAL")
        emit(f"folder_size_gb={folder_size / 1024**3:.2f}")
        emit(f"free_now_gb={free_now / 1024**3:.2f}")
        emit(f"min_free_after_zip_gb={self.cfg['min_free_gb']}")

        if free_now - folder_size < min_free_after:
            print_warn(
                "STOP: no hay espacio seguro para crear ZIP manteniendo carpeta. "
                "Se deja la carpeta sin comprimir."
            )
            return None

        print_section("CREANDO ZIP FINAL")

        if os.path.exists(zip_path):
            previous_zip = f"{zip_path}.previous.{self.cfg['ts']}"
            print_warn(f"ZIP existente movido a: {previous_zip}")
            os.rename(zip_path, previous_zip)

        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as z:
            for root, _, files in os.walk(self.cfg["outdir"]):
                for name in files:
                    path = os.path.join(root, name)
                    arcname = os.path.relpath(path, os.path.dirname(self.cfg["outdir"]))
                    z.write(path, arcname)

        zip_manifest = {
            "zip_file": zip_path,
            "zip_sha256": sha256_file(zip_path),
            "zip_size_gb": round(os.path.getsize(zip_path) / 1024**3, 2),
            "source_folder": self.cfg["outdir"],
            "source_folder_size_gb": round(folder_size / 1024**3, 2),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        zip_manifest_path = os.path.join(
            self.cfg["outdir"],
            f"{os.path.basename(zip_path)}_manifest_{self.cfg['ts']}.json",
        )

        with open(zip_manifest_path, "w", encoding="utf-8") as f:
            json.dump(zip_manifest, f, ensure_ascii=False, indent=2)

        print_section("ZIP MANIFEST")
        emit(json.dumps(zip_manifest, ensure_ascii=False, indent=2))

        return zip_path


def build_config():
    banner()

    print_warn("Modo interactivo. No borra eventos del Indexer. No elimina respaldos locales.")
    print_warn("Recomendación general: para auditoría SOC/forense operativo, usar wazuh-alerts-*.")

    default_user = os.getenv("SUDO_USER") or os.getenv("USER") or "root"
    default_base = f"/home/{default_user}" if default_user != "root" else "/root"

    print_section("CONEXION AL WAZUH INDEXER")
    print("IP/host del Wazuh Indexer:")
    print("  - Si ejecutas dentro del Indexer, usa 127.0.0.1.")
    print("  - Si ejecutas desde otro servidor autorizado, usa IP o DNS del Indexer.")
    host = ask("IP/host del Wazuh Indexer", "127.0.0.1")

    print("\nPuerto HTTPS del Wazuh Indexer:")
    print("  - Normalmente es 9200.")
    port = ask("Puerto HTTPS del Wazuh Indexer", "9200")

    print_section("MES A RESPALDAR")
    print("Formato esperado: YYYY-MM")
    print("Ejemplo: 2026-05")
    month = ask("Mes a respaldar en formato YYYY-MM", datetime.now(timezone.utc).strftime("%Y-%m"))

    start, end = parse_month(month)
    index_month = month.replace("-", ".")
    label = month_label_es(month)

    print_section("TIPO DE DATOS / PATRON DE INDICES")
    print("1) Solo alerts genérico    -> wazuh-alerts-*YYYY.MM*       (RECOMENDADO)")
    print("2) Solo archives genérico  -> wazuh-archives-*YYYY.MM*")
    print("3) Ambos genérico          -> wazuh-alerts-*YYYY.MM*,wazuh-archives-*YYYY.MM*")
    print("4) Patrón manual           -> tú defines el patrón exacto")
    print("")
    print("Ejemplos de patrón manual:")
    print("  wazuh-alerts-4.x-2026.05.*")
    print("  wazuh-alerts-*2026.05*")
    print("  wazuh-alerts-*,custom-alerts-*")
    print("")
    print("Puedes usar placeholders en patrón manual:")
    print("  {YYYY.MM} -> 2026.05")
    print("  {YYYY-MM} -> 2026-05")

    data_choice = ask("Selecciona opcion", "1")

    if data_choice == "1":
        index_pattern = f"wazuh-alerts-*{index_month}*"
    elif data_choice == "2":
        index_pattern = f"wazuh-archives-*{index_month}*"
    elif data_choice == "3":
        index_pattern = f"wazuh-alerts-*{index_month}*,wazuh-archives-*{index_month}*"
    elif data_choice == "4":
        raw = ask("Patrón manual")
        index_pattern = raw.replace("{YYYY.MM}", index_month).replace("{YYYY-MM}", month)
    else:
        raise SystemExit(color("Opción inválida.", RED))

    print_section("CAMPO TEMPORAL")
    print("Campo usado para filtrar el mes.")
    print("  - auto: intenta detectar timestamp o @timestamp.")
    print("  - timestamp: común en Wazuh alerts.")
    print("  - @timestamp: común en OpenSearch/Elastic genérico.")
    print("  - manual: escribe otro campo.")
    time_choice = ask("Campo temporal", "auto")

    if time_choice.lower() == "manual":
        time_field = ask("Nombre exacto del campo temporal")
    else:
        time_field = time_choice

    print_section("DESTINO DEL RESPALDO")
    print("Carpeta base donde guardar el respaldo.")
    print("El script creará una carpeta del mes y, opcionalmente, un ZIP final.")
    base_out = ask("Carpeta base donde guardar el respaldo", default_base)

    outdir = os.path.join(base_out, f"backups_wazuh_eventos_{label}")
    zipfile_path = os.path.join(base_out, f"backups_wazuh_eventos_{label}.zip")

    print_section("RENDIMIENTO Y CARGA")
    print("Cantidad de slices paralelos:")
    print("  - Conservador: 2")
    print("  - Recomendado: 4")
    print("  - Agresivo: 6 u 8 solo con ventana controlada.")
    slices = safe_int(ask("Cantidad de slices paralelos", "4"), 4)

    print("\nTamaño de lote por scroll:")
    print("  - Conservador: 5000")
    print("  - Recomendado: 10000")
    print("  - Agresivo: 20000")
    batch_size = safe_int(ask("Tamaño de lote por scroll", "10000"), 10000)

    print("\nTiempo de scroll:")
    print("  - Recomendado: 10m")
    print("  - Si el servidor está lento: 15m o 20m")
    scroll = ask("Tiempo de scroll", "10m")

    print_section("CONTROL DE ESPACIO")
    print("Espacio libre mínimo a conservar en GB.")
    print("Si el disco baja de este margen durante la exportación, el script aborta.")
    min_free_gb = safe_int(ask("Espacio libre mínimo a conservar en GB", "80"), 80)

    print("\nFactor de seguridad sobre store.size:")
    print("  - Recomendado: 1.20")
    print("  - Más conservador: 1.50")
    space_safety_factor = safe_float(ask("Factor de seguridad sobre store.size", "1.20"), 1.20)

    print("\n¿Crear ZIP final además de dejar la carpeta?")
    print("  - Sí: deja carpeta + ZIP.")
    print("  - No: deja solo carpeta exportada.")
    print("  - Si hay poco espacio, usar No.")
    create_zip = ask_yes_no("¿Crear ZIP final además de dejar la carpeta?", True)

    print_section("AUTENTICACION")
    print("1) Certificado admin local")
    print("   - Recomendado si ejecutas desde el Wazuh Indexer como root.")
    print("2) Usuario/password")
    print("   - Requiere usuario con permisos sobre los índices.")
    auth_choice = ask("Selecciona opcion", "1")

    cfg = {
        "host": host,
        "port": port,
        "month": month,
        "gte": start.strftime("%Y-%m-%dT00:00:00Z"),
        "lt": end.strftime("%Y-%m-%dT00:00:00Z"),
        "index_pattern": index_pattern,
        "time_field": time_field,
        "label": label,
        "base_out": base_out,
        "outdir": outdir,
        "zipfile": zipfile_path,
        "slices": slices,
        "batch_size": batch_size,
        "min_free_gb": min_free_gb,
        "space_safety_factor": space_safety_factor,
        "scroll": scroll,
        "create_zip": create_zip,
        "ts": datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"),
        "auth_mode": "cert" if auth_choice == "1" else "basic",
        "cert": None,
        "key": None,
        "ca": None,
        "username": None,
        "password": None,
    }

    if cfg["auth_mode"] == "cert":
        print_section("RUTAS DE CERTIFICADOS")
        print("Déjalas por defecto si estás ejecutando desde el Wazuh Indexer.")
        cfg["cert"] = ask("Ruta admin.pem", "/etc/wazuh-indexer/certs/admin.pem")
        cfg["key"] = ask("Ruta admin-key.pem", "/etc/wazuh-indexer/certs/admin-key.pem")
        cfg["ca"] = ask("Ruta root-ca.pem", "/etc/wazuh-indexer/certs/root-ca.pem")

        for f in [cfg["cert"], cfg["key"], cfg["ca"]]:
            if not os.path.isfile(f):
                raise SystemExit(color(f"ERROR: no existe archivo requerido: {f}", RED))

    else:
        print_section("CREDENCIALES INDEXER")
        cfg["username"] = ask("Usuario Indexer")
        cfg["password"] = ask("Password Indexer", secret=True)
        print("Ruta CA opcional. Si queda vacío, usa TLS inseguro tipo curl -k.")
        ca_path = ask("Ruta CA para validar TLS, vacío para modo inseguro", "")
        cfg["ca"] = ca_path if ca_path else None

        if cfg["ca"] and not os.path.isfile(cfg["ca"]):
            raise SystemExit(color(f"ERROR: no existe CA: {cfg['ca']}", RED))

    return cfg


def fix_ownership(path, zip_path=None):
    sudo_user = os.getenv("SUDO_USER")

    if not sudo_user:
        return

    try:
        import pwd
        user = pwd.getpwnam(sudo_user)
        uid = user.pw_uid
        gid = user.pw_gid

        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                os.chown(root, uid, gid)
                for d in dirs:
                    os.chown(os.path.join(root, d), uid, gid)
                for f in files:
                    os.chown(os.path.join(root, f), uid, gid)

        if zip_path and os.path.exists(zip_path):
            os.chown(zip_path, uid, gid)

    except Exception:
        pass


def main():
    global LOG_FILE_HANDLE

    cfg = build_config()

    print_section("RESUMEN PREVIO")
    print(json.dumps({
        "host": f"{cfg['host']}:{cfg['port']}",
        "month": cfg["month"],
        "range": {
            "gte": cfg["gte"],
            "lt": cfg["lt"],
        },
        "index_pattern": cfg["index_pattern"],
        "time_field": cfg["time_field"],
        "outdir": cfg["outdir"],
        "zipfile": cfg["zipfile"],
        "slices": cfg["slices"],
        "batch_size": cfg["batch_size"],
        "min_free_gb": cfg["min_free_gb"],
        "space_safety_factor": cfg["space_safety_factor"],
        "auth_mode": cfg["auth_mode"],
        "create_zip": cfg["create_zip"],
    }, ensure_ascii=False, indent=2))

    if os.path.exists(cfg["outdir"]):
        print_warn(f"La carpeta ya existe: {cfg['outdir']}")
        if ask_yes_no("¿Mover carpeta anterior a .previous y comenzar limpio?", False):
            previous = f"{cfg['outdir']}.previous.{cfg['ts']}"
            os.rename(cfg["outdir"], previous)
            print_warn(f"Carpeta anterior movida a: {previous}")
        else:
            raise SystemExit(color("Abortado para no sobrescribir respaldo existente.", RED))

    if cfg["create_zip"] and os.path.exists(cfg["zipfile"]):
        print_warn(f"El ZIP ya existe: {cfg['zipfile']}")
        if ask_yes_no("¿Mover ZIP anterior a .previous y continuar?", False):
            previous_zip = f"{cfg['zipfile']}.previous.{cfg['ts']}"
            os.rename(cfg["zipfile"], previous_zip)
            print_warn(f"ZIP anterior movido a: {previous_zip}")
        else:
            raise SystemExit(color("Abortado para no sobrescribir ZIP existente.", RED))

    os.makedirs(cfg["outdir"], exist_ok=True)

    log_path = os.path.join(cfg["outdir"], "backup.log")
    LOG_FILE_HANDLE = open(log_path, "a", encoding="utf-8")

    print_section("LOG INTERNO")
    print_ok(f"backup.log={log_path}")

    emit(json.dumps({
        "event": "start",
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "author": TOOL_AUTHOR,
        "config": {
            "host": f"{cfg['host']}:{cfg['port']}",
            "month": cfg["month"],
            "index_pattern": cfg["index_pattern"],
            "time_field": cfg["time_field"],
            "outdir": cfg["outdir"],
            "zipfile": cfg["zipfile"],
            "slices": cfg["slices"],
            "batch_size": cfg["batch_size"],
            "min_free_gb": cfg["min_free_gb"],
            "create_zip": cfg["create_zip"],
            "auth_mode": cfg["auth_mode"],
        }
    }, ensure_ascii=False, indent=2))

    if not ask_yes_no("¿Continuar con validación?", False):
        raise SystemExit(color("Abortado por el usuario.", YELLOW))

    exporter = WazuhExporter(cfg)

    exporter.validate_auth()
    store_total, indices = exporter.validate_indices_and_count()
    exporter.preflight_space_guard(store_total)

    print_section("DECISION FINAL")
    emit(f"Libre actual: {free_gb(cfg['outdir']):.2f} GB")
    emit(f"Store size del mes: {store_total / 1024**3:.2f} GB")
    emit(f"Factor de seguridad: {cfg['space_safety_factor']:.2f}x")
    emit(f"Umbral mínimo libre final: {cfg['min_free_gb']} GB")
    emit(f"Campo temporal final: {exporter.detected_time_field}")

    if not ask_yes_no("¿Iniciar exportación ahora?", False):
        raise SystemExit(color("Abortado antes de exportar.", YELLOW))

    manifest_path, sha_path = exporter.run_export(store_total, indices)
    zip_path = exporter.create_zip()

    fix_ownership(cfg["outdir"], zip_path)

    print_section("RESULTADO FINAL")
    print_ok(f"Carpeta respaldo: {cfg['outdir']}")
    print_ok(f"Manifest: {manifest_path}")
    print_ok(f"SHA256: {sha_path}")
    print_ok(f"Log interno: {log_path}")

    if zip_path:
        print_ok(f"ZIP respaldo: {zip_path}")
    else:
        print_warn("ZIP no generado. La carpeta exportada quedó disponible.")

    print_ok(f"Espacio final libre: {free_gb(cfg['outdir']):.2f} GB")
    print_warn("No se eliminaron eventos del Indexer ni respaldos locales.")

    emit(json.dumps({
        "event": "finish",
        "ts": datetime.now(timezone.utc).isoformat(),
        "result": "OK",
        "outdir": cfg["outdir"],
        "zip": zip_path,
        "manifest": manifest_path,
        "sha256": sha_path,
        "backup_log": log_path,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warn("\nAbortado por Ctrl+C. Revisa si quedaron archivos parciales en la carpeta de salida.")
        sys.exit(130)
    finally:
        try:
            if LOG_FILE_HANDLE:
                LOG_FILE_HANDLE.close()
        except Exception:
            pass
