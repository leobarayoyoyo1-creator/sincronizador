"""Lógica de sincronização — pull e push."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path, PurePosixPath

import requests

from .constants import (
    ARCHIVE_BATCH_MAX_BYTES,
    ARCHIVE_BATCH_SIZE,
    ARCHIVE_THRESHOLD,
    MTIME_TOLERANCE,
    PARALLEL_WORKERS,
)
from .http import SyncCancelled
from .utils import fmt_bytes


def _diff_manifest(manifest: list, local_dest: Path) -> list:
    to_get = []
    for item in manifest:
        local = local_dest / item["path"]
        if not local.exists():
            to_get.append(item)
        else:
            st = local.stat()
            if (st.st_size != item["size"]
                    or abs(st.st_mtime - item["mtime"]) > MTIME_TOLERANCE):
                to_get.append(item)
    return to_get


def _make_batches(items, max_count, max_bytes, size_fn):
    batches, current, current_bytes = [], [], 0
    for item in items:
        sz = size_fn(item)
        if current and (len(current) >= max_count or current_bytes + sz > max_bytes):
            batches.append(current)
            current, current_bytes = [], 0
        current.append(item)
        current_bytes += sz
    if current:
        batches.append(current)
    return batches


def _run_batched(items, batch_size, batch_fn, log_fn, progress_fn, cancel, size_fn=None):
    """Executa batch_fn em lotes com retry, backoff exponencial e progresso."""
    total = len(items)
    if size_fn:
        batches = _make_batches(items, batch_size, ARCHIVE_BATCH_MAX_BYTES, size_fn)
    else:
        batches = [items[i:i + batch_size] for i in range(0, total, batch_size)]
    done = 0
    for bn, batch in enumerate(batches, 1):
        if cancel and cancel.is_set():
            log_fn("Cancelado.")
            return False
        if len(batches) > 1:
            log_fn(f"── Lote {bn}/{len(batches)} ({len(batch)} arquivo(s)) ──")
        base_done, batch_len = done, len(batch)

        def _pfn(v, _b=base_done, _l=batch_len):
            if progress_fn:
                progress_fn((_b + _l * v / 100) / total * 100)

        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                batch_fn(batch, log_fn, _pfn)
                break
            except SyncCancelled:
                log_fn("Cancelado.")
                return False
            except (requests.RequestException, OSError) as e:
                if attempt < max_attempts - 1:
                    wait = 2 ** attempt
                    log_fn(f"  Falha, retentativa em {wait}s... ({e})")
                    if cancel:
                        cancel.wait(wait)
                        if cancel.is_set():
                            return False
                    else:
                        time.sleep(wait)
                else:
                    log_fn(f"  Erro no lote {bn}: {e}")
                    return False
        done += batch_len
    return True


def _run_parallel(items, one_fn, label_fn, total, log_fn, progress_fn, cancel):
    """Executa one_fn em paralelo com progresso."""
    done = [0]
    lock = threading.Lock()
    errors = []

    def _wrapped(item):
        if cancel and cancel.is_set():
            return None
        one_fn(item)
        with lock:
            done[0] += 1
            return done[0]

    with ThreadPoolExecutor(max_workers=min(PARALLEL_WORKERS, total)) as ex:
        futures = {ex.submit(_wrapped, it): it for it in items}
        for fut in as_completed(futures):
            if cancel and cancel.is_set():
                log_fn("Cancelado.")
                return errors
            try:
                n = fut.result()
                if n is None:
                    continue
                label = label_fn(futures[fut])
                log_fn(f"[{n}/{total}] {label}")
                if progress_fn:
                    progress_fn(n / total * 100)
            except SyncCancelled:
                return errors
            except Exception as e:
                errors.append(str(e))
                log_fn(f"  Erro: {e}")

    return errors


def pull(client, remote_path, local_dest, log_fn, progress_fn=None, cancel=None,
         total_bytes_fn=None):
    local_dest = Path(local_dest)
    log_fn("Buscando lista de arquivos...")
    try:
        manifest = client.get_manifest(remote_path)
    except requests.RequestException as e:
        log_fn(f"Erro ao conectar: {e}")
        return False

    to_download = _diff_manifest(manifest, local_dest)
    total = len(manifest)
    to_dl = len(to_download)
    dl_size = sum(it["size"] for it in to_download)
    if total_bytes_fn:
        total_bytes_fn(dl_size)
    log_fn(f"{total} no servidor — {to_dl} para baixar ({fmt_bytes(dl_size)}).")

    if to_dl == 0:
        log_fn("Tudo sincronizado!")
        if progress_fn:
            progress_fn(100)
        return True

    if to_dl > ARCHIVE_THRESHOLD:
        files = [item["path"] for item in to_download]

        def batch_fn(batch, lfn, pfn):
            client.download_archive(remote_path, batch, local_dest, lfn, pfn, cancel=cancel)

        if not _run_batched(files, ARCHIVE_BATCH_SIZE, batch_fn, log_fn, progress_fn, cancel):
            return False
    else:
        def one_fn(item):
            remote_file = str(PurePosixPath(remote_path) / item["path"])
            client.download(remote_file, local_dest / item["path"], cancel=cancel)

        errors = _run_parallel(
            to_download, one_fn, lambda it: it["path"],
            to_dl, log_fn, progress_fn, cancel,
        )
        if errors:
            log_fn(f"{len(errors)} erro(s) durante download.")
            return False

    log_fn("Concluído!")
    return True


def push(client, local_source, remote_dest, log_fn, progress_fn=None, cancel=None, exclude=None,
         total_bytes_fn=None):
    src = Path(local_source).resolve()

    local_files: dict[str, tuple] = {}
    exclude_set = exclude or set()

    def _walk(dir_path: Path):
        try:
            for entry in dir_path.iterdir():
                rel = entry.relative_to(src).as_posix()
                if any(rel == ex or rel.startswith(ex + "/") for ex in exclude_set):
                    continue
                if entry.is_dir():
                    _walk(entry)
                elif entry.is_file():
                    st = entry.stat()
                    local_files[rel] = (entry, st.st_size, st.st_mtime)
        except OSError as e:
            log_fn(f"Aviso: não foi possível ler {dir_path}: {e}")

    _walk(src)

    log_fn("Verificando remotos...")
    try:
        remote_index = {
            item["path"]: item for item in client.get_manifest(remote_dest)
        }
    except requests.HTTPError as e:
        # 404 = pasta não existe ainda no servidor (esperado em primeiro push)
        if e.response is not None and e.response.status_code == 404:
            remote_index = {}
        else:
            log_fn(f"Erro do servidor: {e}")
            return False
    except requests.ConnectionError:
        log_fn("Erro: servidor inacessível.")
        return False
    except requests.RequestException as e:
        log_fn(f"Erro: {e}")
        return False

    to_upload = []
    for rel, (fp, size, mtime) in local_files.items():
        if rel not in remote_index:
            to_upload.append((rel, fp, size))
        else:
            ri = remote_index[rel]
            if size != ri["size"] or abs(mtime - ri["mtime"]) > MTIME_TOLERANCE:
                to_upload.append((rel, fp, size))

    total = len(local_files)
    to_ul = len(to_upload)
    ul_size = sum(s for _, _, s in to_upload)
    if total_bytes_fn:
        total_bytes_fn(ul_size)
    log_fn(f"{total} arquivo(s) — {to_ul} para enviar ({fmt_bytes(ul_size)}).")

    if to_ul == 0:
        log_fn("Tudo sincronizado!")
        if progress_fn:
            progress_fn(100)
        return True

    if to_ul > ARCHIVE_THRESHOLD:
        def batch_fn(batch, lfn, pfn):
            client.upload_archive(batch, remote_dest, lfn, pfn, cancel=cancel)

        if not _run_batched(to_upload, ARCHIVE_BATCH_SIZE, batch_fn, log_fn, progress_fn, cancel,
                            size_fn=lambda item: item[2]):
            return False
    else:
        def one_fn(item):
            rel, fp, _ = item
            client.upload(fp, str(PurePosixPath(remote_dest) / rel), cancel=cancel)

        errors = _run_parallel(
            to_upload, one_fn, lambda it: it[0],
            to_ul, log_fn, progress_fn, cancel,
        )
        if errors:
            log_fn(f"{len(errors)} erro(s) durante upload.")
            return False

    log_fn("Concluído!")
    return True
