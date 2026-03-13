#!/usr/bin/env python3
"""Sincronizador — daemon always-on (systemd) + GUI desktop para push/pull.

Autenticação : PBKDF2-SHA256 (600 000 iterações) → token de sessão
Performance  :
  - Compressão zstd multi-thread (3-5x mais rápido que gzip)
  - Modo archive (> ARCHIVE_THRESHOLD): tar+zstd em UMA requisição HTTP
  - Modo paralelo (≤ ARCHIVE_THRESHOLD): ThreadPoolExecutor com 16 workers
  - Session pooling com reutilização de conexões TCP/TLS
  - Buffers de 512 KB para I/O de rede e disco
  - Servidor waitress (quando disponível) para concorrência real
Segurança    :
  - Acesso restrito a BASE_DIR (/sistemas)
  - Comparação constant-time de tokens (hmac.compare_digest)
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import tarfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from pathlib import Path, PurePosixPath

# ── constantes ─────────────────────────────────────────────────────────────────

CONFIG_FILE = Path(__file__).parent / "config.json"
PARALLEL_WORKERS = 16
ARCHIVE_THRESHOLD = 3
ARCHIVE_BATCH_SIZE = 800
CHUNK_SIZE = 524288          # 512 KB
BASE_DIR = Path("/sistemas")
MTIME_TOLERANCE = 2          # segundos
ZSTD_LEVEL = 1               # velocidade máxima, boa compressão
ZSTD_THREADS = min(os.cpu_count() or 1, 8)
PBKDF2_ITERATIONS = 600_000


# ── utilidades ─────────────────────────────────────────────────────────────────

def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _safe_path(user_path: str) -> Path | None:
    """Valida que o caminho resolve dentro de BASE_DIR."""
    if not user_path:
        return None
    try:
        resolved = Path(user_path).resolve()
        base = BASE_DIR.resolve()
        if resolved == base or str(resolved).startswith(str(base) + os.sep):
            return resolved
    except (ValueError, OSError):
        pass
    return None


# ── config ─────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_config(data: dict):
    current = load_config()
    current.update(data)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(current, f, indent=2)


# ── auth ───────────────────────────────────────────────────────────────────────

def _hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"{salt.hex()}:{dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    if ":" in stored:
        salt_hex, hash_hex = stored.split(":", 1)
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), PBKDF2_ITERATIONS
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    # SHA-256 legado
    return hmac.compare_digest(
        hashlib.sha256(password.encode()).hexdigest(), stored
    )


# ── daemon Flask ───────────────────────────────────────────────────────────────

def make_daemon_app(password_hash: str):
    import zstandard as zstd
    from flask import (
        Flask, Response, abort, jsonify, send_file,
        request as freq, stream_with_context,
    )

    app = Flask(__name__)
    _token = {"value": None}
    _lock = threading.Lock()

    def _get_token():
        with _lock:
            return _token["value"]

    def _set_token(v):
        with _lock:
            _token["value"] = v

    def require_auth(f):
        @wraps(f)
        def wrapper(*a, **kw):
            tok = freq.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            active = _get_token()
            if not tok or not active or not hmac.compare_digest(tok, active):
                return jsonify({"error": "Não autorizado"}), 401
            return f(*a, **kw)
        return wrapper

    @app.route("/")
    def index():
        return "<h1>Sincronizador</h1><p>OK</p>"

    @app.route("/auth", methods=["POST"])
    def auth():
        data = freq.get_json(silent=True) or {}
        pw = data.get("password", "")
        if not _verify_password(pw, password_hash):
            return jsonify({"error": "Senha incorreta"}), 401
        if ":" not in password_hash:
            save_config({"password_hash": _hash_password(pw)})
        token = secrets.token_hex(32)
        _set_token(token)
        return jsonify({"token": token})

    @app.route("/logout", methods=["POST"])
    @require_auth
    def logout():
        _set_token(None)
        return jsonify({"ok": True})

    # ── manifesto ──────────────────────────────────────────────────────────────

    @app.route("/manifest")
    @require_auth
    def manifest():
        src = _safe_path(freq.args.get("path", ""))
        if src is None:
            abort(403, "Caminho fora de /sistemas")
        if not src.exists() or not src.is_dir():
            return jsonify([])
        files = []
        for fp in src.rglob("*"):
            if fp.is_file():
                st = fp.stat()
                files.append({
                    "path": fp.relative_to(src).as_posix(),
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                })
        return jsonify(files)

    # ── arquivo único ──────────────────────────────────────────────────────────

    @app.route("/file", methods=["GET"])
    @require_auth
    def get_file():
        p = _safe_path(freq.args.get("path", ""))
        if p is None:
            abort(403, "Caminho fora de /sistemas")
        if not p.is_file():
            abort(404)
        return send_file(p)

    @app.route("/file", methods=["POST"])
    @require_auth
    def post_file():
        p = _safe_path(freq.args.get("path", ""))
        if p is None:
            abort(403, "Caminho fora de /sistemas")
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "wb") as out:
            while chunk := freq.stream.read(CHUNK_SIZE):
                out.write(chunk)
        return jsonify({"ok": True})

    # ── archive tar+zstd ──────────────────────────────────────────────────────

    @app.route("/archive", methods=["POST"])
    @require_auth
    def get_archive():
        data = freq.get_json(silent=True) or {}
        base = _safe_path(data.get("base", ""))
        files = data.get("files", [])
        if not files or base is None or not base.is_dir():
            abort(400, "base (dir dentro de /sistemas) e files obrigatórios")

        base_pfx = str(base) + os.sep
        r_fd, w_fd = os.pipe()

        def _pack():
            cctx = zstd.ZstdCompressor(level=ZSTD_LEVEL, threads=ZSTD_THREADS)
            with os.fdopen(w_fd, "wb") as raw:
                with cctx.stream_writer(raw, closefd=False) as zw:
                    with tarfile.open(fileobj=zw, mode="w|") as tar:
                        for rel in files:
                            if rel.startswith("/") or ".." in rel.split("/"):
                                continue
                            fp = (base / rel).resolve()
                            if str(fp).startswith(base_pfx) and fp.is_file():
                                tar.add(fp, arcname=rel)

        t = threading.Thread(target=_pack, daemon=True)
        t.start()

        def _gen():
            with os.fdopen(r_fd, "rb") as rf:
                while chunk := rf.read(CHUNK_SIZE):
                    yield chunk
            t.join()

        return Response(stream_with_context(_gen()), mimetype="application/zstd")

    @app.route("/archive", methods=["PUT"])
    @require_auth
    def put_archive():
        dest = _safe_path(freq.args.get("path", ""))
        if dest is None:
            abort(403, "Caminho fora de /sistemas")
        dest.mkdir(parents=True, exist_ok=True)
        dest_pfx = str(dest) + os.sep

        dctx = zstd.ZstdDecompressor()
        reader = dctx.stream_reader(freq.stream, closefd=False)

        with tarfile.open(fileobj=reader, mode="r|") as tar:
            for member in tar:
                if not (member.isreg() or member.isdir()):
                    continue
                if member.name.startswith("/") or ".." in member.name:
                    continue
                out = (dest / member.name).resolve()
                if not str(out).startswith(dest_pfx):
                    continue
                if member.isdir():
                    out.mkdir(parents=True, exist_ok=True)
                else:
                    out.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(member) as sf, open(out, "wb") as df:
                        while chunk := sf.read(CHUNK_SIZE):
                            df.write(chunk)
                    try:
                        os.utime(out, (member.mtime, member.mtime))
                    except OSError:
                        pass

        return jsonify({"ok": True})

    return app


def run_daemon(port: int):
    cfg = load_config()
    ph = cfg.get("password_hash")
    if not ph:
        print("Nenhuma senha configurada. Execute:", file=sys.stderr)
        print("  python sincronizador.py setpassword", file=sys.stderr)
        sys.exit(1)

    app = make_daemon_app(ph)

    try:
        from waitress import serve
        print(f"Daemon em http://127.0.0.1:{port}  (waitress, {ZSTD_THREADS} threads zstd)")
        serve(app, host="127.0.0.1", port=port, threads=8)
    except ImportError:
        import logging
        logging.getLogger("werkzeug").setLevel(logging.WARNING)
        print(f"Daemon em http://127.0.0.1:{port}  (werkzeug)")
        print("  dica: pip install waitress  para melhor performance")
        app.run(host="127.0.0.1", port=port, threaded=True)


def cmd_setpassword():
    import getpass
    pw = getpass.getpass("Nova senha: ")
    if not pw:
        print("Senha vazia.", file=sys.stderr)
        sys.exit(1)
    if pw != getpass.getpass("Confirmar: "):
        print("Não conferem.", file=sys.stderr)
        sys.exit(1)
    save_config({"password_hash": _hash_password(pw)})
    print("Senha salva (PBKDF2-SHA256).")


# ── cliente ────────────────────────────────────────────────────────────────────

class SyncClient:
    def __init__(self, host: str, token: str):
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        self.base = host.rstrip("/")
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {token}"

        adapter = HTTPAdapter(
            max_retries=Retry(total=3, backoff_factor=0.5,
                              status_forcelist=[502, 503, 504]),
            pool_connections=PARALLEL_WORKERS,
            pool_maxsize=PARALLEL_WORKERS * 2,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get_manifest(self, remote_path: str) -> list:
        r = self.session.get(
            f"{self.base}/manifest", params={"path": remote_path}, timeout=30,
        )
        r.raise_for_status()
        return r.json()

    def download(self, remote_file: str, local_path: Path):
        r = self.session.get(
            f"{self.base}/file", params={"path": remote_file},
            stream=True, timeout=300,
        )
        r.raise_for_status()
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, "wb") as f:
            for chunk in r.iter_content(CHUNK_SIZE):
                f.write(chunk)

    def upload(self, local_path: Path, remote_file: str):
        with open(local_path, "rb") as f:
            r = self.session.post(
                f"{self.base}/file", params={"path": remote_file},
                data=f, timeout=300,
            )
        r.raise_for_status()

    def download_archive(self, base_path, files, local_dest, log_fn, progress_fn=None):
        import zstandard as zstd

        total = len(files)
        total_bytes = 0
        log_fn(f"Recebendo {total} arquivo(s)...")
        if progress_fn:
            progress_fn(0)

        r = self.session.post(
            f"{self.base}/archive",
            json={"base": base_path, "files": files},
            stream=True, timeout=600,
        )
        r.raise_for_status()

        dest_pfx = str(local_dest.resolve()) + os.sep
        dctx = zstd.ZstdDecompressor()
        r.raw.decode_content = True
        reader = dctx.stream_reader(r.raw, closefd=False)

        extracted = 0
        skipped = 0

        with tarfile.open(fileobj=reader, mode="r|") as tar:
            for member in tar:
                if not (member.isreg() or member.isdir()):
                    continue
                if member.name.startswith("/") or ".." in member.name:
                    continue
                out = (local_dest / member.name).resolve()
                if not str(out).startswith(dest_pfx):
                    continue
                if member.isdir():
                    out.mkdir(parents=True, exist_ok=True)
                    continue

                if out.is_file():
                    st = out.stat()
                    if (st.st_size == member.size
                            and abs(st.st_mtime - member.mtime) <= MTIME_TOLERANCE):
                        skipped += 1
                        extracted += 1
                        if progress_fn:
                            progress_fn(extracted / total * 100)
                        continue

                out.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as sf, open(out, "wb") as df:
                    while chunk := sf.read(CHUNK_SIZE):
                        df.write(chunk)
                try:
                    os.utime(out, (member.mtime, member.mtime))
                except OSError:
                    pass

                extracted += 1
                total_bytes += member.size
                log_fn(f"[{extracted}/{total}] {member.name}  ({_fmt_bytes(total_bytes)})")
                if progress_fn:
                    progress_fn(extracted / total * 100)

        if skipped:
            log_fn(f"  ({skipped} já existiam, pulados)")
        if progress_fn:
            progress_fn(100)

    def upload_archive(self, to_upload, remote_dest, log_fn, progress_fn=None):
        import zstandard as zstd

        total = len(to_upload)
        total_size = sum(fp.stat().st_size for _, fp in to_upload)
        log_fn(f"Enviando {total} arquivo(s) ({_fmt_bytes(total_size)})...")
        if progress_fn:
            progress_fn(0)

        r_fd, w_fd = os.pipe()

        def _pack():
            cctx = zstd.ZstdCompressor(level=ZSTD_LEVEL, threads=ZSTD_THREADS)
            with os.fdopen(w_fd, "wb") as raw:
                with cctx.stream_writer(raw, closefd=False) as zw:
                    with tarfile.open(fileobj=zw, mode="w|") as tar:
                        for i, (rel, fp) in enumerate(to_upload, 1):
                            tar.add(str(fp), arcname=rel)
                            log_fn(f"[{i}/{total}] {rel}  ({_fmt_bytes(fp.stat().st_size)})")
                            if progress_fn:
                                progress_fn(i / total * 100)

        pack_thread = threading.Thread(target=_pack, daemon=True)
        pack_thread.start()

        with os.fdopen(r_fd, "rb") as rf:
            r = self.session.put(
                f"{self.base}/archive", params={"path": remote_dest},
                data=rf, timeout=600,
            )

        pack_thread.join()
        r.raise_for_status()
        if progress_fn:
            progress_fn(100)

    def logout(self):
        try:
            self.session.post(f"{self.base}/logout", timeout=5)
        except Exception:
            pass


def do_auth(host: str, password: str) -> str:
    import requests
    r = requests.post(
        f"{host.rstrip('/')}/auth", json={"password": password}, timeout=10,
    )
    if r.status_code == 401:
        raise ValueError("Senha incorreta.")
    r.raise_for_status()
    return r.json()["token"]


# ── lógica de sincronização ────────────────────────────────────────────────────

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


def pull(client, remote_path, local_dest, log_fn, progress_fn=None):
    log_fn("Buscando lista de arquivos...")
    try:
        manifest = client.get_manifest(remote_path)
    except Exception as e:
        log_fn(f"Erro: {e}")
        return False

    to_download = _diff_manifest(manifest, local_dest)
    total, to_dl = len(manifest), len(to_download)
    log_fn(f"{total} no servidor — {to_dl} para baixar.")

    if to_dl == 0:
        log_fn("Tudo sincronizado!")
        if progress_fn:
            progress_fn(100)
        return True

    if to_dl > ARCHIVE_THRESHOLD:
        files = [item["path"] for item in to_download]
        batches = [files[i:i + ARCHIVE_BATCH_SIZE]
                   for i in range(0, to_dl, ARCHIVE_BATCH_SIZE)]
        done_files = 0
        for bn, batch in enumerate(batches, 1):
            if len(batches) > 1:
                log_fn(f"── Lote {bn}/{len(batches)} ({len(batch)} arquivo(s)) ──")
            base_done, batch_len = done_files, len(batch)

            def _pfn(v, _b=base_done, _l=batch_len):
                if progress_fn:
                    progress_fn((_b + _l * v / 100) / to_dl * 100)

            for attempt in range(2):
                try:
                    client.download_archive(
                        remote_path, batch, local_dest, log_fn, _pfn,
                    )
                    break
                except Exception as e:
                    if attempt == 0:
                        log_fn(f"  Falha, tentando novamente... ({e})")
                    else:
                        log_fn(f"  Erro no lote {bn}: {e}")
                        return False
            done_files += batch_len
    else:
        done = [0]
        lock = threading.Lock()
        errors = []

        def _one(item):
            remote_file = str(PurePosixPath(remote_path) / item["path"])
            client.download(remote_file, local_dest / item["path"])
            with lock:
                done[0] += 1
                return done[0], item["path"]

        with ThreadPoolExecutor(max_workers=min(PARALLEL_WORKERS, to_dl)) as ex:
            futures = {ex.submit(_one, it): it for it in to_download}
            for fut in as_completed(futures):
                try:
                    n, path = fut.result()
                    log_fn(f"[{n}/{to_dl}] {path}")
                    if progress_fn:
                        progress_fn(n / to_dl * 100)
                except Exception as e:
                    errors.append(str(e))
                    log_fn(f"  Erro: {e}")

        if errors:
            log_fn(f"{len(errors)} erro(s) durante download.")
            return False

    log_fn("Concluído!")
    return True


def push(client, local_source, remote_dest, log_fn, progress_fn=None):
    src = local_source.resolve()
    local_files = {
        fp.relative_to(src).as_posix(): fp
        for fp in src.rglob("*") if fp.is_file()
    }

    log_fn("Verificando remotos...")
    try:
        remote_index = {
            item["path"]: item for item in client.get_manifest(remote_dest)
        }
    except Exception:
        remote_index = {}

    to_upload = []
    for rel, fp in local_files.items():
        if rel not in remote_index:
            to_upload.append((rel, fp))
        else:
            st = fp.stat()
            ri = remote_index[rel]
            if (st.st_size != ri["size"]
                    or abs(st.st_mtime - ri["mtime"]) > MTIME_TOLERANCE):
                to_upload.append((rel, fp))

    total, to_ul = len(local_files), len(to_upload)
    log_fn(f"{total} arquivo(s) — {to_ul} para enviar.")

    if to_ul == 0:
        log_fn("Tudo sincronizado!")
        if progress_fn:
            progress_fn(100)
        return True

    if to_ul > ARCHIVE_THRESHOLD:
        batches = [to_upload[i:i + ARCHIVE_BATCH_SIZE]
                   for i in range(0, to_ul, ARCHIVE_BATCH_SIZE)]
        done_files = 0
        for bn, batch in enumerate(batches, 1):
            if len(batches) > 1:
                log_fn(f"── Lote {bn}/{len(batches)} ({len(batch)} arquivo(s)) ──")
            base_done, batch_len = done_files, len(batch)

            def _pfn(v, _b=base_done, _l=batch_len):
                if progress_fn:
                    progress_fn((_b + _l * v / 100) / to_ul * 100)

            for attempt in range(2):
                try:
                    client.upload_archive(batch, remote_dest, log_fn, _pfn)
                    break
                except Exception as e:
                    if attempt == 0:
                        log_fn(f"  Falha, tentando novamente... ({e})")
                    else:
                        log_fn(f"  Erro no lote {bn}: {e}")
                        return False
            done_files += batch_len
    else:
        done = [0]
        lock = threading.Lock()
        errors = []

        def _one(item):
            rel, fp = item
            client.upload(fp, str(PurePosixPath(remote_dest) / rel))
            with lock:
                done[0] += 1
                return done[0], rel

        with ThreadPoolExecutor(max_workers=min(PARALLEL_WORKERS, to_ul)) as ex:
            futures = {ex.submit(_one, it): it for it in to_upload}
            for fut in as_completed(futures):
                try:
                    n, rel = fut.result()
                    log_fn(f"[{n}/{to_ul}] {rel}")
                    if progress_fn:
                        progress_fn(n / to_ul * 100)
                except Exception as e:
                    errors.append(str(e))
                    log_fn(f"  Erro: {e}")

        if errors:
            log_fn(f"{len(errors)} erro(s) durante upload.")
            return False

    log_fn("Concluído!")
    return True


# ── GUI ────────────────────────────────────────────────────────────────────────

def run_gui():
    import customtkinter as ctk
    from tkinter import filedialog, messagebox

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    cfg = load_config()
    client_ref = {"client": None}
    busy_lock = threading.Lock()

    root = ctk.CTk()
    root.title("Sincronizador")
    root.geometry("680x800")
    root.minsize(620, 700)

    def ui(fn):
        try:
            root.after(0, fn)
        except Exception:
            pass

    # ── header ─────────────────────────────────────────────────────────────────

    header = ctk.CTkFrame(root, fg_color="transparent")
    header.pack(fill="x", padx=24, pady=(20, 0))
    ctk.CTkLabel(
        header, text="Sincronizador",
        font=ctk.CTkFont(size=24, weight="bold"),
    ).pack(side="left")
    ctk.CTkLabel(
        header, text="zstd + tar streaming",
        font=ctk.CTkFont(size=12), text_color="#666",
    ).pack(side="left", padx=(12, 0), pady=(6, 0))

    # ── conexão ────────────────────────────────────────────────────────────────

    conn = ctk.CTkFrame(root, corner_radius=12)
    conn.pack(fill="x", padx=24, pady=(16, 0))
    conn.columnconfigure(1, weight=1)

    ctk.CTkLabel(
        conn, text="Conexão", font=ctk.CTkFont(size=15, weight="bold"),
    ).grid(row=0, column=0, columnspan=3, sticky="w", padx=20, pady=(16, 8))

    ctk.CTkLabel(conn, text="Host", width=60).grid(
        row=1, column=0, sticky="w", padx=(20, 8), pady=6,
    )
    host_entry = ctk.CTkEntry(conn, placeholder_text="https://...")
    host_entry.grid(row=1, column=1, columnspan=2, sticky="ew", padx=(0, 20), pady=6)
    if cfg.get("host"):
        host_entry.insert(0, cfg["host"])

    ctk.CTkLabel(conn, text="Senha", width=60).grid(
        row=2, column=0, sticky="w", padx=(20, 8), pady=6,
    )
    pw_entry = ctk.CTkEntry(conn, show="*", placeholder_text="Senha do daemon")
    pw_entry.grid(row=2, column=1, sticky="ew", padx=0, pady=6)

    conn_btn = ctk.CTkButton(
        conn, text="Conectar", width=120,
        fg_color="#E67E22", hover_color="#D35400",
        font=ctk.CTkFont(size=13, weight="bold"),
    )
    conn_btn.grid(row=2, column=2, padx=(12, 20), pady=6)

    status_dot = ctk.CTkLabel(
        conn, text="●  Desconectado",
        text_color="#666", font=ctk.CTkFont(size=12),
    )
    status_dot.grid(row=3, column=0, columnspan=3, sticky="w", padx=20, pady=(4, 16))

    # ── tabs ───────────────────────────────────────────────────────────────────

    tabview = ctk.CTkTabview(root, corner_radius=12)
    tabview.pack(fill="both", expand=True, padx=24, pady=(16, 24))

    tab_push = tabview.add("  Enviar  →  ")
    tab_pull = tabview.add("  ←  Receber  ")

    op_buttons: list[ctk.CTkButton] = []

    def build_tab(parent, mode):
        is_push = mode == "push"

        lbl_local = "Pasta local (origem)" if is_push else "Pasta local (destino)"
        lbl_remote = "Pasta remota (destino)" if is_push else "Pasta remota (origem)"

        # local path
        ctk.CTkLabel(
            parent, text=lbl_local, font=ctk.CTkFont(size=12),
        ).pack(anchor="w", padx=20, pady=(14, 3))

        local_row = ctk.CTkFrame(parent, fg_color="transparent")
        local_row.pack(fill="x", padx=20, pady=(0, 10))
        local_entry = ctk.CTkEntry(
            local_row, placeholder_text="Selecione uma pasta...",
        )
        local_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        if cfg.get(f"{mode}_local"):
            local_entry.insert(0, cfg[f"{mode}_local"])

        def _browse():
            d = filedialog.askdirectory()
            if d:
                local_entry.delete(0, "end")
                local_entry.insert(0, d)

        ctk.CTkButton(
            local_row, text="Procurar", width=100, command=_browse,
        ).pack(side="right")

        # remote path
        ctk.CTkLabel(
            parent, text=lbl_remote, font=ctk.CTkFont(size=12),
        ).pack(anchor="w", padx=20, pady=(2, 3))

        remote_entry = ctk.CTkEntry(
            parent, placeholder_text="/sistemas/...",
        )
        remote_entry.pack(fill="x", padx=20, pady=(0, 14))
        if cfg.get(f"{mode}_remote"):
            remote_entry.insert(0, cfg[f"{mode}_remote"])

        # action button
        if is_push:
            btn_fg, btn_hover = "#2980B9", "#2471A3"
            btn_text = "Enviar  →"
        else:
            btn_fg, btn_hover = "#27AE60", "#229954"
            btn_text = "←  Receber"

        action_btn = ctk.CTkButton(
            parent, text=btn_text, height=44, corner_radius=10,
            fg_color=btn_fg, hover_color=btn_hover,
            font=ctk.CTkFont(size=15, weight="bold"),
            state="disabled",
        )
        action_btn.pack(padx=20, pady=(0, 14))
        op_buttons.append(action_btn)

        # progress
        prog_row = ctk.CTkFrame(parent, fg_color="transparent")
        prog_row.pack(fill="x", padx=20, pady=(0, 6))

        progress_bar = ctk.CTkProgressBar(prog_row, height=16, corner_radius=8)
        progress_bar.pack(side="left", fill="x", expand=True, padx=(0, 12))
        progress_bar.set(0)

        pct_label = ctk.CTkLabel(
            prog_row, text="0 %", width=50,
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        pct_label.pack(side="right")

        # status
        status_var = ctk.StringVar(value="")
        ctk.CTkLabel(
            parent, textvariable=status_var,
            font=ctk.CTkFont(size=11), text_color="#777",
        ).pack(anchor="w", padx=20, pady=(0, 4))

        # log
        log_box = ctk.CTkTextbox(
            parent, corner_radius=10, state="disabled",
            font=ctk.CTkFont(family="Consolas", size=11),
        )
        log_box.pack(fill="both", expand=True, padx=20, pady=(0, 16))

        def log_msg(msg):
            def _do():
                log_box.configure(state="normal")
                log_box.insert("end", msg + "\n")
                log_box.see("end")
                log_box.configure(state="disabled")
                status_var.set(msg)
            ui(_do)

        def set_progress(v):
            def _do():
                progress_bar.set(v / 100)
                pct_label.configure(text=f"{v:.0f} %")
            ui(_do)

        def do_op():
            cl = client_ref["client"]
            if not cl:
                messagebox.showerror("Erro", "Conecte ao servidor primeiro.")
                return
            local_val = local_entry.get().strip()
            remote_val = remote_entry.get().strip()
            if not local_val or not remote_val:
                messagebox.showerror("Erro", "Preencha as duas pastas.")
                return
            if not remote_val.startswith("/sistemas"):
                messagebox.showerror(
                    "Erro", "O caminho remoto deve começar com /sistemas/",
                )
                return
            if not busy_lock.acquire(blocking=False):
                return

            save_config({f"{mode}_local": local_val, f"{mode}_remote": remote_val})
            action_btn.configure(state="disabled")
            log_box.configure(state="normal")
            log_box.delete("1.0", "end")
            log_box.configure(state="disabled")
            set_progress(0)

            def _run():
                try:
                    if is_push:
                        push(cl, Path(local_val), remote_val, log_msg, set_progress)
                    else:
                        pull(cl, remote_val, Path(local_val), log_msg, set_progress)
                except Exception as e:
                    log_msg(f"Erro: {e}")
                finally:
                    busy_lock.release()
                    ui(lambda: action_btn.configure(state="normal"))

            threading.Thread(target=_run, daemon=True).start()

        action_btn.configure(command=do_op)

    build_tab(tab_push, "push")
    build_tab(tab_pull, "pull")

    # ── conexão lógica ─────────────────────────────────────────────────────────

    def do_connect(_event=None):
        host = host_entry.get().strip().rstrip("/")
        pw = pw_entry.get()
        if not host or not pw:
            messagebox.showerror("Erro", "Preencha host e senha.")
            return
        conn_btn.configure(state="disabled")
        status_dot.configure(text="●  Conectando...", text_color="#E67E22")

        def _go():
            try:
                token = do_auth(host, pw)
                cl = SyncClient(host, token)
                client_ref["client"] = cl
                save_config({"host": host})
                ui(lambda: pw_entry.delete(0, "end"))
                ui(lambda: status_dot.configure(
                    text=f"●  Conectado → {host}", text_color="#2ECC71",
                ))
                ui(lambda: conn_btn.configure(
                    text="Desconectar", fg_color="#E74C3C",
                    hover_color="#C0392B", state="normal",
                    command=do_disconnect,
                ))
                for b in op_buttons:
                    ui(lambda _b=b: _b.configure(state="normal"))
            except Exception as e:
                ui(lambda: status_dot.configure(
                    text=f"●  {e}", text_color="#E74C3C",
                ))
                ui(lambda: conn_btn.configure(state="normal"))

        threading.Thread(target=_go, daemon=True).start()

    def do_disconnect():
        cl = client_ref["client"]
        if cl:
            threading.Thread(target=cl.logout, daemon=True).start()
            client_ref["client"] = None
        status_dot.configure(text="●  Desconectado", text_color="#666")
        conn_btn.configure(
            text="Conectar", fg_color="#E67E22", hover_color="#D35400",
            state="normal", command=do_connect,
        )
        for b in op_buttons:
            b.configure(state="disabled")

    conn_btn.configure(command=do_connect)
    pw_entry.bind("<Return>", do_connect)

    def on_close():
        do_disconnect()
        root.after(300, root.destroy)

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


# ── entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sincronizador — daemon systemd + GUI desktop.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  Definir senha:     python sincronizador.py setpassword\n"
            "  Daemon (systemd):  python sincronizador.py daemon --port 5000\n"
            "  GUI (desktop):     python sincronizador.py\n"
            "  Push (CLI):        python sincronizador.py push /local https://host"
            " /remoto --password X\n"
            "  Pull (CLI):        python sincronizador.py pull https://host"
            " /remoto /local --password X\n"
            "\n  Dica: defina SYNC_PASSWORD para evitar --password no CLI.\n"
        ),
    )
    sub = parser.add_subparsers(dest="mode")

    sub.add_parser("setpassword", help="Configurar senha do daemon")

    p_daemon = sub.add_parser("daemon", help="Rodar como daemon")
    p_daemon.add_argument("--port", type=int, default=5000)

    p_push = sub.add_parser("push", help="Enviar arquivos (CLI)")
    p_push.add_argument("local")
    p_push.add_argument("host")
    p_push.add_argument("remote_dest")
    p_push.add_argument(
        "--password", default=os.environ.get("SYNC_PASSWORD", ""),
    )

    p_pull = sub.add_parser("pull", help="Receber arquivos (CLI)")
    p_pull.add_argument("host")
    p_pull.add_argument("remote_src")
    p_pull.add_argument("local_dest")
    p_pull.add_argument(
        "--password", default=os.environ.get("SYNC_PASSWORD", ""),
    )

    args = parser.parse_args()

    if args.mode == "setpassword":
        cmd_setpassword()

    elif args.mode == "daemon":
        run_daemon(args.port)

    elif args.mode in ("push", "pull"):
        pw = args.password
        if not pw:
            import getpass
            pw = getpass.getpass("Senha: ")
        try:
            token = do_auth(args.host, pw)
        except Exception as e:
            print(f"Autenticação falhou: {e}", file=sys.stderr)
            sys.exit(1)
        cl = SyncClient(args.host, token)
        try:
            if args.mode == "push":
                ok = push(cl, Path(args.local), args.remote_dest, print)
            else:
                ok = pull(cl, args.remote_src, Path(args.local_dest), print)
            sys.exit(0 if ok else 1)
        finally:
            cl.logout()

    else:
        try:
            run_gui()
        except ImportError as e:
            print(f"GUI indisponível: {e}", file=sys.stderr)
            print("  pip install customtkinter", file=sys.stderr)
            sys.exit(1)