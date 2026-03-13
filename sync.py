#!/usr/bin/env python3
"""Sincronizador — daemon always-on (systemd) + GUI Windows para push/pull.

Autenticação : handshake com senha → token de sessão em memória
Performance  :
  - Modo archive  (> ARCHIVE_THRESHOLD arquivos): tar.gz em UMA requisição HTTP
  - Modo paralelo (≤ ARCHIVE_THRESHOLD arquivos): ThreadPoolExecutor
  - Session pooling: reutilização de conexões TCP/TLS via requests.Session
"""

import argparse
import hashlib
import json
import os
import secrets
import sys
import tarfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from pathlib import Path, PurePosixPath

CONFIG_FILE        = Path(__file__).parent / "config.json"
PARALLEL_WORKERS   = 8    # conexões simultâneas no modo paralelo
ARCHIVE_THRESHOLD  = 3    # acima disto usa tar.gz em vez de N requisições individuais
ARCHIVE_BATCH_SIZE = 500  # arquivos por lote — evita timeout do cloudflare (~100 s)


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ── config ────────────────────────────────────────────────────────────────────

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


# ── auth helpers ──────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# ── daemon Flask ──────────────────────────────────────────────────────────────

def make_daemon_app(password_hash: str):
    from flask import (
        Flask, jsonify, send_file, abort,
        request as freq, Response, stream_with_context,
    )

    app = Flask(__name__)
    app.active_token = None  # única sessão ativa

    # ── auth ──────────────────────────────────────────────────────────────────

    def require_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = freq.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            if not token or token != app.active_token:
                return jsonify({"error": "Não autorizado"}), 401
            return f(*args, **kwargs)
        return decorated

    @app.route("/")
    def index():
        return "<h1>Sincronizador Daemon</h1><p>OK</p>"

    @app.route("/auth", methods=["POST"])
    def auth():
        data = freq.get_json(silent=True) or {}
        if hash_password(data.get("password", "")) != password_hash:
            return jsonify({"error": "Senha incorreta"}), 401
        token = secrets.token_hex(32)
        app.active_token = token   # invalida sessão anterior
        return jsonify({"token": token})

    @app.route("/logout", methods=["POST"])
    @require_auth
    def logout():
        app.active_token = None
        return jsonify({"ok": True})

    # ── manifesto ─────────────────────────────────────────────────────────────

    @app.route("/manifest")
    @require_auth
    def manifest():
        path_str = freq.args.get("path", "")
        if not path_str:
            abort(400, "path required")
        src = Path(path_str).resolve()
        if not src.exists() or not src.is_dir():
            return jsonify([])   # destino inexistente → lista vazia (push cria)
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

    # ── transferência de arquivo único (fallback / poucos arquivos) ───────────

    @app.route("/file", methods=["GET"])
    @require_auth
    def get_file():
        p = Path(freq.args.get("path", "")).resolve()
        if not p.is_file():
            abort(404)
        return send_file(p)

    @app.route("/file", methods=["POST"])
    @require_auth
    def post_file():
        path_str = freq.args.get("path", "")
        if not path_str:
            abort(400, "path required")
        p = Path(path_str).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "wb") as out:
            while chunk := freq.stream.read(65536):
                out.write(chunk)
        return jsonify({"ok": True})

    # ── modo archive: tar.gz em uma única requisição ──────────────────────────

    @app.route("/archive", methods=["POST"])
    @require_auth
    def get_archive():
        """Recebe lista de arquivos, devolve tar.gz streamado."""
        data  = freq.get_json(silent=True) or {}
        base  = Path(data.get("base", "")).resolve()
        files = data.get("files", [])
        if not files or not base.is_dir():
            abort(400, "base (dir) e files obrigatórios")

        base_str = str(base)
        r_fd, w_fd = os.pipe()

        def _pack():
            with os.fdopen(w_fd, "wb") as wf:
                with tarfile.open(fileobj=wf, mode="w|gz") as tar:
                    for rel in files:
                        fp = (base / rel).resolve()
                        if str(fp).startswith(base_str) and fp.is_file():
                            tar.add(fp, arcname=rel)

        t = threading.Thread(target=_pack, daemon=True)
        t.start()

        def _gen():
            with os.fdopen(r_fd, "rb") as rf:
                while chunk := rf.read(65536):
                    yield chunk
            t.join()

        return Response(stream_with_context(_gen()), mimetype="application/x-tar")

    @app.route("/archive", methods=["PUT"])
    @require_auth
    def put_archive():
        """Recebe tar.gz e extrai na pasta de destino."""
        dest_str = freq.args.get("path", "")
        if not dest_str:
            abort(400, "path required")
        dest = Path(dest_str).resolve()
        dest.mkdir(parents=True, exist_ok=True)
        dest_safe = str(dest)

        with tarfile.open(fileobj=freq.stream, mode="r|gz") as tar:
            for member in tar:
                if not (member.isreg() or member.isdir()):
                    continue
                if member.name.startswith("/") or ".." in member.name:
                    continue
                out = (dest / member.name).resolve()
                if not str(out).startswith(dest_safe):
                    continue
                if member.isdir():
                    out.mkdir(parents=True, exist_ok=True)
                else:
                    out.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(member) as src, open(out, "wb") as dst:
                        while chunk := src.read(65536):
                            dst.write(chunk)
                    try:
                        os.utime(out, (member.mtime, member.mtime))
                    except OSError:
                        pass

        return jsonify({"ok": True})

    return app


def run_daemon(port: int):
    cfg = load_config()
    password_hash = cfg.get("password_hash")
    if not password_hash:
        print("Nenhuma senha configurada. Execute primeiro:", file=sys.stderr)
        print("  python sincronizador.py setpassword", file=sys.stderr)
        sys.exit(1)

    app = make_daemon_app(password_hash)
    import logging
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    print(f"Daemon escutando em http://127.0.0.1:{port}")
    print("Ctrl+C para parar.")
    app.run(host="127.0.0.1", port=port, threaded=True)


def cmd_setpassword():
    import getpass
    pw = getpass.getpass("Nova senha: ")
    if not pw:
        print("Senha não pode ser vazia.", file=sys.stderr)
        sys.exit(1)
    if pw != getpass.getpass("Confirmar senha: "):
        print("Senhas não conferem.", file=sys.stderr)
        sys.exit(1)
    save_config({"password_hash": hash_password(pw)})
    print("Senha salva.")


# ── cliente de API ────────────────────────────────────────────────────────────

class SyncClient:
    def __init__(self, host: str, token: str):
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        self.base = host.rstrip("/")
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {token}"

        # pool de conexões maior + retry automático em falhas de rede
        adapter = HTTPAdapter(
            max_retries=Retry(total=3, backoff_factor=0.5,
                              status_forcelist=[502, 503, 504]),
            pool_connections=PARALLEL_WORKERS,
            pool_maxsize=PARALLEL_WORKERS * 2,
        )
        self.session.mount("http://",  adapter)
        self.session.mount("https://", adapter)

    # ── operações individuais (poucos arquivos) ───────────────────────────────

    def get_manifest(self, remote_path: str) -> list:
        r = self.session.get(
            f"{self.base}/manifest", params={"path": remote_path}, timeout=15
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
            for chunk in r.iter_content(65536):
                f.write(chunk)

    def upload(self, local_path: Path, remote_file: str):
        with open(local_path, "rb") as f:
            r = self.session.post(
                f"{self.base}/file", params={"path": remote_file},
                data=f, timeout=300,
            )
        r.raise_for_status()

    # ── modo archive: tar.gz em UMA requisição ────────────────────────────────

    def download_archive(
        self, base_path: str, files: list,
        local_dest: Path, log_fn, progress_fn=None,
    ):
        """Baixa múltiplos arquivos como tar.gz — 1 requisição HTTP."""
        total = len(files)
        total_size = 0   # acumulado de bytes descomprimidos para exibição
        log_fn(f"Recebendo {total} arquivo(s)...")
        if progress_fn:
            progress_fn(0)

        r = self.session.post(
            f"{self.base}/archive",
            json={"base": base_path, "files": files},
            stream=True, timeout=600,
        )
        r.raise_for_status()

        dest_safe = str(local_dest.resolve())
        r.raw.decode_content = True
        extracted = 0
        skipped   = 0

        with tarfile.open(fileobj=r.raw, mode="r|gz") as tar:
            for member in tar:
                if not (member.isreg() or member.isdir()):
                    continue
                if member.name.startswith("/") or ".." in member.name:
                    continue
                out = (local_dest / member.name).resolve()
                if not str(out).startswith(dest_safe):
                    continue
                if member.isdir():
                    out.mkdir(parents=True, exist_ok=True)
                    continue

                # Pula se já existe com mesmo tamanho e mtime
                if out.is_file():
                    st = out.stat()
                    if st.st_size == member.size and abs(st.st_mtime - member.mtime) <= 2:
                        skipped += 1
                        extracted += 1
                        if progress_fn:
                            progress_fn(extracted / total * 100)
                        continue

                out.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as src, open(out, "wb") as dst:
                    while chunk := src.read(65536):
                        dst.write(chunk)
                try:
                    os.utime(out, (member.mtime, member.mtime))
                except OSError:
                    pass
                extracted += 1
                total_size += member.size
                log_fn(f"[{extracted}/{total}] {member.name}  ({_fmt_bytes(total_size)})")
                if progress_fn:
                    progress_fn(extracted / total * 100)

        if skipped:
            log_fn(f"  ({skipped} arquivo(s) já existiam, pulados)")

        if progress_fn:
            progress_fn(100)

    def upload_archive(
        self, to_upload: list,
        remote_dest: str, log_fn, progress_fn=None,
    ):
        """Envia múltiplos arquivos como tar.gz — 1 requisição HTTP."""
        total = len(to_upload)
        total_size = sum(fp.stat().st_size for _, fp in to_upload)
        log_fn(f"Enviando {total} arquivo(s)  ({_fmt_bytes(total_size)} total)...")
        if progress_fn:
            progress_fn(0)

        # pipe: empacotar e enviar em streaming sem carregar tudo na memória.
        # O _pack roda em thread separada e reporta progresso por arquivo;
        # como o pipe sincroniza escrita/leitura, o progresso de empacotamento
        # reflete o progresso real de upload.
        r_fd, w_fd = os.pipe()

        def _pack():
            with os.fdopen(w_fd, "wb") as wf:
                with tarfile.open(fileobj=wf, mode="w|gz") as tar:
                    for i, (rel, fp) in enumerate(to_upload, 1):
                        tar.add(str(fp), arcname=rel)
                        log_fn(f"[{i}/{total}] {rel}  ({_fmt_bytes(fp.stat().st_size)})")
                        if progress_fn:
                            progress_fn(i / total * 100)

        pack_thread = threading.Thread(target=_pack, daemon=True)
        pack_thread.start()

        with os.fdopen(r_fd, "rb") as rf:
            r = self.session.put(
                f"{self.base}/archive",
                params={"path": remote_dest},
                data=rf,
                timeout=600,
            )

        pack_thread.join()
        r.raise_for_status()

        if progress_fn:
            progress_fn(100)

    # ─────────────────────────────────────────────────────────────────────────

    def logout(self):
        try:
            self.session.post(f"{self.base}/logout", timeout=5)
        except Exception:
            pass


def do_auth(host: str, password: str) -> str:
    """Autentica e retorna o token. Lança ValueError em caso de falha."""
    import requests
    r = requests.post(
        f"{host.rstrip('/')}/auth", json={"password": password}, timeout=10
    )
    if r.status_code == 401:
        raise ValueError("Senha incorreta.")
    r.raise_for_status()
    return r.json()["token"]


# ── lógica de sincronização ───────────────────────────────────────────────────

def _diff_manifest(manifest: list, local_dest: Path) -> list:
    """Retorna itens do manifesto que diferem do estado local."""
    to_get = []
    for item in manifest:
        local = local_dest / item["path"]
        if not local.exists():
            to_get.append(item)
        else:
            st = local.stat()
            if st.st_size != item["size"] or abs(st.st_mtime - item["mtime"]) > 1:
                to_get.append(item)
    return to_get


def pull(client: SyncClient, remote_path: str, local_dest: Path, log_fn, progress_fn=None):
    """Baixa arquivos do daemon (remote_path) → local_dest."""
    log_fn("Buscando lista de arquivos...")
    try:
        manifest = client.get_manifest(remote_path)
    except Exception as e:
        log_fn(f"Erro ao conectar: {e}")
        return False

    to_download = _diff_manifest(manifest, local_dest)
    total, to_dl = len(manifest), len(to_download)
    log_fn(f"{total} arquivo(s) no servidor — {to_dl} para baixar.")

    if to_dl == 0:
        log_fn("Tudo já sincronizado!")
        if progress_fn:
            progress_fn(100)
        return True

    if to_dl > ARCHIVE_THRESHOLD:
        # ── modo archive em lotes — evita timeout do cloudflare ──────────────
        files    = [item["path"] for item in to_download]
        batches  = [files[i:i + ARCHIVE_BATCH_SIZE]
                    for i in range(0, to_dl, ARCHIVE_BATCH_SIZE)]
        n_batches = len(batches)
        done_files = 0

        for batch_num, batch in enumerate(batches, 1):
            if n_batches > 1:
                log_fn(f"── Lote {batch_num}/{n_batches} ({len(batch)} arquivo(s)) ──")

            base_done = done_files
            batch_len = len(batch)

            def _batch_pfn(v, _b=base_done, _l=batch_len):
                if progress_fn:
                    progress_fn((_b + _l * v / 100) / to_dl * 100)

            for attempt in range(2):
                try:
                    client.download_archive(remote_path, batch, local_dest, log_fn, _batch_pfn)
                    break
                except Exception as e:
                    if attempt == 0:
                        log_fn(f"  Falha, tentando novamente... ({e})")
                    else:
                        log_fn(f"  Erro no lote {batch_num}: {e}")
                        return False

            done_files += batch_len

    else:
        # ── modo paralelo: até PARALLEL_WORKERS downloads simultâneos ────────
        done = [0]
        lock = threading.Lock()

        def _one(item):
            remote_file = str(PurePosixPath(remote_path) / item["path"])
            client.download(remote_file, local_dest / item["path"])
            with lock:
                done[0] += 1
                return done[0], item["path"]

        with ThreadPoolExecutor(max_workers=min(PARALLEL_WORKERS, to_dl)) as ex:
            futures = {ex.submit(_one, item): item for item in to_download}
            for fut in as_completed(futures):
                try:
                    n, path = fut.result()
                    log_fn(f"[{n}/{to_dl}] {path}")
                    if progress_fn:
                        progress_fn(n / to_dl * 100)
                except Exception as e:
                    log_fn(f"  Erro: {e}")

    log_fn("Concluído!")
    return True


def push(client: SyncClient, local_source: Path, remote_dest: str, log_fn, progress_fn=None):
    """Envia arquivos de local_source → daemon (remote_dest)."""
    src = local_source.resolve()
    local_files = {
        fp.relative_to(src).as_posix(): fp
        for fp in src.rglob("*") if fp.is_file()
    }

    log_fn("Verificando arquivos remotos...")
    try:
        remote_index = {item["path"]: item for item in client.get_manifest(remote_dest)}
    except Exception:
        remote_index = {}

    to_upload = []
    for rel, fp in local_files.items():
        if rel not in remote_index:
            to_upload.append((rel, fp))
        else:
            st = fp.stat()
            ri = remote_index[rel]
            if st.st_size != ri["size"] or abs(st.st_mtime - ri["mtime"]) > 1:
                to_upload.append((rel, fp))

    total, to_ul = len(local_files), len(to_upload)
    log_fn(f"{total} arquivo(s) — {to_ul} para enviar.")

    if to_ul == 0:
        log_fn("Tudo já sincronizado!")
        if progress_fn:
            progress_fn(100)
        return True

    if to_ul > ARCHIVE_THRESHOLD:
        # ── modo archive em lotes — evita timeout do cloudflare ──────────────
        batches   = [to_upload[i:i + ARCHIVE_BATCH_SIZE]
                     for i in range(0, to_ul, ARCHIVE_BATCH_SIZE)]
        n_batches = len(batches)
        done_files = 0

        for batch_num, batch in enumerate(batches, 1):
            if n_batches > 1:
                log_fn(f"── Lote {batch_num}/{n_batches} ({len(batch)} arquivo(s)) ──")

            base_done = done_files
            batch_len = len(batch)

            def _batch_pfn(v, _b=base_done, _l=batch_len):
                if progress_fn:
                    progress_fn((_b + _l * v / 100) / to_ul * 100)

            for attempt in range(2):
                try:
                    client.upload_archive(batch, remote_dest, log_fn, _batch_pfn)
                    break
                except Exception as e:
                    if attempt == 0:
                        log_fn(f"  Falha, tentando novamente... ({e})")
                    else:
                        log_fn(f"  Erro no lote {batch_num}: {e}")
                        return False

            done_files += batch_len

    else:
        # ── modo paralelo ─────────────────────────────────────────────────────
        done = [0]
        lock = threading.Lock()

        def _one(item):
            rel, fp = item
            client.upload(fp, str(PurePosixPath(remote_dest) / rel))
            with lock:
                done[0] += 1
                return done[0], rel

        with ThreadPoolExecutor(max_workers=min(PARALLEL_WORKERS, to_ul)) as ex:
            futures = {ex.submit(_one, item): item for item in to_upload}
            for fut in as_completed(futures):
                try:
                    n, rel = fut.result()
                    log_fn(f"[{n}/{to_ul}] {rel}")
                    if progress_fn:
                        progress_fn(n / to_ul * 100)
                except Exception as e:
                    log_fn(f"  Erro: {e}")

    log_fn("Concluído!")
    return True


# ── GUI ───────────────────────────────────────────────────────────────────────

def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    cfg = load_config()
    client_ref = {"client": None}

    root = tk.Tk()
    root.title("Sincronizador")
    root.resizable(False, False)

    # ── painel de conexão ─────────────────────────────────────────────────────
    conn_frame = ttk.LabelFrame(root, text="Conexão", padding=10)
    conn_frame.pack(fill="x", padx=10, pady=(10, 0))

    tk.Label(conn_frame, text="Host:").grid(row=0, column=0, sticky="w", padx=4, pady=3)
    host_var = tk.StringVar(value=cfg.get("host", "https://"))
    tk.Entry(conn_frame, textvariable=host_var, width=38).grid(
        row=0, column=1, sticky="ew", padx=4
    )

    tk.Label(conn_frame, text="Senha:").grid(row=1, column=0, sticky="w", padx=4, pady=3)
    pw_var = tk.StringVar()
    tk.Entry(conn_frame, textvariable=pw_var, show="*", width=26).grid(
        row=1, column=1, sticky="w", padx=4
    )

    conn_status_var = tk.StringVar(value="Desconectado.")
    tk.Label(conn_frame, textvariable=conn_status_var, fg="gray").grid(
        row=2, column=0, columnspan=3, pady=(4, 0)
    )

    conn_btn = tk.Button(
        conn_frame, text="Conectar",
        bg="#FF9800", fg="white", font=("Arial", 10, "bold"), padx=10,
    )
    conn_btn.grid(row=1, column=2, padx=8)

    # ── abas de operação ──────────────────────────────────────────────────────
    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=10, pady=10)

    pad = {"padx": 10, "pady": 5}
    op_buttons = []

    def make_op_tab(parent, mode):
        is_push = mode == "push"

        lbl_local  = "Pasta local (origem):"    if is_push else "Pasta local (destino):"
        lbl_remote = "Pasta no Linux (destino):" if is_push else "Pasta no Linux (origem):"

        tk.Label(parent, text=lbl_local).grid(row=0, column=0, sticky="w", **pad)
        local_var = tk.StringVar(value=cfg.get(f"{mode}_local", ""))
        tk.Entry(parent, textvariable=local_var, width=32).grid(
            row=0, column=1, sticky="ew", **pad
        )
        tk.Button(parent, text="...", command=lambda: local_var.set(
            filedialog.askdirectory() or local_var.get()
        )).grid(row=0, column=2, **pad)

        tk.Label(parent, text=lbl_remote).grid(row=1, column=0, sticky="w", **pad)
        remote_var = tk.StringVar(value=cfg.get(f"{mode}_remote", ""))
        tk.Entry(parent, textvariable=remote_var, width=36).grid(
            row=1, column=1, columnspan=2, sticky="ew", **pad
        )

        btn = tk.Button(
            parent,
            text="Enviar →" if is_push else "← Receber",
            bg="#2196F3" if is_push else "#4CAF50",
            fg="white", font=("Arial", 11, "bold"), padx=14, pady=4,
            state="disabled",
        )
        btn.grid(row=2, column=0, columnspan=3, pady=8)
        op_buttons.append(btn)

        progress = ttk.Progressbar(parent, length=400, mode="determinate")
        progress.grid(row=3, column=0, columnspan=3, padx=10, pady=4)

        status_var = tk.StringVar(value="")
        tk.Label(parent, textvariable=status_var, fg="gray").grid(
            row=4, column=0, columnspan=3
        )

        log_text = tk.Text(
            parent, height=10, width=54, state="disabled", font=("Courier", 9)
        )
        log_text.grid(row=5, column=0, columnspan=3, padx=10, pady=6)

        def log_msg(msg):
            log_text.config(state="normal")
            log_text.insert("end", msg + "\n")
            log_text.see("end")
            log_text.config(state="disabled")
            status_var.set(msg)

        def do_op():
            cl = client_ref["client"]
            if not cl:
                messagebox.showerror("Erro", "Conecte ao servidor primeiro.")
                return
            local  = local_var.get()
            remote = remote_var.get()
            if not local or not remote:
                messagebox.showerror("Erro", "Preencha as duas pastas.")
                return
            save_config({f"{mode}_local": local, f"{mode}_remote": remote})
            btn.config(state="disabled")
            log_text.config(state="normal")
            log_text.delete("1.0", "end")
            log_text.config(state="disabled")
            progress["value"] = 0

            def _run():
                fn = push if is_push else pull
                args = (cl, Path(local), remote) if is_push else (cl, remote, Path(local))
                fn(*args, log_msg, lambda v: progress.__setitem__("value", v))
                btn.config(state="normal")

            threading.Thread(target=_run, daemon=True).start()

        btn.config(command=do_op)

    tab_push = ttk.Frame(nb)
    nb.add(tab_push, text="  Enviar →  ")
    make_op_tab(tab_push, "push")

    tab_pull = ttk.Frame(nb)
    nb.add(tab_pull, text="  ← Receber  ")
    make_op_tab(tab_pull, "pull")

    # ── lógica de conexão ─────────────────────────────────────────────────────

    def do_connect():
        host = host_var.get().rstrip("/")
        pw   = pw_var.get()
        if not host or not pw:
            messagebox.showerror("Erro", "Preencha o host e a senha.")
            return
        conn_btn.config(state="disabled")
        conn_status_var.set("Conectando...")

        def _connect():
            try:
                token = do_auth(host, pw)
                cl = SyncClient(host, token)
                client_ref["client"] = cl
                save_config({"host": host})
                pw_var.set("")
                conn_status_var.set(f"Conectado → {host}")
                conn_btn.config(
                    text="Desconectar", bg="#f44336", state="normal",
                    command=do_disconnect,
                )
                for b in op_buttons:
                    b.config(state="normal")
            except Exception as e:
                conn_status_var.set(f"Falha: {e}")
                conn_btn.config(state="normal")

        threading.Thread(target=_connect, daemon=True).start()

    def do_disconnect():
        cl = client_ref["client"]
        if cl:
            threading.Thread(target=cl.logout, daemon=True).start()
            client_ref["client"] = None
        conn_status_var.set("Desconectado.")
        conn_btn.config(
            text="Conectar", bg="#FF9800", state="normal", command=do_connect,
        )
        for b in op_buttons:
            b.config(state="disabled")

    conn_btn.config(command=do_connect)

    def on_close():
        do_disconnect()
        root.after(400, root.destroy)

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sincronizador — daemon systemd + GUI Windows.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  Definir senha:     python sincronizador.py setpassword\n"
            "  Daemon (systemd):  python sincronizador.py daemon --port 5000\n"
            "  GUI (Windows):     python sincronizador.py\n"
            "  Push (CLI):        python sincronizador.py push /local https://host /remoto --password X\n"
            "  Pull (CLI):        python sincronizador.py pull https://host /remoto /local --password X\n"
        ),
    )
    sub = parser.add_subparsers(dest="mode")

    sub.add_parser("setpassword", help="Configurar senha do daemon")

    p_daemon = sub.add_parser("daemon", help="Rodar como daemon always-on")
    p_daemon.add_argument("--port", type=int, default=5000, help="Porta (padrão: 5000)")

    p_push = sub.add_parser("push", help="Enviar arquivos locais para o daemon (CLI)")
    p_push.add_argument("local",        help="Pasta local de origem")
    p_push.add_argument("host",         help="URL do daemon")
    p_push.add_argument("remote_dest",  help="Pasta de destino no servidor")
    p_push.add_argument("--password",   required=True)

    p_pull = sub.add_parser("pull", help="Receber arquivos do daemon (CLI)")
    p_pull.add_argument("host",         help="URL do daemon")
    p_pull.add_argument("remote_src",   help="Pasta de origem no servidor")
    p_pull.add_argument("local_dest",   help="Pasta destino local")
    p_pull.add_argument("--password",   required=True)

    args = parser.parse_args()

    if args.mode == "setpassword":
        cmd_setpassword()

    elif args.mode == "daemon":
        run_daemon(args.port)

    elif args.mode in ("push", "pull"):
        try:
            token = do_auth(args.host, args.password)
        except Exception as e:
            print(f"Autenticação falhou: {e}", file=sys.stderr)
            sys.exit(1)
        cl = SyncClient(args.host, token)
        try:
            if args.mode == "push":
                push(cl, Path(args.local), args.remote_dest, print)
            else:
                pull(cl, args.remote_src, Path(args.local_dest), print)
        finally:
            cl.logout()

    else:
        try:
            run_gui()
        except Exception as e:
            print(
                f"GUI indisponível ({e}). Use: python sincronizador.py --help",
                file=sys.stderr,
            )
            sys.exit(1)