#!/usr/bin/env python3
"""Sincronizador — daemon always-on (systemd) + GUI Windows para push/pull.

Fluxo de autenticação:
  1. GUI abre → usuário digita host e senha → clica Conectar
  2. POST /auth com senha → servidor verifica hash → retorna token de sessão
  3. Todas as rotas exigem header  Authorization: Bearer <token>
  4. Apenas uma sessão ativa por vez (novo login invalida o anterior)
  5. Ao fechar a GUI (ou /logout) o servidor descarta o token
"""

import argparse
import hashlib
import json
import secrets
import sys
import threading
from functools import wraps
from pathlib import Path, PurePosixPath

CONFIG_FILE = Path(__file__).parent / "config.json"


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
    from flask import Flask, jsonify, send_file, abort, request as freq

    app = Flask(__name__)
    app.active_token = None  # única sessão ativa

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
        pw = data.get("password", "")
        if hash_password(pw) != password_hash:
            return jsonify({"error": "Senha incorreta"}), 401
        token = secrets.token_hex(32)
        app.active_token = token          # invalida sessão anterior automaticamente
        return jsonify({"token": token})

    @app.route("/logout", methods=["POST"])
    @require_auth
    def logout():
        app.active_token = None
        return jsonify({"ok": True})

    @app.route("/manifest")
    @require_auth
    def manifest():
        path_str = freq.args.get("path", "")
        if not path_str:
            abort(400, "path required")
        src = Path(path_str).resolve()
        if not src.exists() or not src.is_dir():
            return jsonify([])            # destino ainda não existe → lista vazia (push cria)
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

    @app.route("/file", methods=["GET"])
    @require_auth
    def get_file():
        path_str = freq.args.get("path", "")
        if not path_str:
            abort(400)
        p = Path(path_str).resolve()
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
            while True:
                chunk = freq.stream.read(65536)
                if not chunk:
                    break
                out.write(chunk)
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
    app.run(host="127.0.0.1", port=port)


def cmd_setpassword():
    import getpass
    pw = getpass.getpass("Nova senha: ")
    if not pw:
        print("Senha não pode ser vazia.", file=sys.stderr)
        sys.exit(1)
    confirm = getpass.getpass("Confirmar senha: ")
    if pw != confirm:
        print("Senhas não conferem.", file=sys.stderr)
        sys.exit(1)
    save_config({"password_hash": hash_password(pw)})
    print("Senha salva.")


# ── cliente de API ────────────────────────────────────────────────────────────

class SyncClient:
    def __init__(self, host: str, token: str):
        self.base = host.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"}

    def get_manifest(self, remote_path: str) -> list:
        import requests
        r = requests.get(
            f"{self.base}/manifest", params={"path": remote_path},
            headers=self.headers, timeout=15,
        )
        r.raise_for_status()
        return r.json()

    def download(self, remote_file: str, local_path: Path):
        import requests
        r = requests.get(
            f"{self.base}/file", params={"path": remote_file},
            headers=self.headers, stream=True, timeout=120,
        )
        r.raise_for_status()
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, "wb") as f:
            for chunk in r.iter_content(65536):
                f.write(chunk)

    def upload(self, local_path: Path, remote_file: str):
        import requests
        with open(local_path, "rb") as f:
            r = requests.post(
                f"{self.base}/file", params={"path": remote_file},
                data=f, headers=self.headers, timeout=120,
            )
        r.raise_for_status()

    def logout(self):
        import requests
        try:
            requests.post(f"{self.base}/logout", headers=self.headers, timeout=5)
        except Exception:
            pass


def do_auth(host: str, password: str) -> str:
    """Autentica e retorna o token. Lança exceção em caso de falha."""
    import requests
    r = requests.post(
        f"{host.rstrip('/')}/auth",
        json={"password": password},
        timeout=10,
    )
    if r.status_code == 401:
        raise ValueError("Senha incorreta.")
    r.raise_for_status()
    return r.json()["token"]


# ── lógica de sincronização ───────────────────────────────────────────────────

def pull(client: SyncClient, remote_path: str, local_dest: Path, log_fn, progress_fn=None):
    """Baixa arquivos do daemon (remote_path) para local_dest."""
    log_fn("Buscando lista de arquivos...")
    try:
        manifest = client.get_manifest(remote_path)
    except Exception as e:
        log_fn(f"Erro ao conectar: {e}")
        return False

    to_download = []
    for item in manifest:
        local = local_dest / item["path"]
        if not local.exists():
            to_download.append(item)
        else:
            st = local.stat()
            if st.st_size != item["size"] or abs(st.st_mtime - item["mtime"]) > 1:
                to_download.append(item)

    total, to_dl = len(manifest), len(to_download)
    log_fn(f"{total} arquivo(s) no servidor — {to_dl} para baixar.")
    if to_dl == 0:
        log_fn("Tudo já sincronizado!")
        return True

    for i, item in enumerate(to_download, 1):
        remote_file = str(PurePosixPath(remote_path) / item["path"])
        log_fn(f"[{i}/{to_dl}] {item['path']}")
        try:
            client.download(remote_file, local_dest / item["path"])
            if progress_fn:
                progress_fn(i / to_dl * 100)
        except Exception as e:
            log_fn(f"  Erro: {e}")

    log_fn("Concluído!")
    return True


def push(client: SyncClient, local_source: Path, remote_dest: str, log_fn, progress_fn=None):
    """Envia arquivos de local_source para o daemon (remote_dest)."""
    src = local_source.resolve()
    local_files = {
        fp.relative_to(src).as_posix(): fp
        for fp in src.rglob("*") if fp.is_file()
    }

    log_fn("Verificando arquivos remotos...")
    try:
        remote_index = {item["path"]: item for item in client.get_manifest(remote_dest)}
    except Exception:
        remote_index = {}   # destino não existe ainda — envia tudo

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
        return True

    for i, (rel, fp) in enumerate(to_upload, 1):
        remote_file = str(PurePosixPath(remote_dest) / rel)
        log_fn(f"[{i}/{to_ul}] {rel}")
        try:
            client.upload(fp, remote_file)
            if progress_fn:
                progress_fn(i / to_ul * 100)
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

        lbl_local  = "Pasta local (origem):"   if is_push else "Pasta local (destino):"
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
            local = local_var.get()
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

            def _set_progress(val):
                progress["value"] = val

            def _run():
                if is_push:
                    push(cl, Path(local), remote, log_msg, _set_progress)
                else:
                    pull(cl, remote, Path(local), log_msg, _set_progress)
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
        pw = pw_var.get()
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
            text="Conectar", bg="#FF9800", state="normal",
            command=do_connect,
        )
        for b in op_buttons:
            b.config(state="disabled")

    conn_btn.config(command=do_connect)

    def on_close():
        do_disconnect()
        root.after(400, root.destroy)   # aguarda logout disparar antes de fechar

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
    p_push.add_argument("local", help="Pasta local de origem")
    p_push.add_argument("host", help="URL do daemon  ex: https://tunnel.example.com")
    p_push.add_argument("remote_dest", help="Pasta de destino no servidor")
    p_push.add_argument("--password", required=True, help="Senha do daemon")

    p_pull = sub.add_parser("pull", help="Receber arquivos do daemon (CLI)")
    p_pull.add_argument("host", help="URL do daemon  ex: https://tunnel.example.com")
    p_pull.add_argument("remote_src", help="Pasta de origem no servidor")
    p_pull.add_argument("local_dest", help="Pasta destino local")
    p_pull.add_argument("--password", required=True, help="Senha do daemon")

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