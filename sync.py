#!/usr/bin/env python3
"""Sincronizador — servidor ou cliente, Windows 11 e Ubuntu Server."""

import argparse
import json
import sys
import threading
from pathlib import Path

CONFIG_FILE = Path(__file__).parent / "config.json"


# ── utilitários ───────────────────────────────────────────────────────────────

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


# ── Flask (servidor) ──────────────────────────────────────────────────────────

def make_flask_app(source_folder: Path):
    from flask import Flask, jsonify, send_file, abort, request as freq

    app = Flask(__name__)
    src = source_folder.resolve()

    @app.route("/")
    def index():
        return f"<h1>Sincronizador</h1><p>Servindo: <code>{src}</code></p>"

    @app.route("/manifest")
    def manifest():
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

    @app.route("/file")
    def serve_file():
        rel = freq.args.get("path", "")
        if not rel:
            abort(400)
        target = (src / rel).resolve()
        if not str(target).startswith(str(src)):
            abort(403)
        if not target.exists():
            abort(404)
        return send_file(target)

    return app, src


def run_server_cli(folder: str, port: int):
    source = Path(folder)
    if not source.exists():
        print(f"Erro: pasta não encontrada: {folder}", file=sys.stderr)
        sys.exit(1)
    app, src = make_flask_app(source)
    print(f"Servindo : {src}")
    print(f"Endereço : http://0.0.0.0:{port}")
    print("Ctrl+C para parar.")
    import logging
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app.run(host="0.0.0.0", port=port)


# ── sincronização (cliente) ───────────────────────────────────────────────────

def sync(url: str, dest: Path, log_fn, progress_fn=None) -> bool:
    import requests

    log_fn("Buscando lista de arquivos...")
    try:
        resp = requests.get(f"{url}/manifest", timeout=15)
        resp.raise_for_status()
        manifest = resp.json()
    except Exception as e:
        log_fn(f"Erro ao conectar: {e}")
        return False

    to_download = []
    for item in manifest:
        local = dest / item["path"]
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
        log_fn(f"[{i}/{to_dl}] {item['path']}")
        try:
            r = requests.get(
                f"{url}/file", params={"path": item["path"]},
                stream=True, timeout=60,
            )
            r.raise_for_status()
            local = dest / item["path"]
            local.parent.mkdir(parents=True, exist_ok=True)
            with open(local, "wb") as f:
                for chunk in r.iter_content(8192):
                    f.write(chunk)
            if progress_fn:
                progress_fn(i / to_dl * 100)
        except Exception as e:
            log_fn(f"  Erro: {e}")

    log_fn("Sincronização concluída!")
    return True


def run_client_cli(url: str, dest: str):
    sync(url.rstrip("/"), Path(dest), print)


# ── GUI ───────────────────────────────────────────────────────────────────────

def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    cfg = load_config()
    root = tk.Tk()
    root.title("Sincronizador")
    root.resizable(False, False)

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=10, pady=10)

    pad = {"padx": 12, "pady": 6}

    # ══ ABA SERVIDOR ══════════════════════════════════════════════════════════
    tab_srv = ttk.Frame(nb)
    nb.add(tab_srv, text="  Servidor  ")

    tk.Label(tab_srv, text="Pasta a servir:").grid(row=0, column=0, sticky="w", **pad)
    srv_folder_var = tk.StringVar(value=cfg.get("server_folder", ""))
    tk.Entry(tab_srv, textvariable=srv_folder_var, width=36).grid(row=0, column=1, sticky="ew", **pad)
    tk.Button(tab_srv, text="...", command=lambda: srv_folder_var.set(
        filedialog.askdirectory() or srv_folder_var.get()
    )).grid(row=0, column=2, **pad)

    tk.Label(tab_srv, text="Porta:").grid(row=1, column=0, sticky="w", **pad)
    srv_port_var = tk.StringVar(value=str(cfg.get("port", 5000)))
    tk.Entry(tab_srv, textvariable=srv_port_var, width=8).grid(row=1, column=1, sticky="w", **pad)

    srv_status_var = tk.StringVar(value="Parado.")
    tk.Label(tab_srv, textvariable=srv_status_var, fg="gray").grid(
        row=2, column=0, columnspan=3, pady=4
    )

    srv_btn_ref = {}

    def start_server():
        folder = srv_folder_var.get()
        if not folder:
            messagebox.showerror("Erro", "Selecione a pasta a servir.")
            return
        try:
            port = int(srv_port_var.get())
        except ValueError:
            messagebox.showerror("Erro", "Porta inválida.")
            return

        source = Path(folder)
        if not source.exists():
            messagebox.showerror("Erro", f"Pasta não encontrada:\n{folder}")
            return

        save_config({"server_folder": folder, "port": port})

        app, src = make_flask_app(source)
        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)

        srv_status_var.set(f"Rodando em http://0.0.0.0:{port}")
        srv_btn_ref["btn"].config(state="disabled")

        threading.Thread(
            target=lambda: app.run(host="0.0.0.0", port=port),
            daemon=True,
        ).start()

    btn_srv = tk.Button(
        tab_srv, text="Iniciar Servidor",
        command=start_server,
        bg="#2196F3", fg="white",
        font=("Arial", 11, "bold"), padx=14, pady=4,
    )
    btn_srv.grid(row=3, column=0, columnspan=3, pady=10)
    srv_btn_ref["btn"] = btn_srv

    # ══ ABA CLIENTE ═══════════════════════════════════════════════════════════
    tab_cli = ttk.Frame(nb)
    nb.add(tab_cli, text="  Cliente  ")

    tk.Label(tab_cli, text="URL do servidor:").grid(row=0, column=0, sticky="w", **pad)
    url_var = tk.StringVar(value=cfg.get("server_url", "http://"))
    tk.Entry(tab_cli, textvariable=url_var, width=42).grid(
        row=0, column=1, columnspan=2, sticky="ew", **pad
    )

    tk.Label(tab_cli, text="Pasta destino:").grid(row=1, column=0, sticky="w", **pad)
    dest_var = tk.StringVar(value=cfg.get("destination", ""))
    tk.Entry(tab_cli, textvariable=dest_var, width=36).grid(row=1, column=1, sticky="ew", **pad)
    tk.Button(tab_cli, text="...", command=lambda: dest_var.set(
        filedialog.askdirectory() or dest_var.get()
    )).grid(row=1, column=2, **pad)

    sync_btn = tk.Button(
        tab_cli, text="Sincronizar",
        bg="#4CAF50", fg="white",
        font=("Arial", 11, "bold"), padx=14, pady=4,
    )
    sync_btn.grid(row=2, column=0, columnspan=3, pady=10)

    progress = ttk.Progressbar(tab_cli, length=420, mode="determinate")
    progress.grid(row=3, column=0, columnspan=3, padx=12, pady=4)

    cli_status_var = tk.StringVar(value="Pronto.")
    tk.Label(tab_cli, textvariable=cli_status_var, fg="gray").grid(
        row=4, column=0, columnspan=3, pady=2
    )

    log_text = tk.Text(tab_cli, height=10, width=56, state="disabled", font=("Courier", 9))
    log_text.grid(row=5, column=0, columnspan=3, padx=12, pady=6)

    def log_msg(msg):
        log_text.config(state="normal")
        log_text.insert("end", msg + "\n")
        log_text.see("end")
        log_text.config(state="disabled")
        cli_status_var.set(msg)

    def set_progress(val):
        progress["value"] = val

    def do_sync():
        url = url_var.get().rstrip("/")
        dest = dest_var.get()
        if not url or not dest:
            messagebox.showerror("Erro", "Preencha a URL e a pasta destino.")
            return
        save_config({"server_url": url, "destination": dest})
        sync_btn.config(state="disabled")
        log_text.config(state="normal")
        log_text.delete("1.0", "end")
        log_text.config(state="disabled")
        progress["value"] = 0

        def _run():
            sync(url, Path(dest), log_msg, set_progress)
            sync_btn.config(state="normal")

        threading.Thread(target=_run, daemon=True).start()

    sync_btn.config(command=do_sync)

    root.mainloop()


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sincronizador de arquivos — servidor ou cliente.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  Abrir GUI:                  python sincronizador.py\n"
            "  Servidor headless:          python sincronizador.py server /minha/pasta --port 5000\n"
            "  Cliente headless:           python sincronizador.py client http://192.168.1.10:5000 /destino\n"
        ),
    )
    sub = parser.add_subparsers(dest="mode")

    p_srv = sub.add_parser("server", help="Rodar como servidor (sem GUI)")
    p_srv.add_argument("folder", help="Pasta a servir")
    p_srv.add_argument("--port", type=int, default=5000, help="Porta (padrão: 5000)")

    p_cli = sub.add_parser("client", help="Sincronizar arquivos (sem GUI)")
    p_cli.add_argument("url", help="URL do servidor  ex: http://192.168.1.10:5000")
    p_cli.add_argument("dest", help="Pasta destino local")

    args = parser.parse_args()

    if args.mode == "server":
        run_server_cli(args.folder, args.port)
    elif args.mode == "client":
        run_client_cli(args.url, args.dest)
    else:
        try:
            run_gui()
        except Exception as e:
            print(f"GUI indisponível ({e}). Use: python sincronizador.py --help", file=sys.stderr)
            sys.exit(1)