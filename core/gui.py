"""GUI desktop com customtkinter."""

import threading
import time
from pathlib import Path

from .client import SyncClient, do_auth
from .config import load_config, save_config
from .constants import MAX_LOG_LINES
from .sync_logic import pull, push
from .utils import fmt_eta


def run_gui():
    import customtkinter as ctk
    from tkinter import filedialog, messagebox

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    cfg = load_config()
    client_ref = {"client": None}
    busy_lock = threading.Lock()
    cancel_event = threading.Event()

    root = ctk.CTk()
    root.title("Sincronizador")
    root.geometry("680x820")
    root.minsize(620, 720)

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

        # botões ação + cancelar
        if is_push:
            btn_fg, btn_hover = "#2980B9", "#2471A3"
            btn_text = "Enviar  →"
        else:
            btn_fg, btn_hover = "#27AE60", "#229954"
            btn_text = "←  Receber"

        btn_row = ctk.CTkFrame(parent, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(0, 14))

        action_btn = ctk.CTkButton(
            btn_row, text=btn_text, height=44, corner_radius=10,
            fg_color=btn_fg, hover_color=btn_hover,
            font=ctk.CTkFont(size=15, weight="bold"),
            state="disabled",
        )
        action_btn.pack(side="left", fill="x", expand=True, padx=(0, 8))
        op_buttons.append(action_btn)

        cancel_btn = ctk.CTkButton(
            btn_row, text="Cancelar", height=44, width=100, corner_radius=10,
            fg_color="#E74C3C", hover_color="#C0392B",
            font=ctk.CTkFont(size=13, weight="bold"),
            state="disabled",
        )
        cancel_btn.pack(side="right")

        # progresso
        prog_row = ctk.CTkFrame(parent, fg_color="transparent")
        prog_row.pack(fill="x", padx=20, pady=(0, 6))

        progress_bar = ctk.CTkProgressBar(prog_row, height=16, corner_radius=8)
        progress_bar.pack(side="left", fill="x", expand=True, padx=(0, 12))
        progress_bar.set(0)

        pct_label = ctk.CTkLabel(
            prog_row, text="0 %", width=130,
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="e",
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
                # Limita número de linhas para não crescer infinitamente
                line_count = int(log_box.index("end-1c").split(".")[0])
                if line_count > MAX_LOG_LINES:
                    log_box.delete("1.0", f"{line_count - MAX_LOG_LINES}.0")
                log_box.see("end")
                log_box.configure(state="disabled")
                status_var.set(msg)
            ui(_do)

        start_time = [0.0]

        def set_progress(v):
            elapsed = time.monotonic() - start_time[0]
            if v > 0 and elapsed > 2:
                eta = elapsed / v * (100 - v)
                extra = f"  ETA {fmt_eta(eta)}"
            else:
                extra = ""
            def _do():
                progress_bar.set(v / 100)
                pct_label.configure(text=f"{v:.0f} %{extra}")
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
                messagebox.showinfo("Aguarde", "Operação em andamento.")
                return

            cancel_event.clear()
            save_config({f"{mode}_local": local_val, f"{mode}_remote": remote_val})
            action_btn.configure(state="disabled")
            cancel_btn.configure(state="normal")
            log_box.configure(state="normal")
            log_box.delete("1.0", "end")
            log_box.configure(state="disabled")
            set_progress(0)
            start_time[0] = time.monotonic()

            def _run():
                try:
                    if is_push:
                        push(cl, Path(local_val), remote_val, log_msg, set_progress, cancel_event)
                    else:
                        pull(cl, remote_val, Path(local_val), log_msg, set_progress, cancel_event)
                except Exception as e:
                    log_msg(f"Erro: {e}")
                finally:
                    elapsed = time.monotonic() - start_time[0]
                    log_msg(f"Tempo total: {fmt_eta(elapsed)}")
                    busy_lock.release()
                    ui(lambda: action_btn.configure(state="normal"))
                    ui(lambda: cancel_btn.configure(state="disabled"))

            threading.Thread(target=_run, daemon=True).start()

        def do_cancel():
            cancel_event.set()
            cancel_btn.configure(state="disabled")

        action_btn.configure(command=do_op)
        cancel_btn.configure(command=do_cancel)

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
