import hashlib
import json
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

import requests

CONFIG_FILE = Path(__file__).parent / "config.json"


def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {"server_url": "", "destination": ""}


def save_config(data):
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)


def md5_of_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sincronizador")
        self.resizable(False, False)
        self.config_data = load_config()
        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 12, "pady": 6}

        tk.Label(self, text="URL do servidor:").grid(row=0, column=0, sticky="w", **pad)
        self.url_var = tk.StringVar(value=self.config_data.get("server_url", ""))
        tk.Entry(self, textvariable=self.url_var, width=42).grid(row=0, column=1, columnspan=2, sticky="ew", **pad)

        tk.Label(self, text="Pasta destino:").grid(row=1, column=0, sticky="w", **pad)
        self.dest_var = tk.StringVar(value=self.config_data.get("destination", ""))
        tk.Entry(self, textvariable=self.dest_var, width=36).grid(row=1, column=1, sticky="ew", **pad)
        tk.Button(self, text="...", command=self._choose_folder).grid(row=1, column=2, **pad)

        self.sync_btn = tk.Button(
            self, text="Sincronizar",
            command=self._start_sync,
            bg="#4CAF50", fg="white",
            font=("Arial", 11, "bold"),
            padx=14, pady=4
        )
        self.sync_btn.grid(row=2, column=0, columnspan=3, pady=10)

        self.progress = ttk.Progressbar(self, length=420, mode="determinate")
        self.progress.grid(row=3, column=0, columnspan=3, padx=12, pady=4)

        self.status_var = tk.StringVar(value="Pronto.")
        tk.Label(self, textvariable=self.status_var, fg="gray").grid(row=4, column=0, columnspan=3, pady=2)

        self.log = tk.Text(self, height=12, width=56, state="disabled", font=("Courier", 9))
        self.log.grid(row=5, column=0, columnspan=3, padx=12, pady=6)

    def _choose_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.dest_var.set(folder)

    def _log(self, msg):
        self.log.config(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.config(state="disabled")
        self.status_var.set(msg)

    def _start_sync(self):
        url = self.url_var.get().rstrip("/")
        dest = self.dest_var.get()

        if not url or not dest:
            messagebox.showerror("Erro", "Preencha a URL e a pasta destino.")
            return

        save_config({"server_url": url, "destination": dest})

        self.sync_btn.config(state="disabled")
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")
        self.progress["value"] = 0

        threading.Thread(target=self._sync, args=(url, dest), daemon=True).start()

    def _sync(self, url, dest):
        dest_path = Path(dest)

        try:
            self._log("Buscando lista de arquivos...")
            resp = requests.get(f"{url}/manifest", timeout=15)
            resp.raise_for_status()
            manifest = resp.json()
        except Exception as e:
            self._log(f"Erro ao conectar: {e}")
            self.sync_btn.config(state="normal")
            return

        to_download = []
        for item in manifest:
            local_file = dest_path / item["path"]
            if not local_file.exists():
                to_download.append(item)
            elif md5_of_file(local_file) != item["md5"]:
                to_download.append(item)

        total = len(manifest)
        to_dl = len(to_download)
        self._log(f"{total} arquivo(s) no servidor — {to_dl} para baixar.")

        if to_dl == 0:
            self._log("Tudo já sincronizado!")
            self.sync_btn.config(state="normal")
            return

        for i, item in enumerate(to_download, 1):
            try:
                self._log(f"[{i}/{to_dl}] {item['path']}")
                r = requests.get(f"{url}/file", params={"path": item["path"]}, stream=True, timeout=60)
                r.raise_for_status()

                local_file = dest_path / item["path"]
                local_file.parent.mkdir(parents=True, exist_ok=True)

                with open(local_file, "wb") as f:
                    for chunk in r.iter_content(8192):
                        f.write(chunk)

                self.progress["value"] = (i / to_dl) * 100
                self.update_idletasks()

            except Exception as e:
                self._log(f"  Erro: {e}")

        self._log("Sincronização concluída!")
        self.sync_btn.config(state="normal")


if __name__ == "__main__":
    App().mainloop()
