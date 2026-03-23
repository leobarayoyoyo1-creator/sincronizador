"""Cliente HTTP para sincronização."""

import os
import tarfile
import threading

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .constants import CHUNK_SIZE, MTIME_TOLERANCE, PARALLEL_WORKERS, ZSTD_LEVEL, ZSTD_THREADS
from .utils import fmt_bytes, is_name_safe


class SyncClient:
    def __init__(self, host: str, token: str):
        self.base = host.rstrip("/")
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {token}"

        adapter = HTTPAdapter(
            max_retries=Retry(
                total=3, backoff_factor=0.5,
                status_forcelist=[502, 503, 504],
            ),
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
        items = r.json()
        # Valida estrutura dos itens do manifesto
        return [
            it for it in items
            if isinstance(it, dict) and "path" in it and "size" in it and "mtime" in it
        ]

    def download(self, remote_file: str, local_path):
        from pathlib import Path
        local_path = Path(local_path)
        r = self.session.get(
            f"{self.base}/file", params={"path": remote_file},
            stream=True, timeout=300,
        )
        r.raise_for_status()
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, "wb") as f:
            for chunk in r.iter_content(CHUNK_SIZE):
                f.write(chunk)

    def upload(self, local_path, remote_file: str):
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
                if not is_name_safe(member.name):
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
                log_fn(f"[{extracted}/{total}] {member.name}  ({fmt_bytes(total_bytes)})")
                if progress_fn:
                    progress_fn(extracted / total * 100)

        if skipped:
            log_fn(f"  ({skipped} já existiam, pulados)")
        if progress_fn:
            progress_fn(100)

    def upload_archive(self, to_upload, remote_dest, log_fn, progress_fn=None):
        import zstandard as zstd

        total = len(to_upload)
        total_size = sum(size for _, _, size in to_upload)
        log_fn(f"Enviando {total} arquivo(s) ({fmt_bytes(total_size)})...")
        if progress_fn:
            progress_fn(0)

        r_fd, w_fd = os.pipe()

        def _pack():
            cctx = zstd.ZstdCompressor(level=ZSTD_LEVEL, threads=ZSTD_THREADS)
            with os.fdopen(w_fd, "wb") as raw:
                with cctx.stream_writer(raw, closefd=False) as zw:
                    with tarfile.open(fileobj=zw, mode="w|") as tar:
                        for i, (rel, fp, size) in enumerate(to_upload, 1):
                            tar.add(str(fp), arcname=rel)
                            log_fn(f"[{i}/{total}] {rel}  ({fmt_bytes(size)})")
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
    r = requests.post(
        f"{host.rstrip('/')}/auth", json={"password": password}, timeout=10,
    )
    if r.status_code == 401:
        raise ValueError("Senha incorreta.")
    r.raise_for_status()
    return r.json()["token"]
