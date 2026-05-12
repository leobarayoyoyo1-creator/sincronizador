import argparse
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import tarfile
import threading
import time
from collections import defaultdict, deque
from functools import wraps
from pathlib import Path

# ── constantes ─────────────────────────────────────────────────────────────────

CONFIG_FILE = Path(__file__).parent / "config.json"
CHUNK_SIZE = 524_288          # 512 KB
BASE_DIR = Path("/sistemas")
ZSTD_LEVEL = 1
ZSTD_THREADS = min(os.cpu_count() or 1, 8)
PBKDF2_ITERATIONS = 600_000
MAX_UPLOAD_BYTES = 10 * 1024**3  # 10 GB

TOKEN_TTL_SECONDS = 24 * 3600         # sessão expira em 24h
AUTH_WINDOW_SECONDS = 60              # janela do rate limit
AUTH_MAX_ATTEMPTS = 5                 # tentativas por janela por IP

log = logging.getLogger("sincronizador")


# ── utilidades ─────────────────────────────────────────────────────────────────

def _safe_path(user_path: str) -> Path | None:
    """Valida que o caminho resolve dentro de BASE_DIR."""
    if not user_path:
        return None
    try:
        resolved = Path(user_path).resolve()
        base = BASE_DIR.resolve()
        if resolved == base or resolved.is_relative_to(base):
            return resolved
    except (ValueError, OSError):
        pass
    return None


def _is_name_safe(name: str) -> bool:
    """Verifica que um nome de membro de tar não escapa do destino."""
    return not name.startswith("/") and ".." not in name.split("/")


class _LimitedReader:
    """Wrapper que corta a leitura ao atingir limit bytes."""

    def __init__(self, stream, limit: int):
        self._stream = stream
        self._limit = limit
        self._read = 0

    def read(self, n: int = -1) -> bytes:
        remaining = self._limit - self._read
        if remaining <= 0:
            return b""
        to_read = remaining if n is None or n < 0 else min(n, remaining)
        chunk = self._stream.read(to_read)
        self._read += len(chunk)
        return chunk


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
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass


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
            "sha256", password.encode(), bytes.fromhex(salt_hex), PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    # SHA-256 legado — primeiro login válido migra automaticamente
    return hmac.compare_digest(
        hashlib.sha256(password.encode()).hexdigest(), stored,
    )


# ── daemon Flask ───────────────────────────────────────────────────────────────

def make_daemon_app(password_hash: str):
    import zstandard as zstd
    from flask import (
        Flask,
        Response,
        abort,
        jsonify,
        send_file,
        stream_with_context,
    )
    from flask import request as freq

    app = Flask(__name__)
    _tokens: dict[str, float] = {}      # token -> created_at
    _lock = threading.Lock()
    _auth_attempts: dict[str, deque] = defaultdict(deque)
    _auth_lock = threading.Lock()

    def _client_ip() -> str:
        xff = freq.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return freq.remote_addr or "unknown"

    def _check_rate_limit(ip: str) -> bool:
        now = time.monotonic()
        with _auth_lock:
            attempts = _auth_attempts[ip]
            while attempts and attempts[0] < now - AUTH_WINDOW_SECONDS:
                attempts.popleft()
            if len(attempts) >= AUTH_MAX_ATTEMPTS:
                return False
            attempts.append(now)
            return True

    def _add_token(tok: str):
        now = time.monotonic()
        with _lock:
            _tokens[tok] = now
            expired = [t for t, ts in _tokens.items() if now - ts > TOKEN_TTL_SECONDS]
            for t in expired:
                _tokens.pop(t, None)

    def _remove_token(tok: str):
        with _lock:
            _tokens.pop(tok, None)

    def _check_token(tok: str) -> bool:
        now = time.monotonic()
        with _lock:
            expired = [t for t, ts in _tokens.items() if now - ts > TOKEN_TTL_SECONDS]
            for t in expired:
                _tokens.pop(t, None)
            return any(hmac.compare_digest(tok, t) for t in _tokens)

    def require_auth(f):
        @wraps(f)
        def wrapper(*a, **kw):
            tok = freq.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            if not tok or not _check_token(tok):
                return jsonify({"error": "Não autorizado"}), 401
            return f(*a, **kw)
        return wrapper

    # ── rotas ──────────────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        return "<h1>Sincronizador</h1><p>OK</p>"

    @app.route("/auth", methods=["POST"])
    def auth():
        ip = _client_ip()
        if not _check_rate_limit(ip):
            log.warning("Rate limit atingido em /auth para %s", ip)
            return jsonify({"error": "Muitas tentativas, aguarde"}), 429
        data = freq.get_json(silent=True) or {}
        pw = data.get("password", "")
        if not _verify_password(pw, password_hash):
            log.warning("Tentativa de login com senha incorreta de %s", ip)
            return jsonify({"error": "Senha incorreta"}), 401
        if ":" not in password_hash:
            save_config({"password_hash": _hash_password(pw)})
        token = secrets.token_hex(32)
        _add_token(token)
        log.info("Nova sessão autenticada para %s", ip)
        return jsonify({"token": token})

    @app.route("/logout", methods=["POST"])
    @require_auth
    def logout():
        tok = freq.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        _remove_token(tok)
        log.info("Sessão encerrada")
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
        content_length = freq.content_length or 0
        if content_length > MAX_UPLOAD_BYTES:
            abort(413, "Arquivo excede limite de upload")
        p.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with open(p, "wb") as out:
            while chunk := freq.stream.read(CHUNK_SIZE):
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES:
                    break
                out.write(chunk)
        if written > MAX_UPLOAD_BYTES:
            p.unlink(missing_ok=True)
            abort(413, "Upload excede limite")
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
        if not all(isinstance(f, str) for f in files):
            abort(400, "files deve ser lista de strings")

        base_pfx = str(base) + os.sep
        r_fd, w_fd = os.pipe()
        cancel = threading.Event()

        def _pack():
            try:
                cctx = zstd.ZstdCompressor(level=ZSTD_LEVEL, threads=ZSTD_THREADS)
                with os.fdopen(w_fd, "wb") as raw:
                    with cctx.stream_writer(raw, closefd=False) as zw:
                        with tarfile.open(fileobj=zw, mode="w|") as tar:
                            for rel in files:
                                if cancel.is_set():
                                    return
                                if not _is_name_safe(rel):
                                    continue
                                fp = (base / rel).resolve()
                                if str(fp).startswith(base_pfx) and fp.is_file():
                                    tar.add(fp, arcname=rel)
            except (BrokenPipeError, OSError):
                pass  # cliente desconectou — encerramento limpo

        t = threading.Thread(target=_pack, daemon=True)
        t.start()

        def _gen():
            try:
                with os.fdopen(r_fd, "rb") as rf:
                    while True:
                        chunk = rf.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        yield chunk
            finally:
                cancel.set()
                t.join(timeout=5)

        return Response(stream_with_context(_gen()), mimetype="application/zstd")

    @app.route("/archive", methods=["PUT"])
    @require_auth
    def put_archive():
        dest = _safe_path(freq.args.get("path", ""))
        if dest is None:
            abort(403, "Caminho fora de /sistemas")

        content_length = freq.content_length or 0
        if content_length > MAX_UPLOAD_BYTES:
            abort(413, "Archive excede limite de upload")

        dest.mkdir(parents=True, exist_ok=True)
        dest_pfx = str(dest) + os.sep

        log.info("Archive PUT para %s (Content-Length: %s)", dest, content_length)

        limited = _LimitedReader(freq.stream, MAX_UPLOAD_BYTES)
        dctx = zstd.ZstdDecompressor()
        reader = dctx.stream_reader(limited, closefd=False)

        extracted = 0
        try:
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                for member in tar:
                    if not (member.isreg() or member.isdir()):
                        continue
                    if not _is_name_safe(member.name):
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
                        extracted += 1
        except tarfile.ReadError as e:
            log.error("Archive corrompido: %s", e)
            abort(400, "Archive inválido")

        log.info("Archive PUT concluído: %d arquivo(s)", extracted)
        return jsonify({"ok": True, "extracted": extracted})

    return app


def run_daemon(port: int, bind: str = "127.0.0.1"):
    cfg = load_config()
    ph = cfg.get("password_hash")
    if not ph:
        print("Nenhuma senha configurada. Execute:", file=sys.stderr)
        print("  python server.py setpassword", file=sys.stderr)
        sys.exit(1)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    app = make_daemon_app(ph)

    try:
        from waitress import serve
        log.info(
            "Daemon em http://%s:%d  (waitress, %d threads zstd)",
            bind, port, ZSTD_THREADS,
        )
        serve(app, host=bind, port=port, threads=8)
    except ImportError:
        logging.getLogger("werkzeug").setLevel(logging.WARNING)
        log.info("Daemon em http://%s:%d  (werkzeug)", bind, port)
        log.info("  dica: pip install waitress  para melhor performance")
        app.run(host=bind, port=port, threaded=True)


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


# ── entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sincronizador — daemon systemd.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  Definir senha:  python server.py setpassword\n"
            "  Iniciar daemon: python server.py daemon --port 5000\n"
            "  Bind externo:   python server.py daemon --port 5000 --bind 0.0.0.0\n"
        ),
    )
    sub = parser.add_subparsers(dest="mode")

    sub.add_parser("setpassword", help="Configurar senha do daemon")

    p_daemon = sub.add_parser("daemon", help="Rodar como daemon")
    p_daemon.add_argument("--port", type=int, default=5000)
    p_daemon.add_argument("--bind", default="127.0.0.1",
                          help="Endereço de bind (padrão: 127.0.0.1)")

    args = parser.parse_args()

    if args.mode == "setpassword":
        cmd_setpassword()
    elif args.mode == "daemon":
        run_daemon(args.port, args.bind)
    else:
        parser.print_help()
        sys.exit(1)
