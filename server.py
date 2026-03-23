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
    # SHA-256 legado
    return hmac.compare_digest(
        hashlib.sha256(password.encode()).hexdigest(), stored,
    )


# ── daemon Flask ───────────────────────────────────────────────────────────────

def make_daemon_app(password_hash: str):
    import zstandard as zstd
    from flask import (
        Flask, Response, abort, jsonify, send_file,
        request as freq, stream_with_context,
    )

    app = Flask(__name__)
    _tokens: set[str] = set()
    _lock = threading.Lock()

    def _add_token(tok: str):
        with _lock:
            _tokens.add(tok)

    def _remove_token(tok: str):
        with _lock:
            _tokens.discard(tok)

    def _check_token(tok: str) -> bool:
        with _lock:
            return any(hmac.compare_digest(tok, s) for s in _tokens)

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
        data = freq.get_json(silent=True) or {}
        pw = data.get("password", "")
        if not _verify_password(pw, password_hash):
            log.warning("Tentativa de login com senha incorreta")
            return jsonify({"error": "Senha incorreta"}), 401
        if ":" not in password_hash:
            save_config({"password_hash": _hash_password(pw)})
        token = secrets.token_hex(32)
        _add_token(token)
        log.info("Nova sessão autenticada")
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

        base_pfx = str(base) + os.sep
        r_fd, w_fd = os.pipe()

        def _pack():
            cctx = zstd.ZstdCompressor(level=ZSTD_LEVEL, threads=ZSTD_THREADS)
            with os.fdopen(w_fd, "wb") as raw:
                with cctx.stream_writer(raw, closefd=False) as zw:
                    with tarfile.open(fileobj=zw, mode="w|") as tar:
                        for rel in files:
                            if not _is_name_safe(rel):
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

        cl = freq.content_length
        log.info("Archive PUT para %s (Content-Length: %s)", dest, cl)

        # Lê o body inteiro em memória se o proxy já bufferizou,
        # caso contrário usa o stream direto
        import io
        raw_data = freq.get_data()
        if not raw_data:
            log.error("Body do request vazio — proxy pode estar bloqueando")
            abort(400, "Body vazio")
        log.info("Archive PUT: %d bytes recebidos", len(raw_data))

        dctx = zstd.ZstdDecompressor()
        reader = dctx.stream_reader(io.BytesIO(raw_data), closefd=False)

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

        return jsonify({"ok": True})

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
