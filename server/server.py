import hashlib
import json
from flask import Flask, jsonify, send_file, abort, request
from pathlib import Path

app = Flask(__name__)

with open(Path(__file__).parent / "config.json") as f:
    config = json.load(f)

SOURCE_FOLDER = Path(config["folder"]).resolve()
PORT = config.get("port", 5000)


def md5_of_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


@app.route("/")
def index():
    return f"<h1>Sincronizador</h1><p>Servindo: <code>{SOURCE_FOLDER}</code></p>"


@app.route("/manifest")
def manifest():
    files = []
    for file_path in SOURCE_FOLDER.rglob("*"):
        if file_path.is_file():
            relative = file_path.relative_to(SOURCE_FOLDER)
            files.append({
                "path": str(relative).replace("\\", "/"),
                "size": file_path.stat().st_size,
                "md5": md5_of_file(file_path),
            })
    return jsonify(files)


@app.route("/file")
def serve_file():
    rel_path = request.args.get("path", "")
    if not rel_path:
        abort(400)

    target = (SOURCE_FOLDER / rel_path).resolve()

    # Bloqueia path traversal (ex: ../../etc/passwd)
    if not str(target).startswith(str(SOURCE_FOLDER)):
        abort(403)

    if not target.exists():
        abort(404)

    return send_file(target)


if __name__ == "__main__":
    print(f"Servindo pasta: {SOURCE_FOLDER}")
    print(f"Rodando em: http://0.0.0.0:{PORT}")
    app.run(host="0.0.0.0", port=PORT)
