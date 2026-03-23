#!/usr/bin/env python3
"""Sincronizador — desktop (GUI + CLI push/pull).

Exemplos:
  GUI:        python desktop.py
  Push (CLI): python desktop.py push /local https://host /remoto --password X
  Pull (CLI): python desktop.py pull https://host /remoto /local --password X

  Dica: defina SYNC_PASSWORD para evitar --password no CLI.
"""

import argparse
import os
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Sincronizador — GUI desktop + CLI push/pull.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  GUI:        python desktop.py\n"
            "  Push (CLI): python desktop.py push /local https://host /remoto --password X\n"
            "  Pull (CLI): python desktop.py pull https://host /remoto /local --password X\n"
            "\n  Dica: defina SYNC_PASSWORD para evitar --password no CLI.\n"
        ),
    )
    sub = parser.add_subparsers(dest="mode")

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

    if args.mode in ("push", "pull"):
        from .http import SyncClient, do_auth
        from .sync_logic import pull, push

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
            from .gui import run_gui
            run_gui()
        except ImportError as e:
            print(f"GUI indisponível: {e}", file=sys.stderr)
            print("  pip install customtkinter", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
