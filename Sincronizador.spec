# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files

# customtkinter precisa dos seus temas/imagens em runtime
datas = collect_data_files("customtkinter")

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "zstandard",
        "charset_normalizer",           # requests falha sem isso em alguns builds
        "charset_normalizer.md__mypyc", # idem
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "matplotlib", "numpy", "pandas", "scipy",
        "PIL", "cv2",
        "xmlrpc", "ftplib", "imaplib", "poplib", "smtplib",
        "unittest", "doctest", "pydoc", "pdb",
        "tkinter.test",
        "sqlite3", "_sqlite3",
        "distutils", "setuptools", "pkg_resources",
        "multiprocessing",
        "xml.etree.cElementTree",
    ],
    noarchive=False,
    optimize=2,  # remove docstrings + asserts
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Sincronizador",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[
        "vcruntime140.dll",  # UPX corrompe DLLs do runtime do Windows
        "msvcp140.dll",
        "python*.dll",
    ],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
