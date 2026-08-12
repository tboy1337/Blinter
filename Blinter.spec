# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec file for Blinter.

This spec file includes optimizations to reduce antivirus false positives:
- Version information resource for legitimacy
- Application icon from resources/blinter_icon.ico
- Disabled UPX compression (--noupx) which triggers heuristic detection
- Console application metadata
- Company and product information

Generate ``file_version_info.txt`` before building:
  python scripts/generate_file_version_info.py
"""

block_cipher = None

a = Analysis(
    ['src/blinter/__main__.py'],
    pathex=['src'],
    binaries=[],
    datas=[
        ('src/blinter/py.typed', 'blinter'),
        ('pyproject.toml', '.'),
    ],
    hiddenimports=['blinter', 'charset_normalizer'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # GUI / IDE
        "tkinter",
        "_tkinter",
        "turtle",
        "idlelib",
        # Test frameworks
        "unittest",
        "test",
        "tests",
        "doctest",
        "pydoc",
        # Terminal UI
        "curses",
        "_curses",
        # Legacy / dev tooling
        "lib2to3",
        "ensurepip",
        "venv",
        "distutils",
        # Email / news / remote protocols (keep email - required by importlib.metadata)
        "imaplib",
        "nntplib",
        "poplib",
        "smtplib",
        "telnetlib",
        "ftplib",
        # Web / networking (not used by Blinter at runtime)
        "http",
        "http.server",
        "http.client",
        "http.cookiejar",
        "xmlrpc",
        "urllib",
        "urllib.request",
        "urllib.parse",
        "urllib.error",
        "urllib.response",
        "ssl",
        "socket",
        "ipaddress",
        "netrc",
        "mimetypes",
        # Scientific / imaging
        "matplotlib",
        "numpy",
        "PIL",
        "cv2",
        "scipy",
        "pandas",
        # Database
        "sqlite3",
        "_sqlite3",
        # XML
        "xml",
        "xmlrpc",
        # Async / multiprocessing
        "asyncio",
        "multiprocessing",
        # Bundled by PyInstaller but not in Blinter runtime import chain
        "subprocess",
        "tracemalloc",
        "difflib",
        "csv",
        "calendar",
        "argparse",
        "tarfile",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='blinter',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # CRITICAL: Disable UPX compression to reduce AV false positives
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # Console application
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version="file_version_info.txt",
    icon="resources/blinter_icon.ico",
)
