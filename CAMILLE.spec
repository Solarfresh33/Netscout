# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for CAMILLE Desktop.

Build (on Windows):
    pip install -r requirements.txt pyinstaller pywebview
    pyinstaller CAMILLE.spec

Output:
    dist/CAMILLE.exe   (single-file, no Python install needed on the target)
"""

block_cipher = None

a = Analysis(
    ['camille/desktop.py'],
    pathex=[],
    binaries=[],
    datas=[
        # Bundle the UI and icon so they exist inside the frozen exe.
        ('camille/web/static/index.html', 'camille/web/static'),
        ('camille/web/static/app.ico',    'camille/web/static'),
        ('camille/web/static/app.png',    'camille/web/static'),
    ],
    hiddenimports=[
        # Imported dynamically / via Flask & pywebview — declare explicitly.
        'camille.web.server',
        'camille.modules.port_scanner',
        'camille.modules.ssl_analyzer',
        'camille.modules.dns_enum',
        'camille.modules.http_analyzer',
        'camille.reports.generator',
        'dns', 'dns.resolver', 'dns.zone', 'dns.query',
        # NOTE: pywebview ships its own PyInstaller hooks that pull in the
        # correct platform backend (Edge WebView2 on Windows) automatically,
        # so we deliberately do NOT hard-list webview.platforms.* here.
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'pytest', 'playwright'],
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
    name='CAMILLE',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,            # no console window — pure GUI app
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='camille/web/static/app.ico',
)
