# -*- mode: python ; coding: utf-8 -*-

import re
import importlib.util
from pathlib import Path

root = Path(SPECPATH)
__version__ = re.search(
    r'^VERSION = "([^"]+)"',
    (root / 'peepdf' / 'PDFCore.py').read_text(encoding='utf-8'),
    re.MULTILINE,
).group(1)

datas = []
excludes = []
stpyv8 = importlib.util.find_spec('STPyV8')
icu = Path(stpyv8.origin).parent / 'stpyv8-icu' / 'icudtl.dat' if stpyv8 else None
if icu is not None and icu.exists():
    datas.append((str(icu), 'stpyv8-icu'))
else:
    excludes.append('STPyV8')

a = Analysis(
    [str(root / 'peepdf' / 'peepdf.py')],
    pathex=[str(root)],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=f'peepdf-{__version__}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=['_STPyV8*.pyd'],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=str(root / 'version.txt'),
    icon=[str(root / 'ds.ico')],
)
