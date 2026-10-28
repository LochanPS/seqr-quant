# PyInstaller spec — build a single static-ish binary of the agent (PRD 15 Slice 3).
#   pip install pyinstaller
#   pyinstaller --clean --noconfirm seqr-agent.spec
#   dist/seqr-agent run --config agent.yaml
#
# The plugins are imported dynamically via the REGISTRY, so they are listed as hiddenimports.
# PyKCS11 is intentionally NOT bundled (optional, host-specific HSM lib).

block_cipher = None

a = Analysis(
    ["seqr_agent/cli.py"],
    pathex=["."],
    binaries=[],
    datas=[],
    hiddenimports=[
        "seqr_agent.plugins.tls_probe",
        "seqr_agent.plugins.cert_store",
        "seqr_agent.plugins.proxy_conf",
        "seqr_agent.plugins.pkcs11",
        "yaml",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=["PyKCS11"],
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz, a.scripts, a.binaries, a.zipfiles, a.datas, [],
    name="seqr-agent",
    debug=False, strip=False, upx=False, console=True,
)
