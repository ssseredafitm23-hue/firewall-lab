import os
import secrets
import shutil
from pathlib import Path

os.umask(0o077)

config = Path("config")
config.mkdir(mode=0o700, exist_ok=True)
Path("logs").mkdir(mode=0o700, exist_ok=True)
Path("outputs").mkdir(exist_ok=True)

runtime = config / "runtime.json"
token = config / "admin.key"

if not runtime.exists():
    shutil.copyfile("config.json", runtime)
    runtime.chmod(0o600)
    print("Runtime configuration created")
else:
    print("Runtime configuration preserved")

if not token.exists():
    with token.open("x") as f:
        f.write(secrets.token_hex(32) + "\n")
    token.chmod(0o600)
    print("Admin token created")
else:
    print("Existing admin token preserved")

print("Initialization completed")
