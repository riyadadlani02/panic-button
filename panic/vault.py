"""Split-key vault: opening needs both the passphrase and the key file."""
import base64
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_OPEN_FAILED = "Could not open the vault: wrong passphrase, wrong key file, or damaged file."


class VaultError(Exception):
    pass


def new_keyfile() -> bytes:
    return secrets.token_bytes(32)


def _derive(passphrase: str, keyfile: bytes, salt: bytes) -> bytes:
    stretched = hash_secret_raw(
        passphrase.encode(), salt, time_cost=3, memory_cost=65536,
        parallelism=4, hash_len=32, type=Type.ID,
    )
    # Key file is mixed in after the KDF so neither piece alone yields the key.
    return HKDF(hashes.SHA256(), 32, None, b"panic-vault-v1").derive(stretched + keyfile)


def save(path: Path, data: dict, passphrase: str, keyfile: bytes) -> None:
    data["version"] = data.get("version", 0) + 1
    data["saved_at"] = datetime.now(timezone.utc).isoformat()
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    header = json.dumps({
        "format": 1,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
    }).encode()
    body = ChaCha20Poly1305(_derive(passphrase, keyfile, salt)).encrypt(
        nonce, json.dumps(data).encode(), header)
    path = Path(path)
    # mkstemp creates 0o600; same-directory temp keeps os.replace atomic.
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(header + b"\n" + body)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def load(path: Path, passphrase: str, keyfile: bytes) -> dict:
    try:
        header, body = Path(path).read_bytes().split(b"\n", 1)
        meta = json.loads(header)
        salt = base64.b64decode(meta["salt"], validate=True)
        nonce = base64.b64decode(meta["nonce"], validate=True)
        key = _derive(passphrase, keyfile, salt)
        return json.loads(ChaCha20Poly1305(key).decrypt(nonce, body, header))
    except Exception as e:
        raise VaultError(_OPEN_FAILED) from e
