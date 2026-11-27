"""The vault passphrase in the macOS Keychain: service `panic-button`, account = the vault's absolute path."""
from pathlib import Path

SERVICE = "panic-button"


class KeychainError(Exception):
    pass


def _backend(backend):
    if backend is not None:
        return backend
    try:
        import keyring
    except ImportError:
        return None
    return keyring


def _account(vault) -> str:
    return str(Path(vault).expanduser().absolute())


def get(vault, backend=None) -> str | None:
    kr = _backend(backend)
    return kr.get_password(SERVICE, _account(vault)) if kr else None


def set(vault, passphrase: str, backend=None) -> None:
    kr = _backend(backend)
    if kr is None:
        raise KeychainError("Saving the passphrase needs the keyring package (uv sync --group app).")
    kr.set_password(SERVICE, _account(vault), passphrase)


def delete(vault, backend=None) -> None:
    kr = _backend(backend)
    if kr and kr.get_password(SERVICE, _account(vault)) is not None:
        kr.delete_password(SERVICE, _account(vault))
