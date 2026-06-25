"""Pluggable signing: ML-DSA-87 (liboqs) with Ed25519 fallback."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

AlgorithmName = Literal["ML-DSA-87", "ML-DSA-65", "Ed25519"]


@dataclass(frozen=True)
class KeyPair:
    private_key: bytes
    public_key_b64: str


@dataclass(frozen=True)
class Algorithm:
    name: AlgorithmName

    def generate_keypair(self) -> KeyPair:
        if self.name == "Ed25519":
            private = Ed25519PrivateKey.generate()
            public = private.public_key()
            private_bytes = private.private_bytes(
                encoding=Encoding.Raw,
                format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption(),
            )
            public_bytes = public.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
            return KeyPair(private_key=private_bytes, public_key_b64=_b64(public_bytes))

        try:
            import oqs
        except ImportError as exc:
            raise RuntimeError(f"{self.name} requires liboqs-python (pip install qcap[pqc])") from exc

        with oqs.Signature(self.name) as signer:
            public_key, private_key = _pqc_generate_keypair(signer)
            return KeyPair(private_key=private_key, public_key_b64=_b64(public_key))

    def sign(self, private_key: bytes, message: bytes) -> str:
        if self.name == "Ed25519":
            private = Ed25519PrivateKey.from_private_bytes(private_key)
            return _b64(private.sign(message))

        import oqs

        return _b64(_pqc_sign(self.name, private_key, message))

    def verify(self, public_key_b64: str, message: bytes, signature_b64: str) -> bool:
        public_key = _unb64(public_key_b64)
        signature = _unb64(signature_b64)

        if self.name == "Ed25519":
            try:
                Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
                return True
            except InvalidSignature:
                return False

        import oqs

        with oqs.Signature(self.name) as signer:
            return signer.verify(message, signature, public_key)


def _pqc_generate_keypair(signer: object) -> tuple[bytes, bytes]:
    """Support liboqs-python (returns public key only) and legacy oqs-python (tuple)."""
    result = signer.generate_keypair()
    if isinstance(result, tuple):
        public_key, private_key = result
        return public_key, private_key
    return result, signer.export_secret_key()


def _pqc_sign(algorithm: str, private_key: bytes, message: bytes) -> bytes:
    import oqs

    try:
        with oqs.Signature(algorithm, secret_key=private_key) as signer:
            return signer.sign(message)
    except TypeError:
        with oqs.Signature(algorithm) as signer:
            return signer.sign(message, private_key)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def resolve_algorithm(name: AlgorithmName | str | Algorithm | None = None) -> Algorithm:
    if isinstance(name, Algorithm):
        return name
    if name is None:
        if _oqs_available():
            return Algorithm("ML-DSA-87")
        return Algorithm("Ed25519")

    normalized = str(name).strip()
    aliases = {
        "ml-dsa-87": "ML-DSA-87",
        "mldsa87": "ML-DSA-87",
        "ml-dsa-65": "ML-DSA-65",
        "mldsa65": "ML-DSA-65",
        "ed25519": "Ed25519",
        "ML-DSA-87": "ML-DSA-87",
        "ML-DSA-65": "ML-DSA-65",
        "Ed25519": "Ed25519",
    }
    canonical = aliases.get(normalized) or aliases.get(normalized.lower())
    if canonical is None:
        raise ValueError(f"unsupported algorithm: {name!r}")
    return Algorithm(canonical)  # type: ignore[arg-type]


def _oqs_available() -> bool:
    try:
        import oqs

        with oqs.Signature("ML-DSA-87"):
            return True
    except Exception:
        return False


def sign_bytes(algo: Algorithm, private_key: bytes, message: bytes) -> str:
    return algo.sign(private_key, message)


def verify_bytes(algo: Algorithm, public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    return algo.verify(public_key_b64, message, signature_b64)
