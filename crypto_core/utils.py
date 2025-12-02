from Crypto.Random import get_random_bytes
import base64

# Common crypto constants
AES_KEY_SIZE = 32        # 256 bits
AES_BLOCK_SIZE = 16      # AES block size in bytes


def random_bytes(n: int) -> bytes:
    """Return n cryptographically secure random bytes."""
    return get_random_bytes(n)


def to_hex(data: bytes) -> str:
    return data.hex()


def from_hex(h: str) -> bytes:
    return bytes.fromhex(h)


def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def from_base64(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))
