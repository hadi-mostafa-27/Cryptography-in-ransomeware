from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from .utils import to_base64, from_base64

RSA_KEY_SIZE = 2048


def generate_rsa_keys():
    """
    Generate an RSA-2048 key pair.

    Returns:
        (private_key_pem_bytes, public_key_pem_bytes)
    """
    key = RSA.generate(RSA_KEY_SIZE)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def rsa_encrypt_key(sym_key: bytes, public_key_bytes: bytes) -> str:
    """
    Encrypt a symmetric key (e.g. AES key) using RSA-OAEP.
    Returns base64-encoded ciphertext string.
    """
    pub = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(pub)
    enc = cipher.encrypt(sym_key)
    return to_base64(enc)


def rsa_decrypt_key(enc_key_b64: str, private_key_bytes: bytes) -> bytes:
    """
    Decrypt a base64-encoded RSA-OAEP ciphertext and return the symmetric key.
    """
    priv = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(priv)
    return cipher.decrypt(from_base64(enc_key_b64))
