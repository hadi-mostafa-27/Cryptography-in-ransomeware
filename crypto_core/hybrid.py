import os

from .symmetric import generate_aes_key, encrypt_file_aes, decrypt_file_aes
from .asymmetric import generate_rsa_keys, rsa_encrypt_key, rsa_decrypt_key


def create_keys():
    """
    Create a fresh AES-256 key and an RSA-2048 keypair.

    Returns:
        (aes_key_bytes, rsa_private_key_pem_bytes, rsa_public_key_pem_bytes)
    """
    aes_key = generate_aes_key()
    private_key, public_key = generate_rsa_keys()
    return aes_key, private_key, public_key


def encrypt_folder(folder: str, aes_key: bytes, public_key: bytes):
    """
    Encrypt all normal files within a folder using AES-256-CBC.
    The same AES key is used for all files (simple, educational model).

    Returns:
        (list_of_encrypted_filenames, encrypted_aes_key_b64)
    """
    encrypted_files = []

    for filename in os.listdir(folder):
        full = os.path.join(folder, filename)

        # Skip subdirectories
        if os.path.isdir(full):
            continue

        # Skip already encrypted files
        if filename.endswith(".enc_demo"):
            continue

        out_file = full + ".enc_demo"
        encrypt_file_aes(full, out_file, aes_key)
        encrypted_files.append(filename)

    # Encrypt AES key with RSA-2048
    encrypted_aes_key = rsa_encrypt_key(aes_key, public_key)

    return encrypted_files, encrypted_aes_key


def decrypt_folder(folder: str, private_key: bytes, enc_aes_key_b64: str):
    """
    Decrypt all *.enc_demo files in the folder using the AES key
    recovered via RSA-OAEP.

    Returns:
        list of restored file paths.
    """
    aes_key = rsa_decrypt_key(enc_aes_key_b64, private_key)
    restored_files = []

    for filename in os.listdir(folder):
        if not filename.endswith(".enc_demo"):
            continue

        infile = os.path.join(folder, filename)
        outfile = infile.replace(".enc_demo", "_restored")
        decrypt_file_aes(infile, outfile, aes_key)
        restored_files.append(outfile)

    return restored_files
