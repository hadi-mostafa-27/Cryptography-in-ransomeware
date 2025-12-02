#Ahmad Ajamy
#202302989
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pad(data, block_size=16):
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def aes_encrypt(plaintext):
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode())
    ciphertext = cipher.encrypt(padded)
    return key, iv + ciphertext

def aes_decrypt(key, combined):
    iv = combined[:16]
    ciphertext = combined[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    return unpad(decrypted_padded).decode()

def main():
    plaintext = input("Enter plaintext: ")
    key, combined = aes_encrypt(plaintext)
    print("\nCiphertext:")
    print(combined.hex())
    decrypted = aes_decrypt(key, combined)
    print("\nDecrypted plaintext:")
    print(decrypted)

if __name__ == "__main__":
    main()
