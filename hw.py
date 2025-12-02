import sys
import base64
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QComboBox, QTextEdit, QGroupBox
)
from PyQt5.QtGui import QFont

# Crypto imports
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from Crypto.Hash import SHA1, SHA256


# ==========================================================
# DIFFIE–HELLMAN SIMPLE IMPLEMENTATION
# ==========================================================
def diffie_hellman_key_exchange():
    p = 23  # small prime for demo
    g = 5   # primitive root

    a = 6   # Alice private
    b = 15  # Bob private

    A = pow(g, a, p)
    B = pow(g, b, p)

    shared_key1 = pow(B, a, p)
    shared_key2 = pow(A, b, p)

    return p, g, a, b, A, B, shared_key1, shared_key2


# ==========================================================
# GUI APP
# ==========================================================
class CryptoApp(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Cryptography Tool – AES | DES | RSA | SHA | DH")
        self.resize(650, 750)

        # --- FONT ---
        font = QFont("Segoe UI", 10)

        # ------------------------------------------------------
        # INPUT GROUP
        # ------------------------------------------------------
        group_input = QGroupBox("Input")
        group_input.setFont(font)

        self.input_plain = QLineEdit()
        self.input_plain.setPlaceholderText("Enter plaintext here...")

        self.combo_algo = QComboBox()
        self.combo_algo.addItems([
            "AES", "DES", "RSA",
            "SHA-256", "SHA-1",
            "Diffie-Hellman"
        ])

        layout_input = QVBoxLayout()
        layout_input.addWidget(QLabel("Plaintext:"))
        layout_input.addWidget(self.input_plain)
        layout_input.addWidget(QLabel("Select Algorithm:"))
        layout_input.addWidget(self.combo_algo)
        group_input.setLayout(layout_input)

        # ------------------------------------------------------
        # BUTTONS
        # ------------------------------------------------------
        self.btn_encrypt = QPushButton("Run Algorithm")
        self.btn_encrypt.clicked.connect(self.run_algorithm)

        # ------------------------------------------------------
        # OUTPUT: Cipher
        # ------------------------------------------------------
        group_cipher = QGroupBox("Ciphertext / Output")
        group_cipher.setFont(font)

        self.output_cipher = QTextEdit()
        self.output_cipher.setReadOnly(True)

        layout_cipher = QVBoxLayout()
        layout_cipher.addWidget(self.output_cipher)
        group_cipher.setLayout(layout_cipher)

        # ------------------------------------------------------
        # OUTPUT: Decrypted Text
        # ------------------------------------------------------
        group_plain = QGroupBox("Decrypted Plaintext")
        group_plain.setFont(font)

        self.output_plain = QTextEdit()
        self.output_plain.setReadOnly(True)

        layout_plain = QVBoxLayout()
        layout_plain.addWidget(self.output_plain)
        group_plain.setLayout(layout_plain)

        # ------------------------------------------------------
        # EXPLANATION BOX
        # ------------------------------------------------------
        group_exp = QGroupBox("Explanation")
        group_exp.setFont(font)

        self.output_explain = QTextEdit()
        self.output_explain.setReadOnly(True)

        layout_exp = QVBoxLayout()
        layout_exp.addWidget(self.output_explain)
        group_exp.setLayout(layout_exp)

        # ------------------------------------------------------
        # MAIN LAYOUT
        # ------------------------------------------------------
        layout = QVBoxLayout()
        layout.addWidget(group_input)
        layout.addWidget(self.btn_encrypt)
        layout.addWidget(group_cipher)
        layout.addWidget(group_plain)
        layout.addWidget(group_exp)

        self.setLayout(layout)

        # Styling
        self.setStyleSheet("""
        QWidget {
            background: #f0f2f5;
        }
        QGroupBox {
            background: white;
            border-radius: 10px;
            margin-top: 10px;
            padding: 15px;
            border: 2px solid #0078d7;
        }
        QPushButton {
            padding: 10px;
            background-color: #0078d7;
            color: white;
            border-radius: 8px;
            font-size: 14px;
        }
        QPushButton:hover {
            background-color: #005a9e;
        }
        """)

    # ======================================================
    # MAIN ALGORITHM HANDLER
    # ======================================================
    def run_algorithm(self):
        algo = self.combo_algo.currentText()
        text = self.input_plain.text()

        if algo in ["SHA-256", "SHA-1", "Diffie-Hellman"]:
            pass  # These don't need plaintext decrypt
        else:
            if not text:
                self.output_cipher.setText("Please enter plaintext.")
                return

        if algo == "AES":
            self.do_aes(text)
        elif algo == "DES":
            self.do_des(text)
        elif algo == "RSA":
            self.do_rsa(text)
        elif algo == "SHA-256":
            self.do_sha256(text)
        elif algo == "SHA-1":
            self.do_sha1(text)
        elif algo == "Diffie-Hellman":
            self.do_dh()

    # ======================================================
    # AES
    # ======================================================
    def do_aes(self, text):
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv

        ct = cipher.encrypt(pad(text.encode(), AES.block_size))
        cipher_b64 = base64.b64encode(iv + ct).decode()

        # decrypt
        raw = base64.b64decode(cipher_b64)
        iv2 = raw[:16]
        ct2 = raw[16:]
        cipher_dec = AES.new(key, AES.MODE_CBC, iv2)
        pt = unpad(cipher_dec.decrypt(ct2), AES.block_size).decode()

        self.output_cipher.setText(cipher_b64)
        self.output_plain.setText(pt)

        self.output_explain.setText(
            f"AES Explanation:\n"
            f"• Symmetric encryption (same key for enc/dec)\n"
            f"• Key size: 128 bits\n"
            f"• Mode: CBC\n"
            f"• IV: {base64.b64encode(iv).decode()}\n"
            f"• Ciphertext is IV + encrypted blocks encoded in Base64"
        )

    # ======================================================
    # DES
    # ======================================================
    def do_des(self, text):
        key = get_random_bytes(8)
        cipher = DES.new(key, DES.MODE_CBC)
        iv = cipher.iv

        ct = cipher.encrypt(pad(text.encode(), DES.block_size))
        cipher_b64 = base64.b64encode(iv + ct).decode()

        raw = base64.b64decode(cipher_b64)
        iv2 = raw[:8]
        ct2 = raw[8:]
        cipher_dec = DES.new(key, DES.MODE_CBC, iv2)
        pt = unpad(cipher_dec.decrypt(ct2), DES.block_size).decode()

        self.output_cipher.setText(cipher_b64)
        self.output_plain.setText(pt)

        self.output_explain.setText(
            f"DES Explanation:\n"
            f"• Symmetric encryption (same key for enc/dec)\n"
            f"• Key size: 64 bits (8 bytes)\n"
            f"• Mode: CBC\n"
            f"• IV: {base64.b64encode(iv).decode()}"
        )

    # ======================================================
    # RSA
    # ======================================================
    def do_rsa(self, text):
        key = RSA.generate(2048)
        public = key.publickey()
        cipher = PKCS1_OAEP.new(public)

        ct = cipher.encrypt(text.encode())
        cipher_b64 = base64.b64encode(ct).decode()

        cipher_dec = PKCS1_OAEP.new(key)
        pt = cipher_dec.decrypt(base64.b64decode(cipher_b64)).decode()

        self.output_cipher.setText(cipher_b64)
        self.output_plain.setText(pt)

        self.output_explain.setText(
            f"RSA Explanation:\n"
            f"• Asymmetric encryption (public key encrypts, private key decrypts)\n"
            f"• Key size: 2048 bits\n"
            f"• RSA uses mathematical exponentiation mod n\n"
            f"• Uses OAEP padding for security"
        )

    # ======================================================
    # SHA-256
    # ======================================================
    def do_sha256(self, text):
        h = SHA256.new(text.encode()).hexdigest()

        self.output_cipher.setText(h)
        self.output_plain.setText("Hashing has no decryption.")
        self.output_explain.setText(
            "SHA-256 Explanation:\n"
            "• One-way hashing algorithm\n"
            "• Produces 256-bit digest\n"
            "• Cannot be decrypted"
        )

    # ======================================================
    # SHA-1
    # ======================================================
    def do_sha1(self, text):
        h = SHA1.new(text.encode()).hexdigest()

        self.output_cipher.setText(h)
        self.output_plain.setText("Hashing has no decryption.")
        self.output_explain.setText(
            "SHA-1 Explanation:\n"
            "• One-way hashing algorithm\n"
            "• Produces 160-bit digest\n"
            "• Considered weak but educational"
        )

    # ======================================================
    # DIFFIE–HELLMAN
    # ======================================================
    def do_dh(self):
        p, g, a, b, A, B, k1, k2 = diffie_hellman_key_exchange()

        self.output_cipher.setText(
            f"Alice sends A = {A}\nBob sends B = {B}"
        )
        self.output_plain.setText(
            f"Shared key (Alice): {k1}\nShared key (Bob): {k2}"
        )

        self.output_explain.setText(
            "Diffie–Hellman Explanation:\n"
            "• Not encryption — key exchange protocol\n"
            f"• Public prime p = {p}\n"
            f"• Generator g = {g}\n"
            f"• Alice private a = {a}\n"
            f"• Bob private b = {b}\n"
            "• Shared key = g^(ab) mod p"
        )


# ==========================================================
# RUN APP
# ==========================================================
app = QApplication(sys.argv)
window = CryptoApp()
window.show()
sys.exit(app.exec_())
