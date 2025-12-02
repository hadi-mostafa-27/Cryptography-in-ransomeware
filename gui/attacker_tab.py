import os
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QTextEdit,
    QGroupBox, QSizePolicy, QSpacerItem
)

from crypto_core.hybrid import create_keys, encrypt_folder
from file_ops.file_manager import create_backup


class AttackerTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.victim_folder_path = None
        self.aes_key = None
        self.private_key = None
        self.public_key = None
        self.encrypted_aes_key_b64 = None

        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(14)

        info_label = QLabel(
            "Simulates attacker workflow: Hybrid encryption using AES-256 (CBC) + RSA-2048."
        )
        info_label.setObjectName("SectionInfoLabel")
        layout.addWidget(info_label)

        # ROW 1
        row1 = QHBoxLayout()
        row1.setSpacing(14)

        # Victim folder group
        folder_box = QGroupBox("1. Victim Folder")
        fb = QVBoxLayout()

        self.folder_label = QLabel("Victim folder: [not selected]")
        self.folder_label.setObjectName("PathLabel")

        btn_folder = QPushButton("Select Victim Folder")
        btn_folder.setObjectName("PrimaryButton")
        btn_folder.clicked.connect(self.choose_victim_folder)

        fb.addWidget(self.folder_label)
        fb.addWidget(btn_folder)
        folder_box.setLayout(fb)

        # Key generation group
        key_box = QGroupBox("2. Key Generation (AES-256 + RSA-2048)")
        kb = QVBoxLayout()

        self.keys_info_label = QLabel("Keys status: not generated")
        self.keys_info_label.setObjectName("StatusLabel")

        btn_keys = QPushButton("Generate Keys")
        btn_keys.setObjectName("AccentButton")
        btn_keys.clicked.connect(self.generate_keys_clicked)

        kb.addWidget(self.keys_info_label)
        kb.addWidget(btn_keys)
        key_box.setLayout(kb)

        row1.addWidget(folder_box)
        row1.addWidget(key_box)
        layout.addLayout(row1)

        # ROW 2
        row2 = QHBoxLayout()
        row2.setSpacing(14)

        # Encryption area
        encrypt_box = QGroupBox("3. Encryption Process")
        eb = QVBoxLayout()

        btn_encrypt = QPushButton("Run Encryption")
        btn_encrypt.setObjectName("DangerButton")
        btn_encrypt.clicked.connect(self.encrypt_files_clicked)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setObjectName("LogTextEdit")

        eb.addWidget(btn_encrypt)
        eb.addWidget(self.log_view)
        encrypt_box.setLayout(eb)

        # Ransom + key info
        ransom_box = QGroupBox("4. Ransom Note + RSA Private Key")
        rb = QVBoxLayout()

        ransom_label = QLabel("Generated ransom note (educational):")
        ransom_label.setObjectName("SubSectionLabel")

        self.ransom_note_view = QTextEdit()
        self.ransom_note_view.setReadOnly(True)
        self.ransom_note_view.setObjectName("MonospaceTextEdit")

        key_label = QLabel("RSA Private Key (Visible only in LAB demo):")
        key_label.setObjectName("SubSectionLabel")

        self.private_key_view = QTextEdit()
        self.private_key_view.setReadOnly(True)
        self.private_key_view.setObjectName("MonospaceTextEdit")

        rb.addWidget(ransom_label)
        rb.addWidget(self.ransom_note_view)
        rb.addWidget(key_label)
        rb.addWidget(self.private_key_view)
        ransom_box.setLayout(rb)

        row2.addWidget(encrypt_box)
        row2.addWidget(ransom_box)
        layout.addLayout(row2)

        layout.addItem(QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))
        self.setLayout(layout)

    # ---------------- Event Handlers ----------------

    def choose_victim_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Select Victim Folder", os.path.abspath("data")
        )
        if folder:
            self.victim_folder_path = folder
            self.folder_label.setText(f"Victim folder: {folder}")
            self.log_view.append(f"[INFO] Selected: {folder}")

    def generate_keys_clicked(self):
        self.log_view.append("[INFO] Generating AES-256 key + RSA-2048 keys...")
        self.aes_key, self.private_key, self.public_key = create_keys()

        pem = self.private_key.decode(errors="ignore").replace("\r", "")
        self.private_key_view.setPlainText(pem)

        self.keys_info_label.setText("Keys successfully generated.")
        self.log_view.append("[OK] AES-256 key (32 bytes)")
        self.log_view.append("[OK] RSA keypair (2048-bit)")

    def encrypt_files_clicked(self):
        if not self.victim_folder_path:
            self.log_view.append("[ERROR] Please select a victim folder.")
            return
        if not self.aes_key:
            self.log_view.append("[ERROR] Generate keys first.")
            return

        self.log_view.append("[INFO] Creating backup...")
        backup = create_backup(self.victim_folder_path)
        self.log_view.append(f"[OK] Backup stored at: {backup}")

        self.log_view.append("[INFO] Encrypting files using AES-256-CBC...")
        enc_files, enc_aes_key_b64 = encrypt_folder(
            self.victim_folder_path, self.aes_key, self.public_key
        )

        for f in enc_files:
            self.log_view.append(f"[ENCRYPTED] {f}")

        self.encrypted_aes_key_b64 = enc_aes_key_b64

        ransom_note = (
            "=== RANSOM NOTE (Educational) ===\n\n"
            "Your files have been encrypted using AES-256 in CBC mode.\n"
            "The AES key was encrypted using RSA-2048 (OAEP).\n\n"
            f"Encrypted AES-256 Key (Base64):\n{enc_aes_key_b64}\n\n"
            "Encrypted Files:\n" + "\n".join(enc_files) +
            f"\n\nBackup at:\n{backup}"
        )

        self.ransom_note_view.setPlainText(ransom_note)
        self.log_view.append("[DONE] Ransom note generated.")
