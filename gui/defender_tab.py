import os
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QTextEdit,
    QLineEdit, QGroupBox, QSizePolicy, QSpacerItem
)

from crypto_core.hybrid import decrypt_folder
from file_ops.file_manager import restore_backup, list_encrypted_files


class DefenderTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.victim_folder_path = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(14)

        info_label = QLabel(
            "Simulates defender recovery: RSA decrypts AES-256 key, then files are restored. Backup option included."
        )
        info_label.setObjectName("SectionInfoLabel")
        layout.addWidget(info_label)

        # ROW 1
        row1 = QHBoxLayout()
        row1.setSpacing(14)

        folder_box = QGroupBox("1. Encrypted Folder")
        fb = QVBoxLayout()

        self.folder_label = QLabel("Encrypted folder: [not selected]")
        self.folder_label.setObjectName("PathLabel")

        btn_folder = QPushButton("Select Folder")
        btn_folder.setObjectName("PrimaryButton")
        btn_folder.clicked.connect(self.choose_folder)

        fb.addWidget(self.folder_label)
        fb.addWidget(btn_folder)
        folder_box.setLayout(fb)

        key_box = QGroupBox("2. Keys for Decryption")
        kb = QVBoxLayout()

        enc_key_label = QLabel("Encrypted AES Key (Base64):")
        enc_key_label.setObjectName("SubSectionLabel")

        self.enc_key_input = QLineEdit()
        self.enc_key_input.setObjectName("InputLineEdit")
        self.enc_key_input.setPlaceholderText("Paste encrypted AES-256 key (Base64)")

        priv_label = QLabel("RSA Private Key (PEM):")
        priv_label.setObjectName("SubSectionLabel")

        self.private_key_text = QTextEdit()
        self.private_key_text.setObjectName("MonospaceTextEdit")
        self.private_key_text.setPlaceholderText("Paste RSA PRIVATE KEY (PEM)")

        kb.addWidget(enc_key_label)
        kb.addWidget(self.enc_key_input)
        kb.addWidget(priv_label)
        kb.addWidget(self.private_key_text)
        key_box.setLayout(kb)

        row1.addWidget(folder_box)
        row1.addWidget(key_box)
        layout.addLayout(row1)

        # ROW 2
        row2 = QHBoxLayout()
        row2.setSpacing(14)

        action_box = QGroupBox("3. Actions")
        ab = QVBoxLayout()

        btn_decrypt = QPushButton("Decrypt Files")
        btn_decrypt.setObjectName("AccentButton")
        btn_decrypt.clicked.connect(self.decrypt_files_clicked)

        btn_backup = QPushButton("Restore Backup")
        btn_backup.setObjectName("SecondaryButton")
        btn_backup.clicked.connect(self.restore_backup_clicked)

        ab.addWidget(btn_decrypt)
        ab.addWidget(btn_backup)
        ab.addStretch(1)
        action_box.setLayout(ab)

        log_box = QGroupBox("4. Logs")
        lb = QVBoxLayout()

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setObjectName("LogTextEdit")

        lb.addWidget(self.log_view)
        log_box.setLayout(lb)

        row2.addWidget(action_box)
        row2.addWidget(log_box)
        layout.addLayout(row2)

        layout.addItem(QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))
        self.setLayout(layout)

    # ---------------- Handlers ----------------

    def choose_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Select Encrypted Folder", os.path.abspath("data")
        )
        if folder:
            self.victim_folder_path = folder
            self.folder_label.setText(folder)

            enc = list_encrypted_files(folder)
            if enc:
                self.log_view.setPlainText("Encrypted files:\n" + "\n".join(enc))
            else:
                self.log_view.setPlainText("No encrypted files found.")

    def decrypt_files_clicked(self):
        if not self.victim_folder_path:
            self.log_view.setPlainText("Select folder first.")
            return

        enc_key = self.enc_key_input.text().strip()
        pem_raw = self.private_key_text.toPlainText().strip()

        if not enc_key:
            self.log_view.setPlainText("Missing encrypted AES key.")
            return

        if "BEGIN" not in pem_raw:
            self.log_view.setPlainText("Invalid RSA key format.")
            return

        # Normalize PEM formatting
        pem = "\n".join(line.strip() for line in pem_raw.splitlines())
        private_key = pem.encode("utf-8")

        try:
            self.log_view.append("[INFO] Recovering AES-256 key via RSA-OAEP...")
            restored = decrypt_folder(self.victim_folder_path, private_key, enc_key)

            if restored:
                self.log_view.append("[OK] Files restored:\n" + "\n".join(restored))
            else:
                self.log_view.append("[WARN] No encrypted files found.")
        except Exception as e:
            self.log_view.append("[ERROR] " + str(e))

    def restore_backup_clicked(self):
        if restore_backup(self.victim_folder_path):
            self.log_view.setPlainText("[OK] Backup restored successfully.")
        else:
            self.log_view.setPlainText("[ERROR] Backup folder not found.")
