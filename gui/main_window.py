from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QTabWidget, QLabel, QFrame
)
from PyQt5.QtCore import Qt

from .attacker_tab import AttackerTab
from .defender_tab import DefenderTab


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Crypto-LAB | Ransomware Crypto Simulator")
        self.resize(1200, 750)

        self._apply_material_style()
        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        root_layout = QVBoxLayout()
        root_layout.setContentsMargins(24, 24, 24, 24)
        root_layout.setSpacing(18)

        # Header
        header_frame = QFrame()
        header_frame.setObjectName("HeaderFrame")
        header_layout = QVBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 20)

        title_label = QLabel("Crypto-LAB")
        title_label.setObjectName("TitleLabel")

        subtitle_label = QLabel(
            "Hybrid Encryption Ransomware Simulation • AES-256 (CBC) + RSA-2048"
        )
        subtitle_label.setObjectName("SubtitleLabel")

        header_layout.addWidget(title_label)
        header_layout.addWidget(subtitle_label)
        header_frame.setLayout(header_layout)

        # Tabs container card
        card_frame = QFrame()
        card_frame.setObjectName("CardFrame")
        card_layout = QVBoxLayout()
        card_layout.setContentsMargins(20, 20, 20, 20)
        card_layout.setSpacing(10)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("MainTabWidget")

        self.attacker_tab = AttackerTab(self)
        self.defender_tab = DefenderTab(self)

        self.tabs.addTab(self.attacker_tab, " Attacker Panel ")
        self.tabs.addTab(self.defender_tab, " Defender Panel ")

        card_layout.addWidget(self.tabs)
        card_frame.setLayout(card_layout)

        root_layout.addWidget(header_frame)
        root_layout.addWidget(card_frame)

        central.setLayout(root_layout)
        self.setCentralWidget(central)

    def _apply_material_style(self):
        self.setStyleSheet("""
        QMainWindow {
            background: #fafafa;
        }

        #HeaderFrame {
            background: transparent;
        }

        #TitleLabel {
            color: #0d47a1;
            font-size: 28px;
            font-weight: 700;
        }

        #SubtitleLabel {
            color: #546e7a;
            font-size: 13px;
            margin-top: -4px;
        }

        #CardFrame {
            background: #ffffff;
            border-radius: 18px;
            border: 1px solid #e0e0e0;
        }

        #MainTabWidget::pane {
            background: transparent;
            border: none;
        }

        #MainTabWidget QTabBar::tab {
            background: #e3f2fd;
            color: #0d47a1;
            padding: 10px 22px;
            border-radius: 10px;
            margin-right: 8px;
            font-weight: 500;
        }

        #MainTabWidget QTabBar::tab:selected {
            background: #2196f3;
            color: white;
            font-weight: 600;
        }

        #MainTabWidget QTabBar::tab:hover:!selected {
            background: #bbdefb;
        }

        QPushButton#PrimaryButton {
            background: #1e88e5;
            color: white;
            padding: 10px 16px;
            border-radius: 8px;
            font-size: 14px;
        }
        QPushButton#PrimaryButton:hover {
            background: #1565c0;
        }

        QPushButton#AccentButton {
            background: #43a047;
            color: white;
            padding: 10px 16px;
            border-radius: 8px;
            font-size: 14px;
        }
        QPushButton#AccentButton:hover {
            background: #2e7d32;
        }

        QPushButton#SecondaryButton {
            background: #eeeeee;
            color: #37474f;
            padding: 10px 16px;
            border-radius: 8px;
            font-size: 14px;
        }
        QPushButton#SecondaryButton:hover {
            background: #e0e0e0;
        }

        QPushButton#DangerButton {
            background: #e53935;
            color: white;
            padding: 10px 16px;
            border-radius: 8px;
            font-size: 14px;
        }
        QPushButton#DangerButton:hover {
            background: #b71c1c;
        }

        QGroupBox {
            border: 1px solid #e0e0e0;
            border-radius: 12px;
            margin-top: 10px;
            background: #ffffff;
            font-weight: 600;
            padding-top: 14px;
        }
        QGroupBox:title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 4px;
            color: #0d47a1;
            font-size: 14px;
        }

        QLabel#SectionInfoLabel {
            color: #37474f;
            font-size: 13px;
        }

        QLabel#PathLabel {
            color: #455a64;
            font-size: 13px;
        }

        QLabel#StatusLabel {
            color: #1b5e20;
            font-size: 13px;
            font-weight: bold;
        }

        QLabel#SubSectionLabel {
            color: #1e88e5;
            font-size: 12px;
            font-weight: 600;
        }

        QLineEdit, QTextEdit {
            background: #ffffff;
            border: 1px solid #cfd8dc;
            border-radius: 8px;
            padding: 8px;
            font-size: 13px;
        }
        QLineEdit:focus, QTextEdit:focus {
            border: 1px solid #64b5f6;
        }

        QTextEdit#MonospaceTextEdit {
            font-family: Consolas, monospace;
            font-size: 12px;
        }

        QTextEdit#LogTextEdit {
            background: #f1f8e9;
            border: 1px solid #c5e1a5;
            font-family: Consolas, monospace;
            font-size: 12px;
        }
        """)
