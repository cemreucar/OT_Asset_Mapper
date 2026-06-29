import sys
from pathlib import Path

import pandas as pd

from PySide6.QtCore import Qt, QAbstractTableModel
from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QFileDialog,
    QMessageBox,
    QWidget,
    QVBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QTabWidget,
    QTableView,
    QFrame,
    QStatusBar,
    QSplitter,
    QGroupBox,
    QScrollArea,
    QToolButton,
    QSizePolicy,
)

from connection_parser import parse_csv_path, parse_pcap_path
from subnet_utils import parse_zone_config
from asset_analyzer import (
    enrich_connections,
    infer_asset_inventory,
    build_communication_matrix,
    build_summary,
)
from report_generator import export_csv, export_excel, generate_html_report


APP_NAME = "OT Asset Mapper Desktop"


class PandasTableModel(QAbstractTableModel):
    def __init__(self, dataframe=None):
        super().__init__()
        self._df = dataframe if dataframe is not None else pd.DataFrame()

    def set_dataframe(self, dataframe):
        self.beginResetModel()
        self._df = dataframe if dataframe is not None else pd.DataFrame()
        self.endResetModel()

    def rowCount(self, parent=None):
        return len(self._df.index)

    def columnCount(self, parent=None):
        return len(self._df.columns)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        value = self._df.iloc[index.row(), index.column()]
        col_name = str(self._df.columns[index.column()])

        if role == Qt.DisplayRole:
            return "" if pd.isna(value) else str(value)

        if role == Qt.TextAlignmentRole:
            numeric_cols = {
                "risk_score",
                "destination_port",
                "talks_to_count",
                "talked_by_count",
                "connection_count",
            }

            if col_name in numeric_cols:
                return Qt.AlignCenter

            return Qt.AlignLeft | Qt.AlignVCenter

        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None

        if orientation == Qt.Horizontal:
            if section < len(self._df.columns):
                return str(self._df.columns[section]).replace("_", " ").title()

        return str(section + 1)


class MetricCard(QFrame):
    def __init__(self, title, value="0"):
        super().__init__()
        self.setObjectName("MetricCard")
        self.setMinimumHeight(84)
        self.setMaximumHeight(96)

        layout = QVBoxLayout()
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(2)

        self.title_label = QLabel(title)
        self.title_label.setObjectName("MetricTitle")

        self.value_label = QLabel(str(value))
        self.value_label.setObjectName("MetricValue")

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)

        self.setLayout(layout)

    def set_value(self, value):
        self.value_label.setText(str(value))


class CollapsibleSection(QWidget):
    def __init__(self, title, content_widget, accent="default"):
        super().__init__()

        self.content_widget = content_widget
        self.content_widget.setObjectName("CollapseContent")
        self.is_open = False

        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        self.toggle_button = QToolButton()
        self.toggle_button.setText(title)
        self.toggle_button.setCheckable(True)
        self.toggle_button.setChecked(False)
        self.toggle_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.toggle_button.setArrowType(Qt.RightArrow)
        self.toggle_button.setCursor(Qt.PointingHandCursor)
        self.toggle_button.setMinimumHeight(50)
        self.toggle_button.setMaximumHeight(54)
        self.toggle_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        if accent == "danger":
            self.toggle_button.setObjectName("DangerCollapseButton")
        else:
            self.toggle_button.setObjectName("CollapseButton")

        self.toggle_button.clicked.connect(self.toggle_content)

        self.content_widget.setVisible(False)
        self.content_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addWidget(self.toggle_button)
        layout.addWidget(self.content_widget)

    def toggle_content(self):
        self.is_open = self.toggle_button.isChecked()
        self.content_widget.setVisible(self.is_open)
        self.toggle_button.setArrowType(Qt.DownArrow if self.is_open else Qt.RightArrow)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle(APP_NAME)
        self.resize(1500, 900)
        self.setMinimumSize(1260, 760)

        self.input_path = None
        self.input_type = None

        self.asset_inventory = pd.DataFrame()
        self.communication_matrix = pd.DataFrame()
        self.enriched_connections = pd.DataFrame()
        self.summary = {}

        self.asset_model = PandasTableModel()
        self.matrix_model = PandasTableModel()
        self.evidence_model = PandasTableModel()

        self._build_menu()
        self._build_ui()
        self._apply_style()

        self.statusBar().showMessage(
            "Ready. Load a CSV, Excel, or PCAP file to start passive OT asset analysis."
        )

    def _build_menu(self):
        file_menu = self.menuBar().addMenu("File")

        load_csv_action = QAction("Load CSV / Excel", self)
        load_csv_action.triggered.connect(self.load_csv)
        file_menu.addAction(load_csv_action)

        load_pcap_action = QAction("Load PCAP / PCAPNG", self)
        load_pcap_action.triggered.connect(self.load_pcap)
        file_menu.addAction(load_pcap_action)

        file_menu.addSeparator()

        export_asset_action = QAction("Export Asset Inventory CSV", self)
        export_asset_action.triggered.connect(self.export_asset_csv)
        file_menu.addAction(export_asset_action)

        export_matrix_action = QAction("Export Communication Matrix CSV", self)
        export_matrix_action.triggered.connect(self.export_matrix_csv)
        file_menu.addAction(export_matrix_action)

        export_excel_action = QAction("Export Excel Workbook", self)
        export_excel_action.triggered.connect(self.export_excel_report)
        file_menu.addAction(export_excel_action)

        export_html_action = QAction("Export HTML Report", self)
        export_html_action.triggered.connect(self.export_html_report)
        file_menu.addAction(export_html_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        help_menu = self.menuBar().addMenu("Help")

        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def _build_ui(self):
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(12, 8, 12, 10)
        root_layout.setSpacing(8)

        header = QWidget()
        header.setObjectName("HeaderPanel")
        header.setFixedHeight(78)

        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(2)

        title = QLabel("OT Asset Mapper")
        title.setObjectName("AppTitle")
        title.setFixedHeight(40)
        title.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        subtitle = QLabel("Passive OT/ICS Asset Inventory & Communication Mapping Tool")
        subtitle.setObjectName("AppSubtitle")
        subtitle.setFixedHeight(22)
        subtitle.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)

        root_layout.addWidget(header, 0)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        left_panel = self._build_left_panel()
        right_panel = self._build_right_panel()

        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([420, 1080])
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        root_layout.addWidget(splitter, 1)

        self.setCentralWidget(root)
        self.setStatusBar(QStatusBar())

    def _build_left_panel(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setMinimumWidth(400)
        scroll.setMaximumWidth(460)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        panel = QWidget()
        panel.setObjectName("LeftPanel")
        panel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(8)
        layout.setAlignment(Qt.AlignTop)

        input_group = QGroupBox("Input Source")
        input_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        input_layout = QVBoxLayout(input_group)
        input_layout.setContentsMargins(12, 16, 12, 12)
        input_layout.setSpacing(8)

        self.file_label = QLabel("No file loaded")
        self.file_label.setWordWrap(True)
        self.file_label.setObjectName("FileLabel")
        self.file_label.setMinimumHeight(34)
        self.file_label.setMaximumHeight(52)
        self.file_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        btn_csv = QPushButton("Load CSV / Excel")
        btn_csv.clicked.connect(self.load_csv)

        btn_pcap = QPushButton("Load PCAP / PCAPNG")
        btn_pcap.clicked.connect(self.load_pcap)

        btn_analyze = QPushButton("Run Analysis")
        btn_analyze.setObjectName("PrimaryButton")
        btn_analyze.clicked.connect(self.run_analysis)

        for btn in [btn_csv, btn_pcap, btn_analyze]:
            btn.setMinimumHeight(40)
            btn.setMaximumHeight(44)
            btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        input_layout.addWidget(self.file_label)
        input_layout.addWidget(btn_csv)
        input_layout.addWidget(btn_pcap)
        input_layout.addWidget(btn_analyze)

        zone_group = QGroupBox("Network Zones")
        zone_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        zone_layout = QVBoxLayout(zone_group)
        zone_layout.setContentsMargins(12, 16, 12, 12)
        zone_layout.setSpacing(8)

        self.zone_text = QTextEdit()
        self.zone_text.setPlainText(
            "OT=10.0.0.0/8,172.16.0.0/12\n"
            "IT=192.168.0.0/16\n"
            "DMZ=\n"
            "Vendor="
        )
        self.zone_text.setMinimumHeight(95)
        self.zone_text.setMaximumHeight(110)

        zone_hint = QLabel("Define zones with CIDR notation.\nExample: OT=10.10.0.0/16")
        zone_hint.setWordWrap(True)
        zone_hint.setObjectName("HintText")

        zone_layout.addWidget(self.zone_text)
        zone_layout.addWidget(zone_hint)

        protocol_content = QFrame()
        protocol_content.setObjectName("CollapseContentFrame")
        protocol_content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        protocol_layout = QVBoxLayout(protocol_content)
        protocol_layout.setContentsMargins(14, 10, 14, 12)
        protocol_layout.setSpacing(6)

        protocol_label = QLabel(
            "Industrial protocols:\n"
            "• 502 Modbus TCP\n"
            "• 102 Siemens S7\n"
            "• 44818 EtherNet/IP\n"
            "• 20000 DNP3\n"
            "• 4840 OPC UA\n"
            "• 47808 BACnet\n"
            "• 2404 IEC 104"
        )
        protocol_label.setWordWrap(True)
        protocol_label.setObjectName("InfoText")
        protocol_layout.addWidget(protocol_label)

        protocol_section = CollapsibleSection("Protocol Intelligence", protocol_content)

        risky_content = QFrame()
        risky_content.setObjectName("CollapseContentFrame")
        risky_content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        risky_layout = QVBoxLayout(risky_content)
        risky_layout.setContentsMargins(14, 10, 14, 12)
        risky_layout.setSpacing(6)

        risky_label = QLabel(
            "Remote/admin or insecure services:\n"
            "• 3389 RDP\n"
            "• 445 SMB\n"
            "• 23 Telnet\n"
            "• 21 FTP\n"
            "• 5900 VNC\n"
            "• 22 SSH"
        )
        risky_label.setWordWrap(True)
        risky_label.setObjectName("InfoText")
        risky_layout.addWidget(risky_label)

        risky_section = CollapsibleSection("Risky Services", risky_content, accent="danger")

        export_content = QFrame()
        export_content.setObjectName("CollapseContentFrame")
        export_content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        export_layout = QVBoxLayout(export_content)
        export_layout.setContentsMargins(14, 10, 14, 12)
        export_layout.setSpacing(8)

        btn_export_asset = QPushButton("Export Asset Inventory CSV")
        btn_export_asset.clicked.connect(self.export_asset_csv)

        btn_export_matrix = QPushButton("Export Communication Matrix CSV")
        btn_export_matrix.clicked.connect(self.export_matrix_csv)

        btn_export_excel = QPushButton("Export Excel Workbook")
        btn_export_excel.clicked.connect(self.export_excel_report)

        btn_export_html = QPushButton("Export HTML Report")
        btn_export_html.clicked.connect(self.export_html_report)

        for btn in [
            btn_export_asset,
            btn_export_matrix,
            btn_export_excel,
            btn_export_html,
        ]:
            btn.setMinimumHeight(38)
            btn.setMaximumHeight(42)
            btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        export_layout.addWidget(btn_export_asset)
        export_layout.addWidget(btn_export_matrix)
        export_layout.addWidget(btn_export_excel)
        export_layout.addWidget(btn_export_html)

        export_section = CollapsibleSection("Export", export_content)

        for section in [protocol_section, risky_section, export_section]:
            section.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        layout.addWidget(input_group)
        layout.addWidget(zone_group)
        layout.addWidget(protocol_section)
        layout.addWidget(risky_section)
        layout.addWidget(export_section)
        layout.addStretch(1)

        scroll.setWidget(panel)
        return scroll

    def _build_right_panel(self):
        panel = QWidget()
        panel.setObjectName("RightPanel")

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(6, 0, 0, 0)
        layout.setSpacing(8)
        layout.setAlignment(Qt.AlignTop)

        metrics_layout = QGridLayout()
        metrics_layout.setContentsMargins(0, 0, 0, 0)
        metrics_layout.setHorizontalSpacing(10)
        metrics_layout.setVerticalSpacing(10)

        self.metric_assets = MetricCard("Assets")
        self.metric_ot_assets = MetricCard("OT Assets")
        self.metric_high = MetricCard("High-Risk Assets")
        self.metric_ot_flows = MetricCard("OT Protocol Flows")
        self.metric_remote = MetricCard("Remote Access → OT")
        self.metric_it_ot = MetricCard("IT → OT")

        cards = [
            self.metric_assets,
            self.metric_ot_assets,
            self.metric_high,
            self.metric_ot_flows,
            self.metric_remote,
            self.metric_it_ot,
        ]

        for i, card in enumerate(cards):
            metrics_layout.addWidget(card, i // 3, i % 3)

        layout.addLayout(metrics_layout, 0)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("MainTabs")

        self.asset_table = QTableView()
        self.asset_table.setModel(self.asset_model)
        self.asset_table.setSortingEnabled(True)
        self.asset_table.setAlternatingRowColors(True)

        self.matrix_table = QTableView()
        self.matrix_table.setModel(self.matrix_model)
        self.matrix_table.setSortingEnabled(True)
        self.matrix_table.setAlternatingRowColors(True)

        self.evidence_table = QTableView()
        self.evidence_table.setModel(self.evidence_model)
        self.evidence_table.setSortingEnabled(True)
        self.evidence_table.setAlternatingRowColors(True)

        self.summary_box = QTextEdit()
        self.summary_box.setReadOnly(True)
        self.summary_box.setPlainText(
            "Load a CSV, Excel, or PCAP file, define network zones, and run analysis.\n\n"
            "The tool will generate:\n"
            "• Asset inventory\n"
            "• Communication matrix\n"
            "• Connection evidence\n"
            "• Risk summary\n"
            "• CSV, Excel, and HTML reports"
        )

        self.tabs.addTab(self.summary_box, "Analyst Summary")
        self.tabs.addTab(self.asset_table, "Asset Inventory")
        self.tabs.addTab(self.matrix_table, "Communication Matrix")
        self.tabs.addTab(self.evidence_table, "Connection Evidence")

        layout.addWidget(self.tabs, 1)
        return panel

    def _apply_style(self):
        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #0f172a;
            }

            QWidget {
                font-family: Segoe UI, Arial;
                font-size: 10.5pt;
                color: #e5e7eb;
                background-color: #0f172a;
            }

            QMenuBar, QMenu {
                background-color: #111827;
                color: #e5e7eb;
            }

            QMenuBar::item:selected, QMenu::item:selected {
                background-color: #1f2937;
            }

            #HeaderPanel {
                background-color: #0f172a;
            }

            #AppTitle {
                font-size: 23pt;
                font-weight: 700;
                color: #f9fafb;
                margin: 0;
                padding: 0;
            }

            #AppSubtitle {
                font-size: 10.5pt;
                color: #94a3b8;
                margin: 0;
                padding: 0;
            }

            QGroupBox {
                border: 1px solid #334155;
                border-radius: 10px;
                margin-top: 10px;
                padding-top: 14px;
                font-weight: 600;
                color: #f8fafc;
                background-color: #0b1324;
            }

            QGroupBox::title {
                subcontrol-origin: margin;
                left: 14px;
                padding: 0 6px;
                background-color: #0f172a;
            }

            QPushButton {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 8px 10px;
                color: #f8fafc;
                font-weight: 500;
            }

            QPushButton:hover {
                background-color: #334155;
            }

            #PrimaryButton {
                background-color: #2563eb;
                border: 1px solid #3b82f6;
                font-weight: 700;
            }

            #PrimaryButton:hover {
                background-color: #1d4ed8;
            }

            QToolButton#CollapseButton {
                background-color: #111827;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 12px 14px;
                color: #e5e7eb;
                font-size: 10.5pt;
                font-weight: 600;
                text-align: left;
            }

            QToolButton#CollapseButton:hover {
                background-color: #172033;
                border: 1px solid #475569;
            }

            QToolButton#DangerCollapseButton {
                background-color: #111827;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 12px 14px;
                color: #fca5a5;
                font-size: 10.5pt;
                font-weight: 600;
                text-align: left;
            }

            QToolButton#DangerCollapseButton:hover {
                background-color: #172033;
                border: 1px solid #7f1d1d;
            }

            #CollapseContentFrame {
                background-color: #0b1324;
                border: 1px solid #334155;
                border-radius: 10px;
            }

            QTextEdit {
                background-color: #0b1324;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 8px;
                color: #e5e7eb;
            }

            QTableView {
                background-color: #0b1324;
                alternate-background-color: #111827;
                gridline-color: #334155;
                color: #e5e7eb;
                border: 1px solid #334155;
                border-radius: 8px;
                selection-background-color: #2563eb;
            }

            QHeaderView::section {
                background-color: #1f2937;
                color: #f8fafc;
                padding: 7px;
                border: 1px solid #334155;
                font-weight: 600;
            }

            QTabWidget::pane {
                border: 1px solid #334155;
                border-radius: 8px;
                background-color: #0b1324;
            }

            QTabBar::tab {
                background: #1f2937;
                color: #d1d5db;
                padding: 9px 14px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                min-width: 125px;
            }

            QTabBar::tab:selected {
                background: #2563eb;
                color: #ffffff;
            }

            #MetricCard {
                background-color: #0b1324;
                border: 1px solid #334155;
                border-radius: 10px;
                min-height: 84px;
                max-height: 96px;
            }

            #MetricTitle {
                color: #94a3b8;
                font-size: 9.5pt;
            }

            #MetricValue {
                color: #f8fafc;
                font-size: 19pt;
                font-weight: 700;
            }

            #FileLabel, #HintText {
                color: #94a3b8;
            }

            #InfoText {
                color: #e5e7eb;
                line-height: 1.35;
            }

            QScrollArea {
                border: none;
            }

            QScrollBar:vertical {
                background: #0f172a;
                width: 10px;
                margin: 0;
            }

            QScrollBar::handle:vertical {
                background: #475569;
                border-radius: 4px;
                min-height: 30px;
            }

            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                height: 0;
            }
            """
        )

    def load_csv(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open CSV or Excel connection file",
            "",
            "Data Files (*.csv *.xlsx *.xls);;CSV Files (*.csv);;Excel Files (*.xlsx *.xls);;All Files (*)",
        )

        if path:
            self.input_path = path
            self.input_type = "csv"
            self.file_label.setText(Path(path).name)
            self.statusBar().showMessage(f"Loaded data file: {path}")

    def load_pcap(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open PCAP/PCAPNG file",
            "",
            "Packet Capture Files (*.pcap *.pcapng);;All Files (*)",
        )

        if path:
            self.input_path = path
            self.input_type = "pcap"
            self.file_label.setText(Path(path).name)
            self.statusBar().showMessage(f"Loaded PCAP: {path}")

    def run_analysis(self):
        if not self.input_path:
            QMessageBox.warning(
                self,
                "No Input File",
                "Please load a CSV, Excel, or PCAP file first.",
            )
            return

        try:
            zones = parse_zone_config(self.zone_text.toPlainText())

            if self.input_type == "csv":
                connections = parse_csv_path(self.input_path)
            elif self.input_type == "pcap":
                connections = parse_pcap_path(self.input_path)
            else:
                raise ValueError("Unsupported input type.")

            if connections.empty:
                QMessageBox.information(
                    self,
                    "No Connections",
                    "No TCP/UDP connections were found.",
                )
                return

            self.enriched_connections = enrich_connections(connections, zones)
            self.asset_inventory = infer_asset_inventory(self.enriched_connections)
            self.communication_matrix = build_communication_matrix(
                self.enriched_connections
            )
            self.summary = build_summary(
                self.asset_inventory,
                self.enriched_connections,
            )

            self.asset_model.set_dataframe(self.asset_inventory)
            self.matrix_model.set_dataframe(self.communication_matrix)
            self.evidence_model.set_dataframe(self.enriched_connections)

            self.asset_table.resizeColumnsToContents()
            self.matrix_table.resizeColumnsToContents()
            self.evidence_table.resizeColumnsToContents()

            self.update_metrics()
            self.update_summary_text()

            self.tabs.setCurrentIndex(1)
            self.statusBar().showMessage("Analysis complete.")

        except Exception as exc:
            QMessageBox.critical(self, "Analysis Failed", str(exc))
            self.statusBar().showMessage("Analysis failed.")

    def update_metrics(self):
        self.metric_assets.set_value(self.summary.get("assets", 0))
        self.metric_ot_assets.set_value(self.summary.get("ot_assets", 0))
        self.metric_high.set_value(self.summary.get("high_risk_assets", 0))
        self.metric_ot_flows.set_value(self.summary.get("ot_protocols", 0))
        self.metric_remote.set_value(self.summary.get("remote_access_to_ot", 0))
        self.metric_it_ot.set_value(self.summary.get("it_to_ot", 0))

    def update_summary_text(self):
        text = f"""
OT Asset Mapper - Analyst Summary

Input file:
{self.input_path}

Executive metrics:
- Total assets: {self.summary.get("assets", 0)}
- OT assets: {self.summary.get("ot_assets", 0)}
- High-risk assets: {self.summary.get("high_risk_assets", 0)}
- OT protocol flows: {self.summary.get("ot_protocols", 0)}
- Remote access to OT: {self.summary.get("remote_access_to_ot", 0)}
- IT-to-OT flows: {self.summary.get("it_to_ot", 0)}

Recommended analyst review:
1. Validate high-risk assets first.
2. Review IT-to-OT and Vendor-to-OT communication paths.
3. Confirm remote/admin services such as RDP, SMB, Telnet, FTP, VNC, and SSH.
4. Validate inferred roles with asset owners and network diagrams.
5. Export Excel or HTML report for documentation.

Professional note:
Role inference is heuristic-based. Treat this output as passive evidence and validate it against operational context.
"""
        self.summary_box.setPlainText(text.strip())

    def _has_results(self):
        if self.asset_inventory is None or self.asset_inventory.empty:
            QMessageBox.warning(
                self,
                "No Results",
                "Run analysis before exporting reports.",
            )
            return False

        return True

    def export_asset_csv(self):
        if not self._has_results():
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Asset Inventory CSV",
            "ot_asset_inventory.csv",
            "CSV Files (*.csv)",
        )

        if path:
            export_csv(self.asset_inventory, path)
            self.statusBar().showMessage(f"Asset CSV exported: {path}")

    def export_matrix_csv(self):
        if not self._has_results():
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Communication Matrix CSV",
            "ot_communication_matrix.csv",
            "CSV Files (*.csv)",
        )

        if path:
            export_csv(self.communication_matrix, path)
            self.statusBar().showMessage(f"Matrix CSV exported: {path}")

    def export_excel_report(self):
        if not self._has_results():
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Excel Workbook",
            "ot_asset_mapper_report.xlsx",
            "Excel Files (*.xlsx)",
        )

        if path:
            export_excel(
                self.asset_inventory,
                self.communication_matrix,
                self.enriched_connections,
                path,
            )
            self.statusBar().showMessage(f"Excel report exported: {path}")

    def export_html_report(self):
        if not self._has_results():
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save HTML Report",
            "ot_asset_mapper_report.html",
            "HTML Files (*.html)",
        )

        if path:
            generate_html_report(
                self.summary,
                self.asset_inventory,
                self.communication_matrix,
                self.enriched_connections,
                path,
            )
            self.statusBar().showMessage(f"HTML report exported: {path}")

    def show_about(self):
        QMessageBox.information(
            self,
            "About OT Asset Mapper",
            "OT Asset Mapper Desktop\n\n"
            "Passive OT/ICS Asset Inventory & Communication Mapping Tool\n\n"
            "Defensive use only. The tool analyzes CSV, Excel, or PCAP files and does not scan or interact with OT assets.",
        )


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)

    font = QFont("Segoe UI", 10)
    app.setFont(font)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()