# OT Asset Mapper Desktop

**Passive OT/ICS Asset Inventory & Communication Mapping Tool**

This is the PySide6 desktop version of OT Asset Mapper.

## What's fixed in v2

- Left panel width improved
- Buttons are no longer cut off
- Reports section has clearer buttons
- File menu now includes:
  - Export Asset Inventory CSV
  - Export Communication Matrix CSV
  - Export Excel Workbook
  - Export HTML Report
- CSV/Excel input support improved
- Sample data includes:
  - comma CSV
  - semicolon CSV for European/Turkish Excel
  - Excel XLSX sample

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
python app_desktop.py
```

## Recommended sample file

Use this if Excel CSV columns appear merged:

```text
sample_data/sample_connections.xlsx
```

The app also supports:

```text
sample_data/sample_connections_semicolon.csv
sample_data/sample_connections_comma.csv
```

## Build Windows EXE

```bash
build_exe_windows.bat
```

Or manually:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name OT_Asset_Mapper app_desktop.py
```

The generated file will be:

```text
dist/OT_Asset_Mapper.exe
```

## CSV Input Format

Required columns:

```csv
source_ip,destination_ip,destination_port,protocol
```

Accepted aliases:

- src_ip
- dst_ip
- dst_port
- dport
- proto

## Disclaimer

For defensive monitoring, learning, and authorized OT/ICS security analysis only.
