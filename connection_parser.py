import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP

REQUIRED_COLUMNS = ["source_ip", "destination_ip", "destination_port", "protocol"]


def normalize_connection_dataframe(df):
    if df is None:
        raise ValueError("Input dataframe is empty.")

    df = df.copy()
    df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]

    aliases = {
        "src": "source_ip", "src_ip": "source_ip", "source": "source_ip", "source_address": "source_ip", "ip_src": "source_ip",
        "dst": "destination_ip", "dst_ip": "destination_ip", "destination": "destination_ip", "destination_address": "destination_ip", "dest_ip": "destination_ip", "ip_dst": "destination_ip",
        "dst_port": "destination_port", "dest_port": "destination_port", "dport": "destination_port", "port": "destination_port",
        "proto": "protocol", "transport": "protocol",
    }

    df = df.rename(columns={c: aliases.get(c, c) for c in df.columns})

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required column(s): {', '.join(missing)}")

    df["source_ip"] = df["source_ip"].astype(str).str.strip()
    df["destination_ip"] = df["destination_ip"].astype(str).str.strip()
    df["destination_port"] = pd.to_numeric(df["destination_port"], errors="coerce").astype("Int64")
    df["protocol"] = df["protocol"].fillna("Unknown").astype(str).str.upper()

    df = df.dropna(subset=["destination_port"])
    return df[REQUIRED_COLUMNS].drop_duplicates()


def parse_csv_path(file_path):
    file_path_str = str(file_path).lower()

    if file_path_str.endswith(".xlsx") or file_path_str.endswith(".xls"):
        df = pd.read_excel(file_path)
        return normalize_connection_dataframe(df)

    # Try automatic detection first. Works for comma, semicolon and tab in most cases.
    try:
        df = pd.read_csv(file_path, sep=None, engine="python", encoding="utf-8-sig")
        normalized = normalize_connection_dataframe(df)
        return normalized
    except Exception:
        pass

    # Fallbacks for Excel regional CSV formats.
    last_error = None
    for sep in [";", ",", "\t"]:
        try:
            df = pd.read_csv(file_path, sep=sep, encoding="utf-8-sig")
            return normalize_connection_dataframe(df)
        except Exception as exc:
            last_error = exc

    raise ValueError(f"Could not parse CSV file. Last error: {last_error}")


def parse_pcap_path(file_path):
    packets = rdpcap(file_path)
    rows = []

    for pkt in packets:
        if IP not in pkt:
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if TCP in pkt:
            rows.append({"source_ip": src_ip, "destination_ip": dst_ip, "destination_port": int(pkt[TCP].dport), "protocol": "TCP"})
        elif UDP in pkt:
            rows.append({"source_ip": src_ip, "destination_ip": dst_ip, "destination_port": int(pkt[UDP].dport), "protocol": "UDP"})

    if not rows:
        return pd.DataFrame(columns=REQUIRED_COLUMNS)

    return normalize_connection_dataframe(pd.DataFrame(rows))
