import pandas as pd

from risk_rules import classify_port, risk_to_score, OT_PROTOCOLS, RISKY_SERVICES, REMOTE_ACCESS_PORTS
from subnet_utils import guess_zone


def enrich_connections(connections_df, zones):
    df = connections_df.copy()
    enriched_rows = []

    for _, row in df.iterrows():
        port_info = classify_port(row["destination_port"])
        src_zone = guess_zone(row["source_ip"], zones)
        dst_zone = guess_zone(row["destination_ip"], zones)

        risk = port_info["risk"]
        notes = [port_info["concern"]]

        if src_zone == "IT" and dst_zone == "OT":
            risk = "High"
            notes.append("IT-to-OT communication detected. Validate business need, firewall policy, and approved access path.")

        if src_zone == "Vendor" and dst_zone == "OT":
            risk = "High"
            notes.append("Vendor-to-OT communication detected. Validate approval, maintenance window, MFA, and VPN controls.")

        try:
            port = int(row["destination_port"])
        except Exception:
            port = None

        if port in REMOTE_ACCESS_PORTS and dst_zone == "OT":
            if risk_to_score(risk) < risk_to_score("High"):
                risk = "High"
            notes.append("Remote or administrative access service targets an OT zone.")

        enriched_rows.append({
            "source_zone": src_zone,
            "destination_zone": dst_zone,
            "service_name": port_info["service_name"],
            "service_category": port_info["service_category"],
            "risk_level": risk,
            "risk_score": risk_to_score(risk),
            "security_note": " ".join(notes)
        })

    enriched = pd.concat([df.reset_index(drop=True), pd.DataFrame(enriched_rows)], axis=1)
    return enriched.sort_values(["risk_score", "destination_port"], ascending=[False, True])


def infer_asset_inventory(enriched_connections):
    if enriched_connections is None or enriched_connections.empty:
        return pd.DataFrame()

    df = enriched_connections.copy()
    all_ips = sorted(set(df["source_ip"].astype(str)).union(set(df["destination_ip"].astype(str))))
    assets = []

    for ip in all_ips:
        as_source = df[df["source_ip"].astype(str) == ip]
        as_dest = df[df["destination_ip"].astype(str) == ip]

        zone = "Unknown"
        if not as_dest.empty:
            zone = as_dest["destination_zone"].mode().iloc[0]
        elif not as_source.empty:
            zone = as_source["source_zone"].mode().iloc[0]

        dest_ports = sorted(set(as_dest["destination_port"].dropna().astype(int).tolist()))
        outbound_ports = sorted(set(as_source["destination_port"].dropna().astype(int).tolist()))

        observed_service_names = sorted(set(as_dest["service_name"].dropna().astype(str).tolist()))
        outbound_service_names = sorted(set(as_source["service_name"].dropna().astype(str).tolist()))

        role_votes = []
        rationale = []

        for port in dest_ports:
            if port in OT_PROTOCOLS:
                role_votes.append(OT_PROTOCOLS[port]["asset_hint"])
                rationale.append(f"Receives {OT_PROTOCOLS[port]['name']} traffic on port {port}.")
            if port in RISKY_SERVICES:
                role_votes.append(RISKY_SERVICES[port]["asset_hint"])
                rationale.append(f"Exposes {RISKY_SERVICES[port]['name']} on port {port}.")

        ot_outbound_ports = [p for p in outbound_ports if p in OT_PROTOCOLS]
        remote_outbound_ports = [p for p in outbound_ports if p in REMOTE_ACCESS_PORTS]

        if ot_outbound_ports and zone in ["IT", "Unknown"]:
            role_votes.append("Engineering Workstation / OT Client")
            rationale.append("Initiates OT protocol sessions toward industrial assets.")

        if remote_outbound_ports and ot_outbound_ports:
            role_votes.append("Engineering Workstation / Remote Access Client")
            rationale.append("Initiates both OT protocol and remote/admin service connections.")

        if not role_votes and zone == "OT":
            role_votes.append("OT Asset")
            rationale.append("Located in OT zone based on subnet configuration.")

        if not role_votes and zone == "IT":
            role_votes.append("IT Host")
            rationale.append("Located in IT zone based on subnet configuration.")

        if not role_votes:
            role_votes.append("Unknown Asset")
            rationale.append("Insufficient evidence for confident role inference.")

        role_guess = pd.Series(role_votes).mode().iloc[0]
        related_rows = pd.concat([as_source, as_dest])
        max_score = int(related_rows["risk_score"].max()) if not related_rows.empty else 1
        risk_level = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}.get(max_score, "Low")

        assets.append({
            "asset_ip": ip,
            "zone": zone,
            "role_guess": role_guess,
            "observed_services": ", ".join([s for s in observed_service_names if s != "Unknown"]) or "None observed as server",
            "destination_ports": ", ".join(map(str, dest_ports)) if dest_ports else "None observed",
            "outbound_services": ", ".join([s for s in outbound_service_names if s != "Unknown"]) or "None observed",
            "talks_to_count": int(as_source["destination_ip"].nunique()),
            "talked_by_count": int(as_dest["source_ip"].nunique()),
            "risk_level": risk_level,
            "risk_score": max_score,
            "rationale": " ".join(rationale)
        })

    result = pd.DataFrame(assets)
    return result.sort_values(["risk_score", "zone", "asset_ip"], ascending=[False, True, True])


def build_communication_matrix(enriched_connections):
    if enriched_connections is None or enriched_connections.empty:
        return pd.DataFrame()

    group_cols = [
        "source_ip", "source_zone", "destination_ip", "destination_zone",
        "destination_port", "protocol", "service_name", "service_category", "risk_level"
    ]

    matrix = enriched_connections.groupby(group_cols, dropna=False).size().reset_index(name="connection_count")

    risk_order = {"High": 1, "Medium": 2, "Low": 3}
    matrix["risk_sort"] = matrix["risk_level"].map(risk_order).fillna(9)
    matrix = matrix.sort_values(["risk_sort", "destination_port"]).drop(columns=["risk_sort"])
    matrix["communication_path"] = matrix["source_ip"] + " -> " + matrix["destination_ip"] + ":" + matrix["destination_port"].astype(str)
    return matrix


def build_summary(asset_inventory, enriched_connections):
    if asset_inventory is None or asset_inventory.empty:
        return {"assets": 0, "ot_assets": 0, "high_risk_assets": 0, "ot_protocols": 0, "remote_access_to_ot": 0, "it_to_ot": 0}

    conn = enriched_connections if enriched_connections is not None else pd.DataFrame()

    return {
        "assets": int(len(asset_inventory)),
        "ot_assets": int((asset_inventory["zone"] == "OT").sum()),
        "high_risk_assets": int((asset_inventory["risk_level"] == "High").sum()),
        "ot_protocols": int((conn["service_category"] == "OT/ICS Protocol").sum()) if not conn.empty else 0,
        "remote_access_to_ot": int(conn[(conn["destination_zone"] == "OT") & (conn["destination_port"].astype(int).isin(list(REMOTE_ACCESS_PORTS)))].shape[0]) if not conn.empty else 0,
        "it_to_ot": int(((conn["source_zone"] == "IT") & (conn["destination_zone"] == "OT")).sum()) if not conn.empty else 0,
    }
