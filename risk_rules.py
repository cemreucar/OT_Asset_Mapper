OT_PROTOCOLS = {
    502: {"name": "Modbus TCP", "asset_hint": "PLC / Controller", "risk": "Medium", "concern": "Modbus TCP is common in industrial environments and often lacks native authentication or encryption."},
    102: {"name": "Siemens S7", "asset_hint": "PLC / Controller", "risk": "Medium", "concern": "Siemens S7 traffic usually indicates PLC or engineering workstation communication."},
    44818: {"name": "EtherNet/IP", "asset_hint": "PLC / Controller", "risk": "Medium", "concern": "EtherNet/IP is common in industrial automation and should be limited to approved assets."},
    20000: {"name": "DNP3", "asset_hint": "RTU / Utility Device", "risk": "Medium", "concern": "DNP3 is used in utility and industrial control environments."},
    4840: {"name": "OPC UA", "asset_hint": "SCADA / OPC Server", "risk": "Medium", "concern": "OPC UA is used for industrial interoperability. Exposure should be reviewed."},
    47808: {"name": "BACnet", "asset_hint": "Building Automation Device", "risk": "Medium", "concern": "BACnet is used in building automation and may expose facility systems."},
    2404: {"name": "IEC 60870-5-104", "asset_hint": "Substation / Utility Device", "risk": "Medium", "concern": "IEC 104 is common in power and utility environments."},
}

RISKY_SERVICES = {
    3389: {"name": "RDP", "asset_hint": "Engineering Workstation / Windows Host", "risk": "High", "concern": "RDP provides remote desktop access and should be tightly controlled in OT networks."},
    445: {"name": "SMB", "asset_hint": "Windows Host / File Server", "risk": "High", "concern": "SMB may enable lateral movement and file sharing risks."},
    23: {"name": "Telnet", "asset_hint": "Legacy Device", "risk": "High", "concern": "Telnet is unencrypted and should generally be replaced or isolated."},
    21: {"name": "FTP", "asset_hint": "Legacy File Transfer Host", "risk": "High", "concern": "FTP sends credentials and data in clear text."},
    5900: {"name": "VNC", "asset_hint": "Remote Access Host", "risk": "High", "concern": "VNC provides remote screen control and must be restricted."},
    22: {"name": "SSH", "asset_hint": "Linux / Network Device", "risk": "Medium", "concern": "SSH is administrative access. Validate source, destination, and access policy."},
    80: {"name": "HTTP", "asset_hint": "Web Interface / HMI", "risk": "Medium", "concern": "HTTP may expose unencrypted management or HMI interfaces."},
    443: {"name": "HTTPS", "asset_hint": "Web Interface / Server", "risk": "Low", "concern": "HTTPS is common, but OT management interfaces should still be inventoried."},
}

REMOTE_ACCESS_PORTS = {22, 3389, 5900, 443, 8443, 1194, 500, 4500}


def classify_port(port):
    try:
        port = int(port)
    except Exception:
        return {"service_name": "Unknown", "service_category": "Unknown", "asset_hint": "Unknown", "risk": "Low", "concern": "No matching rule for this port."}

    if port in OT_PROTOCOLS:
        rule = OT_PROTOCOLS[port]
        return {"service_name": rule["name"], "service_category": "OT/ICS Protocol", "asset_hint": rule["asset_hint"], "risk": rule["risk"], "concern": rule["concern"]}

    if port in RISKY_SERVICES:
        rule = RISKY_SERVICES[port]
        return {"service_name": rule["name"], "service_category": "Remote/Admin or Risky Service", "asset_hint": rule["asset_hint"], "risk": rule["risk"], "concern": rule["concern"]}

    return {"service_name": "Unknown", "service_category": "General Network Service", "asset_hint": "Unknown", "risk": "Low", "concern": "No specific OT or risky service rule matched."}


def risk_to_score(risk):
    return {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(str(risk), 0)
