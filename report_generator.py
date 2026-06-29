from datetime import datetime
import pandas as pd


def export_csv(df, output_path, separator=";"):
    if df is None:
        df = pd.DataFrame()
    df.to_csv(output_path, index=False, sep=separator, encoding="utf-8-sig")


def export_excel(asset_inventory, communication_matrix, enriched_connections, output_path):
    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        asset_inventory.to_excel(writer, sheet_name="Asset Inventory", index=False)
        communication_matrix.to_excel(writer, sheet_name="Communication Matrix", index=False)
        enriched_connections.to_excel(writer, sheet_name="Connection Evidence", index=False)


def generate_html_report(summary, asset_inventory, communication_matrix, enriched_connections, output_path):
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def html_table(df):
        if df is None or df.empty:
            return "<p>No records found.</p>"
        return df.to_html(index=False, escape=False)

    html = f"""
    <html>
    <head>
        <meta charset="utf-8">
        <title>OT Asset Mapper Desktop Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 30px; color: #1f2937; }}
            h1, h2 {{ color: #111827; }}
            .metric {{ display: inline-block; background: #f3f4f6; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px 16px; margin: 6px; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 12px; font-size: 12px; }}
            th, td {{ border: 1px solid #d1d5db; padding: 7px; text-align: left; vertical-align: top; }}
            th {{ background: #f9fafb; }}
            .note {{ color: #6b7280; font-size: 13px; }}
        </style>
    </head>
    <body>
        <h1>OT Asset Mapper Desktop Report</h1>
        <p class="note">Generated at: {generated_at}</p>

        <h2>Executive Summary</h2>
        <div class="metric"><b>Total Assets:</b> {summary.get("assets", 0)}</div>
        <div class="metric"><b>OT Assets:</b> {summary.get("ot_assets", 0)}</div>
        <div class="metric"><b>High-Risk Assets:</b> {summary.get("high_risk_assets", 0)}</div>
        <div class="metric"><b>OT Protocol Flows:</b> {summary.get("ot_protocols", 0)}</div>
        <div class="metric"><b>Remote Access to OT:</b> {summary.get("remote_access_to_ot", 0)}</div>
        <div class="metric"><b>IT-to-OT:</b> {summary.get("it_to_ot", 0)}</div>

        <h2>Asset Inventory</h2>
        {html_table(asset_inventory)}

        <h2>Communication Matrix</h2>
        {html_table(communication_matrix)}

        <h2>Enriched Connection Evidence</h2>
        {html_table(enriched_connections)}

        <h2>Analyst Notes</h2>
        <p>
            This report is based on passive CSV or PCAP analysis. Role inference is heuristic-based and should be validated
            with asset owners, network diagrams, firewall rules, CMDB records, switch/router data, and operational context.
        </p>
    </body>
    </html>
    """

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
