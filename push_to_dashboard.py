import json
import pandas as pd
from datetime import datetime

# Load the Semgrep report
with open("semgrep-report.json") as f:
    semgrep_data = json.load(f)

# Read existing Excel dashboard
dashboard_path = "./Vuln_Management_Dashboard.xlsx"
with pd.ExcelFile(dashboard_path) as xl:
    projects_df = xl.parse("Projects")
    vulns_df = xl.parse("Vulnerabilities")

# Helper function to get the next vuln ID
def get_next_vuln_id(vulns_df):
    if vulns_df.empty:
        return "V-001"
    last_id = vulns_df["Vuln ID"].str.extract(r"V-(\d+)").astype(int).max().iloc[0]
    return f"V-{last_id + 1:03d}"

# Process Semgrep results and convert them to a DataFrame
vulns_data = []
for result in semgrep_data["results"]:
    vuln_id = get_next_vuln_id(vulns_df)
    project_name = "Your Project"  # Replace with dynamic project info if needed
    severity = result.get("extra", {}).get("metadata", {}).get("severity")
    status = "Open"
    cwe_cve = result.get("cwe", "N/A")
    description = result["extra"]["message"]
    file_location = result["path"]
    first_seen = datetime.now()
    last_seen = first_seen
    assigned_to = "Unassigned"  # Replace with dynamic assignee logic if needed
    notes = "Review for mitigation"

    vuln = {
        "Vuln ID": vuln_id,
        "Project ID": project_name,
        "Tool": "Semgrep",
        "Severity": severity,
        "Status": status,
        "CWE/CVE": cwe_cve,
        "Description": description,
        "File/Location": file_location,
        "First Seen": first_seen,
        "Last Seen": last_seen,
        "Assigned To": assigned_to,
        "Notes": notes
    }
    vulns_data.append(vuln)

# Convert vulnerabilities to DataFrame
new_vulns_df = pd.DataFrame(vulns_data)

# Append new vulnerabilities to the existing DataFrame
vulns_df = pd.concat([vulns_df, new_vulns_df], ignore_index=True)

# Update the Projects sheet if necessary (e.g., add new project or update)
# Example: Update Risk Score and # of Open Vulns (simplified)
projects_df.loc[projects_df["Project Name"] == "Your Project", "Risk Score"] = 8.0  # Update based on your logic
projects_df.loc[projects_df["Project Name"] == "Your Project", "# of Open Vulns"] = len(vulns_df[vulns_df["Project ID"] == "Your Project"])

# Save the updated Excel dashboard
with pd.ExcelWriter(dashboard_path, engine="openpyxl") as writer:
    projects_df.to_excel(writer, sheet_name="Projects", index=False)
    vulns_df.to_excel(writer, sheet_name="Vulnerabilities", index=False)

print("Semgrep report pushed to the dashboard successfully!")
