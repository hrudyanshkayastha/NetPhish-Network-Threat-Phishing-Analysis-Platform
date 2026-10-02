"""End-to-end platform verification script for NetPhish.

Author: Hrudyansh Kayastha
"""

import sys
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.config import SAMPLES_DIR, APP_NAME, AUTHOR

client = TestClient(app)

FORBIDDEN_WORDS = [
    "college",
    "student",
    "academic",
    "university",
    "viva",
    "assignment",
    "educational project",
    "beginner project",
]


def log(msg: str, ok: bool = True):
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {msg}")


def main():
    print("=" * 65)
    print(f" NETPHISH v2.0.0 — PLATFORM VERIFICATION")
    print(f" Security Lead / Author: {AUTHOR}")
    print("=" * 65)

    # 1. Health check
    res = client.get("/api/health")
    assert res.status_code == 200, f"Health check failed with {res.status_code}"
    health_data = res.json()
    assert health_data["status"] == "healthy"
    assert health_data["app_name"] == APP_NAME
    assert health_data["author"] == AUTHOR
    log("1. /api/health operational and all security subsystems active")

    # 2. Stats
    res = client.get("/api/stats")
    assert res.status_code == 200
    log("2. /api/stats telemetry retrieved successfully")

    # 3. Clean URL Static Analysis
    res = client.post("/api/url/analyze", json={"url": "https://www.google.com"})
    assert res.status_code == 200
    clean_data = res.json()
    assert clean_data["severity"] == "LOW"
    assert clean_data["risk_score"] < 30.0
    log(f"3. Benign URL assessment: Score {clean_data['risk_score']} ({clean_data['severity']})")

    # 4. Phishing URL Static Analysis
    phish_target = "http://203.0.113.50/login/verify"
    res = client.post("/api/url/analyze", json={"url": phish_target})
    assert res.status_code == 200
    phish_data = res.json()
    assert phish_data["risk_score"] >= 35.0
    assert len(phish_data["detections"]) > 0
    assert len(phish_data["iocs"]) > 0
    url_analysis_id = phish_data["id"]
    log(f"4. Phishing URL assessment: Score {phish_data['risk_score']} ({phish_data['severity']}) with {len(phish_data['detections'])} detections")

    # 5. PCAP Capture Analysis
    susp_pcap = SAMPLES_DIR / "sample_suspicious.pcap"
    assert susp_pcap.exists(), "Sample suspicious PCAP missing"
    with open(susp_pcap, "rb") as f:
        files = {"file": ("sample_suspicious.pcap", f.read(), "application/vnd.tcpdump.pcap")}
    res = client.post("/api/pcap/analyze", files=files)
    assert res.status_code == 200
    pcap_data = res.json()
    assert pcap_data["packet_count"] > 0
    assert pcap_data["flow_count"] > 0
    pcap_analysis_id = pcap_data["id"]
    log(f"5. PCAP flow ingestion: {pcap_data['packet_count']} packets, {pcap_data['flow_count']} flows, Score {pcap_data['risk_score']} ({pcap_data['severity']})")

    # 6. Cross-Source Investigation Dossier Creation
    res = client.post("/api/investigations", json={
        "title": "Correlated Phishing and Network Reconnaissance Incident",
        "analysis_ids": [url_analysis_id, pcap_analysis_id],
        "explanation": "Correlating incoming credential lure URL with recorded outbound host flows",
    })
    assert res.status_code == 200
    inv_data = res.json()
    inv_id = inv_data["id"]
    assert inv_id.startswith("INV-")
    assert len(inv_data["correlations"]) > 0
    assert len(inv_data["timeline"]) > 0
    assert len(inv_data["recommendations"]) > 0
    log(f"6. Investigation Case {inv_id} created: Unified Risk {inv_data['risk_score']:.1f} ({inv_data['severity']}) with {len(inv_data['correlations'])} cross-source correlations")

    # 7. Forensic Reporting
    res_json = client.get(f"/api/reports/{inv_id}/json")
    assert res_json.status_code == 200
    assert res_json.json()["investigation"]["id"] == inv_id
    log(f"7. JSON forensic report exported ({len(res_json.text)} bytes)")

    res_html = client.get(f"/api/reports/{inv_id}/html")
    assert res_html.status_code == 200
    html_text = res_html.text
    assert "NETPHISH" in html_text
    assert inv_id in html_text
    log(f"8. HTML forensic dossier rendered ({len(html_text)} bytes)")

    # 8. Strict Vocabulary Audit on UI and Reports
    for word in FORBIDDEN_WORDS:
        assert word not in html_text.lower(), f"Prohibited word '{word}' found in HTML report!"
    log("9. Strict vocabulary audit PASSED: Zero forbidden terms in forensic reports")

    ui_index = Path("app/ui/templates/index.html")
    if ui_index.exists():
        ui_text = ui_index.read_text(encoding="utf-8")
        for word in FORBIDDEN_WORDS:
            assert word not in ui_text.lower(), f"Prohibited word '{word}' found in UI template!"
        log("10. Strict vocabulary audit PASSED: Zero forbidden terms in UI templates")

    readme_path = Path("README.md")
    if readme_path.exists():
        readme_text = readme_path.read_text(encoding="utf-8")
        for word in FORBIDDEN_WORDS:
            assert word not in readme_text.lower(), f"Prohibited word '{word}' found in README.md!"
        log("11. Strict vocabulary audit PASSED: Zero forbidden terms in README.md")

    print("=" * 65)
    print(" ALL VERIFICATION CHECKS COMPLETED SUCCESSFULLY")
    print("=" * 65)


if __name__ == "__main__":
    main()
