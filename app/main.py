from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import rdpcap
from scapy.layers.isakmp import ISAKMP
import tempfile
import os

app = FastAPI(title="VPN Sentinel Analyzer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # fine for hackathon demo
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

WEAK_ENCRYPTION_ALGOS = {1: "DES", 5: "3DES"}
STRONG_ENCRYPTION_ALGOS = {7: "AES-CBC", 8: "AES-CTR", 20: "AES-GCM"}


def extract_encryption_algo(raw_bytes):
    """
    Scans raw ISAKMP bytes for the Encryption Algorithm attribute.
    In IKE, this attribute is encoded in short form as:
      0x80 0x01 <2-byte algorithm ID>
    (0x80 = 'short form' flag set, 0x01 = attribute type 1 = Encryption Algorithm)
    """
    marker = b'\x80\x01'
    idx = raw_bytes.find(marker)
    if idx != -1 and idx + 4 <= len(raw_bytes):
        algo_id = int.from_bytes(raw_bytes[idx + 2:idx + 4], byteorder='big')
        return algo_id
    return None


def evaluate_findings(ikev1_count, ikev2_count, weak_encryption_found, weak_algo_name=None):
    findings = []

    if ikev1_count > 0:
        findings.append({
            "id": "IKE-001",
            "title": "IKEv1 Detected",
            "severity": "critical",
            "score": 30,
            "recommendation": "Disable IKEv1 and migrate the tunnel to IKEv2."
        })

    if ikev2_count > 0:
        findings.append({
            "id": "IKE-002",
            "title": "IKEv2 In Use",
            "severity": "info",
            "score": 0,
            "recommendation": "IKEv2 detected. Cryptographic policy still requires assessment."
        })

    if weak_encryption_found:
        findings.append({
            "id": "ENC-001",
            "title": f"Weak Encryption Algorithm Detected ({weak_algo_name})",
            "severity": "high",
            "score": 20,
            "recommendation": "Replace weak ciphers (DES/3DES) with AES-256."
        })

    return findings


def calculate_risk(findings):
    total_penalty = sum(f["score"] for f in findings)
    risk_score = min(100, total_penalty)

    if risk_score >= 80:
        level = "critical"
    elif risk_score >= 60:
        level = "high"
    elif risk_score >= 30:
        level = "moderate"
    else:
        level = "low"

    return {"score": risk_score, "level": level}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    file_bytes = await file.read()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        packets = rdpcap(tmp_path)
    finally:
        os.remove(tmp_path)

    udp_500 = 0
    udp_4500 = 0
    esp_packets = 0
    ah_packets = 0

    ikev1_evidence = []
    ikev2_evidence = []

    weak_encryption_found = False
    weak_algo_name = None

    for index, packet in enumerate(packets, start=1):
        if packet.haslayer("UDP"):
            sport = packet["UDP"].sport
            dport = packet["UDP"].dport

            if sport == 500 or dport == 500:
                udp_500 += 1

            if sport == 4500 or dport == 4500:
                udp_4500 += 1

            if packet.haslayer(ISAKMP):
                raw_bytes = bytes(packet[ISAKMP])

                # The ISAKMP header's version byte sits at position 17
                # (after an 8-byte initiator cookie + 8-byte responder cookie + 1-byte next-payload field)
                if len(raw_bytes) > 17:
                    version_byte = raw_bytes[17]
                    major_version = version_byte >> 4

                    # Check for weak encryption algorithm in this packet's SA payload
                    algo_id = extract_encryption_algo(raw_bytes)
                    if algo_id in WEAK_ENCRYPTION_ALGOS:
                        weak_encryption_found = True
                        weak_algo_name = WEAK_ENCRYPTION_ALGOS[algo_id]

                    if packet.haslayer("IP"):
                        src_ip = packet["IP"].src
                        dst_ip = packet["IP"].dst
                    elif packet.haslayer("IPv6"):
                        src_ip = packet["IPv6"].src
                        dst_ip = packet["IPv6"].dst
                    else:
                        src_ip = "unknown"
                        dst_ip = "unknown"

                    evidence_entry = {
                        "packet_number": index,
                        "timestamp": str(packet.time),
                        "source": src_ip,
                        "destination": dst_ip
                    }

                    if major_version == 1:
                        ikev1_evidence.append(evidence_entry)
                    elif major_version == 2:
                        ikev2_evidence.append(evidence_entry)

        if packet.haslayer("ESP"):
            esp_packets += 1

        if packet.haslayer("AH"):
            ah_packets += 1

    findings = evaluate_findings(
        len(ikev1_evidence),
        len(ikev2_evidence),
        weak_encryption_found,
        weak_algo_name
    )
    risk = calculate_risk(findings)

    return {
        "file_name": file.filename,
        "packet_count": len(packets),
        "summary": {
            "udp_500_packets": udp_500,
            "udp_4500_packets": udp_4500,
            "esp_packets": esp_packets,
            "ah_packets": ah_packets,
            "ikev1_packets": len(ikev1_evidence),
            "ikev2_packets": len(ikev2_evidence)
        },
        "evidence": {
            "ikev1": ikev1_evidence,
            "ikev2": ikev2_evidence
        },
        "findings": findings,
        "risk": risk
    }