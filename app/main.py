from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import rdpcap
from scapy.layers.isakmp import ISAKMP
import tempfile
import os

app = FastAPI(title="VPN Sentinel Analyzer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

IKEV1_ENC = {1: "DES", 5: "3DES", 7: "AES-CBC", 8: "AES-CTR", 20: "AES-GCM"}
IKEV1_HASH = {1: "MD5", 2: "SHA", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512"}
IKEV1_AUTH = {1: "PSK", 2: "DSS-SIG", 3: "RSA-SIG"}
IKEV2_ENCR = {
    1: "DES",
    3: "3DES",
    12: "AES-CBC",
    13: "AES-CTR",
    18: "AES-CCM-8",
    19: "AES-GCM-8",
    20: "AES-GCM-16",
}
IKEV2_PRF = {2: "HMAC-SHA1", 5: "HMAC-SHA2-256", 7: "HMAC-SHA2-512"}
IKEV2_INTEG = {2: "HMAC-SHA1-96", 12: "HMAC-SHA2-256-128", 14: "HMAC-SHA2-512-256"}
DH_GROUPS = {1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048", 19: "ECP-256", 20: "ECP-384"}
WEAK_ENCRYPTION_ALGOS = {1: "DES", 5: "3DES"}
IKEV1_EXCH = {2: "Identity Protection (Main Mode)", 4: "Aggressive Mode", 5: "Informational", 32: "Quick Mode"}
IKEV2_EXCH = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL"}


def _param(value, extra=None, missing="Not detected from available capture"):
    if value is None or value == "":
        return {"status": "not_detected", "detail": missing}
    row = {"status": "detected", "value": value}
    if extra:
        row.update(extra)
    return row


def _normalize_enc(name, key_length):
    if name is None:
        return None
    text = str(name)
    if key_length in (128, 256) and "AES" in text.upper():
        if "GCM" in text.upper():
            return f"AES-GCM-{key_length}"
        if "CBC" in text.upper() or text.upper() == "AES-CBC":
            return f"AES-CBC-{key_length}"
        return f"{text}-{key_length}"
    return text


def _walk_ikev1_tv(blob, start=0):
    rows, current, pos = [], {}, start
    while pos + 4 <= len(blob) and (blob[pos] & 0x80):
        atype = blob[pos + 1]
        aval = int.from_bytes(blob[pos + 2 : pos + 4], "big")
        pos += 4
        if atype == 1 and current.get("encryption_id") is not None:
            rows.append(current)
            current = {}
        if atype == 1:
            current["encryption_id"] = aval
            current["encryption"] = IKEV1_ENC.get(aval, f"ENC-{aval}")
        elif atype == 2:
            current["hash"] = IKEV1_HASH.get(aval, f"HASH-{aval}")
        elif atype == 3:
            current["auth_method"] = IKEV1_AUTH.get(aval, f"AUTH-{aval}")
        elif atype == 4:
            current["dh_group"] = aval
        elif atype == 14:
            current["key_length"] = aval
    if current:
        rows.append(current)
    return rows


def parse_ikev1_sa(raw_bytes):
    """RFC 2409 short-form attributes. Encryption = 0x80 0x01 + 2-byte IKEv1 ID."""
    empty = {
        "encryption": None,
        "encryption_id": None,
        "key_length": None,
        "dh_group": None,
        "auth_method": None,
        "hash": None,
    }
    if not raw_bytes or len(raw_bytes) < 28:
        return empty
    marker = raw_bytes.find(b"\x80\x01")
    if marker < 0:
        return empty
    start = marker
    while start >= 4 and raw_bytes[start - 4] & 0x80:
        start -= 4
    rows = _walk_ikev1_tv(raw_bytes, start)
    if not rows:
        return empty
    first = rows[0]
    return {
        "encryption": first.get("encryption"),
        "encryption_id": first.get("encryption_id"),
        "key_length": first.get("key_length"),
        "dh_group": first.get("dh_group"),
        "auth_method": first.get("auth_method"),
        "hash": first.get("hash"),
    }


def _ikev2_proposal(body):
    proposals = []
    pos = 0
    while pos + 8 <= len(body):
        plen = int.from_bytes(body[pos + 2 : pos + 4], "big")
        if plen == 0 or pos + plen > len(body):
            plen = len(body) if pos == 0 else 0
            if plen == 0:
                break
        ntrans = body[pos + 7]
        spi_size = body[pos + 6]
        tpos = pos + 8 + spi_size
        transforms = []
        for _ in range(ntrans):
            if tpos + 8 > len(body):
                break
            tlen = int.from_bytes(body[tpos + 2 : tpos + 4], "big")
            ttype = body[tpos + 4]
            tid = int.from_bytes(body[tpos + 6 : tpos + 8], "big")
            attrs = body[tpos + 8 : tpos + tlen] if tlen >= 8 else b""
            keylen = None
            a = 0
            while a + 4 <= len(attrs) and (attrs[a] & 0x80):
                if attrs[a + 1] == 14:
                    keylen = int.from_bytes(attrs[a + 2 : a + 4], "big")
                a += 4
            name = None
            if ttype == 1:
                name = IKEV2_ENCR.get(tid, f"ENCR-{tid}")
            elif ttype == 2:
                name = IKEV2_PRF.get(tid, f"PRF-{tid}")
            elif ttype == 3:
                name = IKEV2_INTEG.get(tid, f"INTEG-{tid}")
            elif ttype == 4:
                name = DH_GROUPS.get(tid, f"DH-{tid}")
            transforms.append({"type": ttype, "id": tid, "name": name, "key_length": keylen})
            if tlen < 8:
                break
            tpos += tlen
        proposals.append({"transforms": transforms})
        if plen < 8:
            break
        pos += plen
        if pos >= len(body):
            break
    return proposals


def _parse_ikev2_sa_raw(raw):
    if len(raw) < 32:
        return []
    proposals = []
    offset = 28
    while offset + 4 <= len(raw):
        nxt = raw[offset]
        length = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        if length < 4 or offset + length > len(raw):
            break
        body = raw[offset + 4 : offset + length]
        if len(body) >= 8:
            proposals.extend(_ikev2_proposal(body))
        offset += length
        if nxt == 0:
            break
    return proposals


def parse_ikev2_sa(raw_bytes):
    """RFC 7296 §3.3 Transform Substructure. Do not use 0x80 0x01 as the cipher."""
    empty = {
        "encryption": None,
        "encryption_id": None,
        "key_length": None,
        "dh_group": None,
        "auth_method": None,
        "prf": None,
        "integrity": None,
    }
    proposals = _parse_ikev2_sa_raw(raw_bytes)
    if not proposals:
        return empty
    enc = prf = integ = enc_id = keylen = dh = None
    for prop in proposals:
        for t in prop.get("transforms") or []:
            if t.get("type") == 1 and enc is None:
                enc, enc_id, keylen = t.get("name"), t.get("id"), t.get("key_length")
            elif t.get("type") == 2 and prf is None:
                prf = t.get("name")
            elif t.get("type") == 3 and integ is None:
                integ = t.get("name")
            elif t.get("type") == 4 and dh is None:
                dh = t.get("id")
    return {
        "encryption": _normalize_enc(enc, keylen) or enc,
        "encryption_id": enc_id,
        "key_length": keylen,
        "dh_group": dh,
        "auth_method": None,
        "prf": prf,
        "integrity": integ,
    }


def evaluate_findings(ikev1_count, ikev2_count, weak_encryption_found, weak_algo_name=None):
    findings = []
    if ikev1_count > 0:
        findings.append(
            {
                "id": "IKE-001",
                "title": "IKEv1 Detected",
                "severity": "critical",
                "score": 30,
                "recommendation": "Disable IKEv1 and migrate the tunnel to IKEv2.",
            }
        )
    if ikev2_count > 0:
        findings.append(
            {
                "id": "IKE-002",
                "title": "IKEv2 In Use",
                "severity": "info",
                "score": 0,
                "recommendation": "IKEv2 detected. Cryptographic policy still requires assessment.",
            }
        )
    if weak_encryption_found:
        findings.append(
            {
                "id": "ENC-001",
                "title": f"Weak Encryption Algorithm Detected ({weak_algo_name})",
                "severity": "high",
                "score": 20,
                "recommendation": "Replace weak ciphers (DES/3DES) with AES-256.",
            }
        )
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

    udp_500 = udp_4500 = esp_packets = ah_packets = 0
    ikev1_evidence, ikev2_evidence = [], []
    messages = []
    weak_encryption_found = False
    weak_algo_name = None
    last_crypto = {}

    for index, packet in enumerate(packets, start=1):
        if packet.haslayer("UDP"):
            sport, dport = packet["UDP"].sport, packet["UDP"].dport
            if sport == 500 or dport == 500:
                udp_500 += 1
            if sport == 4500 or dport == 4500:
                udp_4500 += 1

            if packet.haslayer(ISAKMP):
                raw_bytes = bytes(packet[ISAKMP])
                if len(raw_bytes) > 17:
                    major_version = raw_bytes[17] >> 4
                    flags = str(getattr(packet[ISAKMP], "flags", "") or "")
                    encrypted = "encrypt" in flags.lower()

                    parsed = {}
                    if not encrypted:
                        if major_version == 1:
                            parsed = parse_ikev1_sa(raw_bytes)
                        elif major_version == 2:
                            parsed = parse_ikev2_sa(raw_bytes)
                        if parsed.get("encryption"):
                            last_crypto = parsed
                        enc_id = parsed.get("encryption_id")
                        enc_name = str(parsed.get("encryption") or "")
                        if major_version == 1 and enc_id in WEAK_ENCRYPTION_ALGOS:
                            weak_encryption_found = True
                            weak_algo_name = WEAK_ENCRYPTION_ALGOS[enc_id]
                        if "DES" in enc_name and "AES" not in enc_name:
                            weak_encryption_found = True
                            weak_algo_name = enc_name

                    if packet.haslayer("IP"):
                        src_ip, dst_ip = packet["IP"].src, packet["IP"].dst
                    elif packet.haslayer("IPv6"):
                        src_ip, dst_ip = packet["IPv6"].src, packet["IPv6"].dst
                    else:
                        src_ip = dst_ip = "unknown"

                    exch = None
                    if len(raw_bytes) > 18:
                        et = raw_bytes[18]
                        exch = IKEV1_EXCH.get(et) if major_version == 1 else IKEV2_EXCH.get(et, f"type-{et}")
                    if len(messages) < 40:
                        messages.append(
                            {
                                "packet_number": index,
                                "ike_version": major_version,
                                "exchange": exch or "IKE",
                                "encrypted_payload": encrypted,
                                "timestamp": str(packet.time),
                                "source": src_ip,
                                "destination": dst_ip,
                            }
                        )

                    evidence_entry = {
                        "packet_number": index,
                        "timestamp": str(packet.time),
                        "source": src_ip,
                        "destination": dst_ip,
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
        weak_algo_name,
    )
    for f in findings:
        f["explanation"] = f.get("recommendation")
        f["reason"] = f.get("recommendation")
        f["detected_value"] = (
            "IKEv1" if f["id"] == "IKE-001" else "IKEv2" if f["id"] == "IKE-002" else weak_algo_name
        )
    risk = calculate_risk(findings)

    ike_label = None
    if ikev1_evidence and ikev2_evidence:
        ike_label = "IKEv1 and IKEv2"
    elif ikev1_evidence:
        ike_label = "IKEv1"
    elif ikev2_evidence:
        ike_label = "IKEv2"

    enc = last_crypto.get("encryption")
    dh = last_crypto.get("dh_group")
    dh_extra = {"name": DH_GROUPS.get(dh, f"group {dh}")} if isinstance(dh, int) else None
    integ = last_crypto.get("integrity") or last_crypto.get("hash")

    why = "IKEv1 present." if ikev1_evidence else "IKEv2 observed." if ikev2_evidence else "No IKE handshake parsed."
    action = findings[0]["recommendation"] if findings else "No action."

    return {
        "file_name": file.filename,
        "packet_count": len(packets),
        "ike": {
            "version": _param(ike_label),
            "messages": messages,
        },
        "summary": {
            "udp_500_packets": udp_500,
            "udp_4500_packets": udp_4500,
            "esp_packets": esp_packets,
            "ah_packets": ah_packets,
            "ikev1_packets": len(ikev1_evidence),
            "ikev2_packets": len(ikev2_evidence),
        },
        "security_parameters": {
            "encryption": _param(enc),
            "dh_group": _param(dh, dh_extra),
            "auth_method": _param(last_crypto.get("auth_method")),
            "authentication": _param(last_crypto.get("auth_method")),
            "integrity": _param(integ),
            "prf": _param(last_crypto.get("prf")),
            "pfs": _param(None, missing="PFS is on Child SA / Quick Mode; often encrypted"),
            "mode": _param(None, missing="Tunnel vs transport is in IPsec proposals, often encrypted"),
            "lifetime_seconds": _param(None),
            "replay_protection": _param(None),
        },
        "evidence": {"ikev1": ikev1_evidence, "ikev2": ikev2_evidence},
        "findings": findings,
        "risk": risk,
        "security_summary": {"why": why, "most_important_action": action},
        "recommendations_prioritized": {
            "immediate": [
                {"finding_id": f["id"], "severity": f["severity"], "recommendation": f["recommendation"]}
                for f in findings
                if f.get("score", 0) > 0
            ],
            "informational": [
                {"finding_id": f["id"], "severity": f["severity"], "recommendation": f["recommendation"]}
                for f in findings
                if f.get("score", 0) == 0
            ],
        },
        "traffic_analysis": {
            "model_available": False,
            "prediction": None,
            "confidence": None,
            "message": "AI prediction unavailable — IsolationForest is not in this minor main.py.",
            "features": {
                "packet_count": len(packets),
                "protocol_distribution": {
                    "ike_isakmp": len(ikev1_evidence) + len(ikev2_evidence),
                    "esp": esp_packets,
                    "ah": ah_packets,
                    "udp_500": udp_500,
                    "udp_4500": udp_4500,
                },
            },
        },
        "report": {
            "html": f"<html><body><h1>VPN Sentinel</h1><p>{file.filename} score {risk['score']}</p></body></html>",
            "json": {"score": risk["score"], "level": risk["level"]},
        },
    }