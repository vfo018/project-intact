#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Consume STIX attack bundles from Kafka, choose the safest countermeasure,
and produce a response STIX bundle back to Kafka (NEW topic).

Policy:
  1) Maximize Risk Factor Reduction (RF)
  2) If tie, minimize (Time + Energy + Monetary Cost)

Deps:
  pip install kafka-python
"""

import os
import json
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from kafka import KafkaConsumer, KafkaProducer


# -------------------- Config --------------------
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "51.178.36.152:9092")

# IMPORTANT: IN_TOPIC is where attack STIX comes in; OUT_TOPIC is where response STIX goes out.
IN_TOPIC = os.getenv("IN_TOPIC", "test_topic")
OUT_TOPIC = os.getenv("OUT_TOPIC", "response_topic")

GROUP_ID = os.getenv("GROUP_ID", "stix-mitigator")
CLIENT_ID = os.getenv("CLIENT_ID", "stix-mitigator")

AUTO_OFFSET_RESET = os.getenv("AUTO_OFFSET_RESET", "latest")  # earliest/latest
KEEP_ORIGINAL_BUNDLE_ID = os.getenv("KEEP_ORIGINAL_BUNDLE_ID", "0") == "1"

DECIDED_BY = os.getenv("DECIDED_BY", "bpm-pipeline")
DEFAULT_CONFIDENCE = float(os.getenv("DEFAULT_CONFIDENCE", "0.9"))
BLOCK_DURATION_SEC = int(os.getenv("BLOCK_DURATION_SEC", "3600"))

# Debug printing controls
PRINT_IO_JSON = os.getenv("PRINT_IO_JSON", "1") == "1"     # print full incoming/outgoing JSON
PRINT_SUMMARY = os.getenv("PRINT_SUMMARY", "0") == "1"     # print short summary line
MAX_JSON_CHARS = int(os.getenv("MAX_JSON_CHARS", "0"))     # 0 = no truncation


# -------------------- STIX helpers --------------------
def now_z() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_bundle_id() -> str:
    return f"bundle--{uuid.uuid4()}"


def find_objects(bundle: dict, stix_type: str) -> list:
    return [o for o in bundle.get("objects", []) if isinstance(o, dict) and o.get("type") == stix_type]


def index_by_id(bundle: dict) -> dict:
    return {o.get("id"): o for o in bundle.get("objects", []) if isinstance(o, dict) and o.get("id")}


def get_observed_data(bundle: dict):
    obs = find_objects(bundle, "observed-data")
    return obs[0] if obs else None


def extract_attack_obj(bundle: dict, observed: dict):
    by_id = index_by_id(bundle)
    for ref in observed.get("object_refs", []):
        obj = by_id.get(ref)
        if obj and obj.get("type") == "x-attack-type":
            return obj
    return None


def extract_ipv4s(bundle: dict, observed: dict) -> list[str]:
    """Return ipv4 list in the order they appear in object_refs."""
    by_id = index_by_id(bundle)
    ips: list[str] = []
    for ref in observed.get("object_refs", []):
        obj = by_id.get(ref)
        if obj and obj.get("type") == "ipv4-addr" and obj.get("value"):
            ips.append(obj["value"])
    return ips


def infer_uc(attack_obj: dict):
    exts = attack_obj.get("extensions", {}) if isinstance(attack_obj, dict) else {}
    if isinstance(exts, dict):
        uc = (exts.get("x-attack-uc-ext") or {}).get("uc")
        if uc:
            return uc

    name = (attack_obj or {}).get("name", "") or ""
    name_l = name.lower()
    if "replay" in name_l or "nas" in name_l:
        return "UC1.2"
    if "malformed" in name_l:
        return "UC1.3"
    if "dos" in name_l or "flood" in name_l or "signalling" in name_l or "heartbeat" in name_l:
        return "UC1.1"
    return None


# -------------------- Countermeasure model --------------------
CM_DESC = {
    "C14": "Notify + Block + Relaunch",
    "C15": "Notify + Block + Reconfigure",
    "C16": "Notify + Block + Redeploy",
    "C17": "Notify + Block + Replace",
    "C18": "Notify + Block + Redirect",
}

# Only RF=9 tier candidates; tie-break by (time+energy+cost)
CM_METRICS = {
    "UC1.1": {
        "C14": {"time": 7, "energy": 5, "cost": 5, "rf": 9},
        "C15": {"time": 9, "energy": 4, "cost": 6, "rf": 9},
        "C16": {"time": 10, "energy": 8, "cost": 9, "rf": 9},
        "C18": {"time": 10, "energy": 10, "cost": 10, "rf": 9},
    },
    "UC1.2": {
        "C14": {"time": 6, "energy": 5, "cost": 5, "rf": 9},
        "C15": {"time": 4, "energy": 4, "cost": 6, "rf": 9},
        "C16": {"time": 10, "energy": 8, "cost": 9, "rf": 9},
        "C17": {"time": 10, "energy": 10, "cost": 10, "rf": 9},
        "C18": {"time": 4, "energy": 10, "cost": 10, "rf": 9},
    },
    "UC1.3": {
        "C14": {"time": 3, "energy": 5, "cost": 5, "rf": 9},
        "C15": {"time": 10, "energy": 4, "cost": 6, "rf": 9},
        "C16": {"time": 10, "energy": 8, "cost": 9, "rf": 9},
        "C17": {"time": 4, "energy": 10, "cost": 10, "rf": 9},
        "C18": {"time": 4, "energy": 10, "cost": 10, "rf": 9},
    },
}


def pick_safest_countermeasure(uc: str):
    candidates = CM_METRICS.get(uc)
    if not candidates:
        # conservative fallback
        return "C14", {"time": None, "energy": None, "cost": None, "rf": None}

    items = []
    for cm_id, m in candidates.items():
        score = (m["rf"], -(m["time"] + m["energy"] + m["cost"]))  # max rf, min sum
        items.append((score, cm_id, m))
    items.sort(reverse=True)
    _, best_id, best_m = items[0]
    return best_id, best_m


def cm_to_actions(cm_id: str, attacker_ip: str | None) -> list[dict]:
    actions: list[dict] = []

    actions.append({
        "type": "notify_operator",
        "channel": "email/slack",
        "message": f"Auto mitigation selected: {cm_id}"
    })
    actions.append({
        "type": "firewall_block",
        "target": attacker_ip or "unknown",
        "duration_sec": BLOCK_DURATION_SEC
    })

    if cm_id == "C14":
        actions.append({"type": "relaunch_nf", "targets": ["AMF", "SMF"], "mode": "rolling"})
    elif cm_id == "C15":
        actions.append({"type": "core_reconfigure", "security_level": "high"})
    elif cm_id == "C16":
        actions.append({"type": "redeploy_slice", "target_slice": "secure-slice"})
    elif cm_id == "C17":
        actions.append({"type": "replace_instance", "targets": ["AMF/SMF"], "strategy": "less_vulnerable_image"})
    elif cm_id == "C18":
        actions.append({"type": "redirect_load", "targets": ["AMF"], "to": "redundant_instance"})

    return actions


def _dump_json(obj: dict) -> str:
    s = json.dumps(obj, ensure_ascii=False, indent=2)
    if MAX_JSON_CHARS and len(s) > MAX_JSON_CHARS:
        return s[:MAX_JSON_CHARS] + "\n... (truncated)\n"
    return s


def build_response_bundle(in_bundle: dict) -> tuple[dict, dict]:
    """
    Enrich incoming bundle with x-mitigation-ext under observed-data.extensions.
    (Kafka topic is handled by producer.send(OUT_TOPIC,...), not stored in STIX.)
    Return (out_bundle, debug_info).
    """
    bundle = deepcopy(in_bundle)

    observed = get_observed_data(bundle)
    if not observed:
        raise ValueError("No observed-data object found in incoming bundle.")

    attack_obj = extract_attack_obj(bundle, observed)
    if not attack_obj:
        raise ValueError("No x-attack-type object referenced by observed-data.object_refs.")

    uc = infer_uc(attack_obj) or "UC1.1"
    cm_id, metrics = pick_safest_countermeasure(uc)

    ips = extract_ipv4s(bundle, observed)
    attacker_ip = ips[0] if len(ips) >= 1 else None

    observed.setdefault("extensions", {})
    if not isinstance(observed["extensions"], dict):
        observed["extensions"] = {}

    mitigation_block = {
        "extension_type": "property-extension",
        "mitigation": {
            "attack_uc": uc,
            "countermeasure": {
                "id": cm_id,
                "name": CM_DESC.get(cm_id, cm_id),
                "risk_factor_reduction": metrics.get("rf"),
                "time": metrics.get("time"),
                "energy": metrics.get("energy"),
                "monetary_cost": metrics.get("cost"),
                "policy": "max_rf_then_min_cost",
            },
            "decision": cm_id,
            "actions": cm_to_actions(cm_id, attacker_ip),
            "status": "recommended",
            "confidence": DEFAULT_CONFIDENCE,
            "decided_at": now_z(),
            "decided_by": DECIDED_BY,
            "comment": "Mitigation generated based on received STIX alert and countermeasure model.",
        },
    }

    observed["extensions"]["x-mitigation-ext"] = mitigation_block
    observed["modified"] = now_z()

    if not KEEP_ORIGINAL_BUNDLE_ID:
        bundle["id"] = new_bundle_id()

    debug_info = {
        "uc": uc,
        "cm_id": cm_id,
        "cm_name": CM_DESC.get(cm_id, cm_id),
        "incoming_bundle_id": in_bundle.get("id"),
        "out_bundle_id": bundle.get("id"),
    }

    return bundle, debug_info


# -------------------- Main loop --------------------
def main():
    # Hard guard: OUT_TOPIC must be a NEW topic (must differ from IN_TOPIC)
    if IN_TOPIC.strip() == OUT_TOPIC.strip():
        raise ValueError(
            f"Config error: IN_TOPIC and OUT_TOPIC must be different. "
            f"Got IN_TOPIC={IN_TOPIC} OUT_TOPIC={OUT_TOPIC}"
        )

    consumer = KafkaConsumer(
        IN_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        group_id=GROUP_ID,
        client_id=CLIENT_ID + "-consumer",
        auto_offset_reset=AUTO_OFFSET_RESET,
        enable_auto_commit=True,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
    )

    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        client_id=CLIENT_ID + "-producer",
        value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
        acks="all",
        retries=5,
    )

    print(f"[+] Kafka bootstrap: {KAFKA_BOOTSTRAP_SERVERS}")
    print(f"[+] Consume topic (IN_TOPIC):  {IN_TOPIC}")
    print(f"[+] Produce topic (OUT_TOPIC): {OUT_TOPIC}")
    print(f"[+] Debug: PRINT_IO_JSON={PRINT_IO_JSON}, PRINT_SUMMARY={PRINT_SUMMARY}, MAX_JSON_CHARS={MAX_JSON_CHARS}")
    print("[+] Waiting for incoming STIX bundles... (Ctrl+C to stop)\n")

    try:
        for msg in consumer:
            in_bundle = msg.value

            # Kafka metadata (print only)
            in_meta = {
                "kafka_topic": getattr(msg, "topic", IN_TOPIC),
                "partition": getattr(msg, "partition", None),
                "offset": getattr(msg, "offset", None),
                "timestamp": getattr(msg, "timestamp", None),
            }

            try:
                out_bundle, info = build_response_bundle(in_bundle)

                # Debug printing
                if PRINT_IO_JSON:
                    print("\n" + "=" * 100)
                    print(f"=== INCOMING STIX (from topic={in_meta['kafka_topic']} partition={in_meta['partition']} offset={in_meta['offset']}) ===")
                    print(_dump_json(in_bundle))
                    print(f"=== OUTGOING STIX (to topic={OUT_TOPIC}) ===")
                    print(_dump_json(out_bundle))
                    print("=" * 100 + "\n")
                elif PRINT_SUMMARY:
                    print(f"[DBG] uc={info['uc']} selected={info['cm_id']} ({info['cm_name']}) "
                          f"in={info['incoming_bundle_id']} out={info['out_bundle_id']} "
                          f"from={in_meta['kafka_topic']} to={OUT_TOPIC}")

                # Produce to NEW topic
                producer.send(OUT_TOPIC, value=out_bundle)
                producer.flush()

                print(f"[OK] Produced response STIX: from_topic={in_meta['kafka_topic']} -> to_topic={OUT_TOPIC} "
                      f"in_bundle={in_bundle.get('id')} out_bundle={out_bundle.get('id')}")

            except Exception as e:
                print(f"[ERR] Failed to process message: {e}")

    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
    finally:
        try:
            producer.close()
        except Exception:
            pass
        try:
            consumer.close()
        except Exception:
            pass
        print("[+] Closed.")


if __name__ == "__main__":
    main()

