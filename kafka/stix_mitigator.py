#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mitigator for real MMT STIX reports.

Robust version:
- Consume messages from Kafka topic: mmt-reports
- Read each Kafka message as raw text, not directly as JSON
- Extract all valid JSON objects from the raw text
- Process only valid STIX bundles: {"type": "bundle", "objects": [...]}
- Skip non-STIX/raw/CSV messages instead of crashing
- Add mitigation information into observed-data.extensions["x-mitigation-ext"]
- Current demo supports only one countermeasure:
    C8 = Notify + Block
- Produce enriched STIX bundle to OUT_TOPIC, default: ulanc-response-mitigator
"""

import os
import json
import uuid
from copy import deepcopy
from datetime import datetime, timezone

from kafka import KafkaConsumer, KafkaProducer


# ------------------------------------------------------------
# Config
# ------------------------------------------------------------

KAFKA_BOOTSTRAP_SERVERS = os.getenv(
    "KAFKA_BOOTSTRAP_SERVERS",
    "51.178.36.152:9092",
)

# UBITECH / Montimage real STIX alert topic.
IN_TOPIC = os.getenv("IN_TOPIC", "mmt-reports")

# ULANCS output topic for STIX with mitigation.
OUT_TOPIC = os.getenv("OUT_TOPIC", "ulanc-response-mitigator")

GROUP_ID = os.getenv("GROUP_ID", "stix-mitigator")
CLIENT_ID = os.getenv("CLIENT_ID", "stix-mitigator")
AUTO_OFFSET_RESET = os.getenv("AUTO_OFFSET_RESET", "latest")

KEEP_ORIGINAL_BUNDLE_ID = os.getenv("KEEP_ORIGINAL_BUNDLE_ID", "0") == "1"

DECIDED_BY = os.getenv("DECIDED_BY", "ulanc-mitigator")
DEFAULT_CONFIDENCE = float(os.getenv("DEFAULT_CONFIDENCE", "0.9"))
BLOCK_DURATION_SEC = int(os.getenv("BLOCK_DURATION_SEC", "3600"))

PRINT_IO_JSON = os.getenv("PRINT_IO_JSON", "1") == "1"
PRINT_SUMMARY = os.getenv("PRINT_SUMMARY", "1") == "1"
MAX_JSON_CHARS = int(os.getenv("MAX_JSON_CHARS", "12000"))

MITIGATION_EXTENSION_KEY = "x-mitigation-ext"

# Current demo supports only Notify + Block.
# C1 = Notify the network operator/provider
# C2 = Block the attacker
# C8 = C1 + C2 = Notify + Block
COUNTERMEASURE_ID = "C8"
COUNTERMEASURE_NAME = "Notify + Block"
COUNTERMEASURE_DESCRIPTION = (
    "C1 + C2: Notify the network operator/provider and block the attacker."
)


# ------------------------------------------------------------
# Basic helpers
# ------------------------------------------------------------

def now_z() -> str:
    """
    Return current UTC time in STIX-friendly format.
    Example:
    2026-05-05T14:32:18.427Z
    """
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_bundle_id() -> str:
    return f"bundle--{uuid.uuid4()}"


def dump_json(obj: dict) -> str:
    text = json.dumps(obj, ensure_ascii=False, indent=2)

    if MAX_JSON_CHARS and len(text) > MAX_JSON_CHARS:
        return text[:MAX_JSON_CHARS] + "\n... truncated ...\n"

    return text


def preview_text(text: str, max_chars: int = 200) -> str:
    """
    Create a short one-line preview for logs.
    """
    text = text.replace("\n", "\\n").replace("\r", "\\r")
    if len(text) > max_chars:
        return text[:max_chars] + "..."
    return text


# ------------------------------------------------------------
# Robust Kafka message parsing
# ------------------------------------------------------------

def extract_json_objects_from_text(raw_text: str) -> list:
    """
    Extract JSON objects embedded in raw Kafka text.

    This handles messages like:

    1,5,"-",1777991883.821386,...       # non-STIX/raw line
    {
      "type": "bundle",
      ...
    }
    {
      "type": "bundle",
      ...
    }

    It scans for '{' and tries json.JSONDecoder.raw_decode() from that position.
    Non-JSON parts are skipped.
    """
    decoder = json.JSONDecoder()
    objects = []
    index = 0
    text_len = len(raw_text)

    while index < text_len:
        start = raw_text.find("{", index)

        if start == -1:
            break

        try:
            obj, end = decoder.raw_decode(raw_text[start:])
            objects.append(obj)
            index = start + end
        except json.JSONDecodeError:
            index = start + 1

    return objects


def is_stix_bundle(obj) -> bool:
    """
    A minimal STIX bundle check.
    """
    return (
        isinstance(obj, dict)
        and obj.get("type") == "bundle"
        and isinstance(obj.get("objects"), list)
    )


def collect_stix_bundles(obj) -> list:
    """
    Collect valid STIX bundles from a parsed JSON object.

    Normally obj is a dict bundle.
    This also supports a JSON list containing bundles.
    """
    bundles = []

    if is_stix_bundle(obj):
        bundles.append(obj)
        return bundles

    if isinstance(obj, list):
        for item in obj:
            bundles.extend(collect_stix_bundles(item))

    return bundles


def extract_stix_bundles_from_raw_message(raw_text: str) -> list:
    """
    Main parser for Kafka message values.

    It does not assume the whole Kafka message is JSON.
    It extracts all JSON objects from the raw text and returns only STIX bundles.
    """
    json_objects = extract_json_objects_from_text(raw_text)

    bundles = []
    for obj in json_objects:
        bundles.extend(collect_stix_bundles(obj))

    return bundles


# ------------------------------------------------------------
# STIX helpers
# ------------------------------------------------------------

def find_objects(bundle: dict, stix_type: str) -> list:
    return [
        obj
        for obj in bundle.get("objects", [])
        if isinstance(obj, dict) and obj.get("type") == stix_type
    ]


def index_by_id(bundle: dict) -> dict:
    return {
        obj.get("id"): obj
        for obj in bundle.get("objects", [])
        if isinstance(obj, dict) and obj.get("id")
    }


def get_first_observed_data(bundle: dict):
    observed_objects = find_objects(bundle, "observed-data")
    return observed_objects[0] if observed_objects else None


def get_attack_object(bundle: dict, observed: dict):
    """
    Find x-attack-type object.

    First try observed-data.object_refs.
    If not found, fallback to the first x-attack-type object in the bundle.
    """
    objects_by_id = index_by_id(bundle)

    for ref in observed.get("object_refs", []):
        obj = objects_by_id.get(ref)
        if obj and obj.get("type") == "x-attack-type":
            return obj

    attack_objects = find_objects(bundle, "x-attack-type")
    return attack_objects[0] if attack_objects else None


def extract_ipv4_addresses(bundle: dict, observed: dict) -> list:
    """
    Return IPv4 addresses in the same order as observed-data.object_refs.

    Current assumption:
    - first IPv4 = attacker/source IP
    - second IPv4 = victim/destination IP
    """
    objects_by_id = index_by_id(bundle)
    ips = []

    for ref in observed.get("object_refs", []):
        obj = objects_by_id.get(ref)
        if obj and obj.get("type") == "ipv4-addr" and obj.get("value"):
            ips.append(obj["value"])

    return ips


def get_observed_description(observed: dict):
    extensions = observed.get("extensions", {})
    if not isinstance(extensions, dict):
        return None

    for ext_value in extensions.values():
        if isinstance(ext_value, dict) and ext_value.get("description"):
            return ext_value.get("description")

    return None


def get_attack_name(observed: dict, attack_obj: dict) -> str:
    if isinstance(attack_obj, dict) and attack_obj.get("name"):
        return attack_obj["name"]

    description = get_observed_description(observed)
    if description:
        return description

    return "Unknown attack"


def get_external_id(attack_obj: dict):
    if not isinstance(attack_obj, dict):
        return None

    for ref in attack_obj.get("external_references", []) or []:
        if isinstance(ref, dict) and ref.get("external_id"):
            return str(ref["external_id"])

    return None


def infer_attack_uc(observed: dict, attack_obj: dict) -> str:
    """
    Infer attack UC only as metadata.

    This does NOT affect the countermeasure.
    The countermeasure is always C8 = Notify + Block.
    """
    external_id = get_external_id(attack_obj)
    attack_name = get_attack_name(observed, attack_obj)
    description = get_observed_description(observed) or ""

    text = f"{external_id or ''} {attack_name} {description}".lower()

    # Current MMT sample:
    # external_id 92 = NGAP packet with wrong SCTP Protocol Identifier
    if external_id == "92":
        return "UC1.3"

    if "wrong sctp protocol identifier" in text:
        return "UC1.3"

    if "malformed" in text or "invalid" in text or "corrupted" in text:
        return "UC1.3"

    if "nas" in text or "replay" in text:
        return "UC1.2"

    if "dos" in text or "flood" in text or "signalling" in text or "signaling" in text:
        return "UC1.1"

    return "UC1.1"


# ------------------------------------------------------------
# Mitigation generation
# ------------------------------------------------------------

def build_notify_block_actions(attacker_ip: str, attack_name: str) -> list:
    return [
        {
            "type": "notify_operator",
            "channel": "operator_console",
            "message": (
                f"Attack detected: {attack_name}. "
                f"Countermeasure selected: {COUNTERMEASURE_NAME}."
            ),
        },
        {
            "type": "firewall_block",
            "target": attacker_ip or "unknown",
            "target_type": "ipv4-addr",
            "duration_sec": BLOCK_DURATION_SEC,
        },
    ]


def build_response_bundle(in_bundle: dict) -> tuple:
    """
    Add x-mitigation-ext to the incoming STIX bundle.
    """
    if not is_stix_bundle(in_bundle):
        raise ValueError("Incoming object is not a valid STIX bundle.")

    out_bundle = deepcopy(in_bundle)

    observed = get_first_observed_data(out_bundle)
    if not observed:
        raise ValueError("No observed-data object found in incoming STIX bundle.")

    attack_obj = get_attack_object(out_bundle, observed)

    attack_name = get_attack_name(observed, attack_obj)
    external_id = get_external_id(attack_obj)
    attack_uc = infer_attack_uc(observed, attack_obj)

    ips = extract_ipv4_addresses(out_bundle, observed)
    attacker_ip = ips[0] if len(ips) >= 1 else None
    victim_ip = ips[1] if len(ips) >= 2 else None

    observed.setdefault("extensions", {})
    if not isinstance(observed["extensions"], dict):
        observed["extensions"] = {}

    mitigation_block = {
        "extension_type": "property-extension",
        "mitigation": {
            "source": "real_mmt_stix_report",
            "attack_uc": attack_uc,
            "attack_name": attack_name,
            "external_id": external_id,
            "attacker_ip": attacker_ip,
            "victim_ip": victim_ip,
            "countermeasure": {
                "id": COUNTERMEASURE_ID,
                "name": COUNTERMEASURE_NAME,
                "description": COUNTERMEASURE_DESCRIPTION,
                "atomic_countermeasures": [
                    {
                        "id": "C1",
                        "name": "Notify the network operator/provider",
                    },
                    {
                        "id": "C2",
                        "name": "Block the attacker",
                    },
                ],
                "policy": "fixed_demo_policy_notify_block_only",
            },
            "decision": COUNTERMEASURE_ID,
            "actions": build_notify_block_actions(
                attacker_ip=attacker_ip,
                attack_name=attack_name,
            ),
            "status": "recommended",
            "confidence": DEFAULT_CONFIDENCE,
            "decided_at": now_z(),
            "decided_by": DECIDED_BY,
            "comment": (
                "Mitigation generated from real MMT STIX alert. "
                "Current demo supports only Notify + Block."
            ),
        },
    }

    observed["extensions"][MITIGATION_EXTENSION_KEY] = mitigation_block
    observed["modified"] = now_z()

    if not KEEP_ORIGINAL_BUNDLE_ID:
        out_bundle["id"] = new_bundle_id()

    debug_info = {
        "attack_uc": attack_uc,
        "attack_name": attack_name,
        "external_id": external_id,
        "countermeasure_id": COUNTERMEASURE_ID,
        "countermeasure_name": COUNTERMEASURE_NAME,
        "attacker_ip": attacker_ip,
        "victim_ip": victim_ip,
        "incoming_bundle_id": in_bundle.get("id"),
        "outgoing_bundle_id": out_bundle.get("id"),
    }

    return out_bundle, debug_info


# ------------------------------------------------------------
# Kafka main loop
# ------------------------------------------------------------

def main():
    if IN_TOPIC.strip() == OUT_TOPIC.strip():
        raise ValueError(
            f"Config error: IN_TOPIC and OUT_TOPIC must be different. "
            f"Got IN_TOPIC={IN_TOPIC}, OUT_TOPIC={OUT_TOPIC}"
        )

    consumer = KafkaConsumer(
        IN_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        group_id=GROUP_ID,
        client_id=CLIENT_ID + "-consumer",
        auto_offset_reset=AUTO_OFFSET_RESET,
        enable_auto_commit=True,

        # Important:
        # Do NOT json.loads here.
        # mmt-reports may contain raw/non-STIX lines before or after STIX bundles.
        value_deserializer=lambda value: value.decode("utf-8", errors="replace"),
    )

    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        client_id=CLIENT_ID + "-producer",
        value_serializer=lambda value: json.dumps(value, ensure_ascii=False).encode("utf-8"),
        acks="all",
        retries=5,
    )

    print(f"[+] Kafka bootstrap: {KAFKA_BOOTSTRAP_SERVERS}")
    print(f"[+] Consume topic: {IN_TOPIC}")
    print(f"[+] Produce topic: {OUT_TOPIC}")
    print(f"[+] Fixed countermeasure: {COUNTERMEASURE_ID} = {COUNTERMEASURE_NAME}")
    print(
        f"[+] PRINT_IO_JSON={PRINT_IO_JSON}, "
        f"PRINT_SUMMARY={PRINT_SUMMARY}, "
        f"MAX_JSON_CHARS={MAX_JSON_CHARS}"
    )
    print("[+] Waiting for real MMT STIX alerts...")

    try:
        for msg in consumer:
            raw_value = msg.value

            bundles = extract_stix_bundles_from_raw_message(raw_value)

            if not bundles:
                print(
                    f"[SKIP] No valid STIX bundle found "
                    f"topic={msg.topic} partition={msg.partition} offset={msg.offset} "
                    f"preview={preview_text(raw_value)}"
                )
                continue

            print(
                f"[+] Found {len(bundles)} STIX bundle(s) "
                f"topic={msg.topic} partition={msg.partition} offset={msg.offset}"
            )

            for in_bundle in bundles:
                try:
                    out_bundle, info = build_response_bundle(in_bundle)

                    if PRINT_IO_JSON:
                        print("\n" + "=" * 100)
                        print(
                            f"=== INCOMING STIX "
                            f"from topic={msg.topic} "
                            f"partition={msg.partition} "
                            f"offset={msg.offset} ==="
                        )
                        print(dump_json(in_bundle))
                        print(f"=== OUTGOING STIX to topic={OUT_TOPIC} ===")
                        print(dump_json(out_bundle))
                        print("=" * 100 + "\n")

                    if PRINT_SUMMARY:
                        print(
                            f"[DBG] attack={info['attack_name']} "
                            f"uc={info['attack_uc']} "
                            f"external_id={info['external_id']} "
                            f"countermeasure={info['countermeasure_id']}({info['countermeasure_name']}) "
                            f"attacker_ip={info['attacker_ip']} "
                            f"victim_ip={info['victim_ip']} "
                            f"from={msg.topic} "
                            f"to={OUT_TOPIC}"
                        )

                    producer.send(OUT_TOPIC, value=out_bundle)
                    producer.flush()

                    print(
                        f"[OK] Produced mitigation STIX: "
                        f"from_topic={msg.topic} -> to_topic={OUT_TOPIC} "
                        f"in_bundle={in_bundle.get('id')} "
                        f"out_bundle={out_bundle.get('id')}"
                    )

                except Exception as exc:
                    print(
                        f"[ERR] Failed to process one STIX bundle "
                        f"topic={msg.topic} partition={msg.partition} offset={msg.offset}: {exc}"
                    )

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
