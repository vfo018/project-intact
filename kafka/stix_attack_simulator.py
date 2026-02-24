#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Simulate Kafka bus: send a STIX 2.1 attack message every 1-10 seconds.
Randomly picks one of three attack use-cases (UC1.1 / UC1.2 / UC1.3).

Dependencies:
  pip install kafka-python
"""

import os
import json
import time
import random
import uuid
from datetime import datetime, timezone
from kafka import KafkaProducer

# ---- Config (env override supported) ----
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "51.178.36.152:9092")
TOPIC = os.getenv("TOPIC", "test_topic")
CLIENT_ID = os.getenv("CLIENT_ID", "attack-stix-simulator")

SLEEP_MIN = int(os.getenv("SLEEP_MIN", "1"))
SLEEP_MAX = int(os.getenv("SLEEP_MAX", "10"))

SRC_IP = os.getenv("SRC_IP", "192.168.62.53")
DST_IP = os.getenv("DST_IP", "192.168.126.67")

PROBE_ID = os.getenv("PROBE_ID", "MMT-PROBE-1")
PROBE_NAME = os.getenv("PROBE_NAME", "MMT-PROBE")

ATTACKS = [
    {
        "uc": "UC1.1",
        "name": "dos_high_rate_signalling_flooding",
        "description": "DoS / High-Rate Signalling Flooding",
    },
    {
        "uc": "UC1.2",
        "name": "nas_replay_attack",
        "description": "NAS Replay Attack",
    },
    {
        "uc": "UC1.3",
        "name": "dos_via_malformed_packets",
        "description": "DoS Attack via Malformed Packets",
    },
]


def now_z() -> str:
    # e.g. 2026-01-13T00:00:00.123Z
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def stix_id(stix_type: str) -> str:
    return f"{stix_type}--{uuid.uuid4()}"


def build_stix_bundle(src_ip: str, dst_ip: str, attack: dict) -> dict:
    created = now_z()

    bundle_id = stix_id("bundle")
    identity_id = stix_id("identity")
    observed_id = stix_id("observed-data")
    src_ip_id = stix_id("ipv4-addr")
    dst_ip_id = stix_id("ipv4-addr")
    attack_id = stix_id("x-attack-type")

    # 你也可以把 simulation_id 换成你系统里的真实 ID
    simulation_id = random.randint(1, 10_000)

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": created,
                "modified": created,
                "name": PROBE_NAME,
                "identity_class": "organization",
                "extensions": {
                    "x-probe-id-ext": {
                        "extension_type": "property-extension",
                        "probe-id": PROBE_ID,
                    }
                },
            },
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": observed_id,
                "created": created,
                "modified": created,
                "first_observed": created,
                "last_observed": created,
                "number_observed": 1,
                "object_refs": [src_ip_id, dst_ip_id, attack_id],
                "created_by_ref": identity_id,
                "extensions": {
                    "x-observed-data-ext": {
                        "extension_type": "property-extension",
                        "description": "Simulated detection of a potential attack",
                    }
                },
            },
            {"type": "ipv4-addr", "id": src_ip_id, "value": src_ip},
            {"type": "ipv4-addr", "id": dst_ip_id, "value": dst_ip},
            {
                "type": "x-attack-type",
                "id": attack_id,
                "name": attack["name"],
                "created": created,
                "modified": created,
                "extensions": {
                    "x-attack-type-ext": {"extension_type": "new-sdo"},
                    "x-attack-uc-ext": {
                        "extension_type": "property-extension",
                        "uc": attack["uc"],
                        "description": attack["description"],
                    },
                    "x-simulation-ext": {
                        "extension_type": "property-extension",
                        "simulation": f"Simulated attack with id = {simulation_id}",
                    },
                },
            },
        ],
    }


def main():
    if SLEEP_MIN < 0 or SLEEP_MAX < SLEEP_MIN:
        raise ValueError("Invalid sleep range. Ensure 0 <= SLEEP_MIN <= SLEEP_MAX.")

    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        client_id=CLIENT_ID,
        value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
        acks="all",
        retries=5,
    )

    print(f"[+] Kafka bootstrap: {KAFKA_BOOTSTRAP_SERVERS}")
    print(f"[+] Topic: {TOPIC}")
    print(f"[+] Sending STIX bundle every {SLEEP_MIN}-{SLEEP_MAX} seconds (Ctrl+C to stop)\n")

    sent = 0
    try:
        while True:
            attack = random.choice(ATTACKS)
            msg = build_stix_bundle(SRC_IP, DST_IP, attack)

            producer.send(TOPIC, value=msg)
            producer.flush()

            sent += 1
            print(f"[{sent}] sent attack={attack['uc']} / {attack['name']}  at {now_z()}")

            time.sleep(random.randint(SLEEP_MIN, SLEEP_MAX))

    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
    finally:
        producer.close()
        print("[+] Producer closed.")


if __name__ == "__main__":
    main()

