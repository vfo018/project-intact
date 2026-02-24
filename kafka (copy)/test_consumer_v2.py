#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Kafka STIX Consumer (for response topic)

- Default topic: response_topic
- Prints bundle id + whether x-mitigation-ext exists in observed-data.extensions
- Pretty prints the whole message (optional)

Dependencies:
  pip install kafka-python
"""

import os
import json
from kafka import KafkaConsumer

# ---- Config (env override supported) ----
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "51.178.36.152:9092")
TOPIC = os.getenv("TOPIC", "response_topic")  # <-- 默认改成 response_topic
GROUP_ID = os.getenv("GROUP_ID", "stix-response-consumer")
AUTO_OFFSET_RESET = os.getenv("AUTO_OFFSET_RESET", "latest")  # earliest/latest
PRINT_FULL_JSON = os.getenv("PRINT_FULL_JSON", "0") == "1"


def find_first(obj_list, stix_type: str):
    for o in obj_list:
        if isinstance(o, dict) and o.get("type") == stix_type:
            return o
    return None


def has_mitigation(bundle: dict) -> bool:
    objs = bundle.get("objects", [])
    obs = find_first(objs, "observed-data")
    if not obs:
        return False
    exts = obs.get("extensions")
    return isinstance(exts, dict) and ("x-mitigation-ext" in exts)


def main():
    consumer = KafkaConsumer(
        TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        group_id=GROUP_ID,
        client_id="test-consumer",
        auto_offset_reset=AUTO_OFFSET_RESET,
        enable_auto_commit=True,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
    )

    print(f"[+] Kafka bootstrap: {KAFKA_BOOTSTRAP_SERVERS}")
    print(f"[+] Consume topic: {TOPIC}")
    print(f"[+] group_id: {GROUP_ID}, auto_offset_reset: {AUTO_OFFSET_RESET}")
    print("[+] Waiting for STIX messages... (Ctrl+C to stop)\n")

    try:
        for msg in consumer:
            bundle = msg.value
            bundle_id = bundle.get("id")
            ok = has_mitigation(bundle)

            print(f"[RECV] bundle_id={bundle_id} | has x-mitigation-ext={ok}")

            # 如果你想看完整 JSON：export PRINT_FULL_JSON=1
            if PRINT_FULL_JSON:
                print(json.dumps(bundle, ensure_ascii=False, indent=2))

            print("-" * 80)

    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
    finally:
        try:
            consumer.close()
        except Exception:
            pass
        print("[+] Consumer closed.")


if __name__ == "__main__":
    main()

