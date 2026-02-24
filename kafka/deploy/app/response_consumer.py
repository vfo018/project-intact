#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
from kafka import KafkaConsumer

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "51.178.36.152:9092")
TOPIC = os.getenv("TOPIC", "response_topic_v2")
GROUP_ID = os.getenv("GROUP_ID", "response-checker")
AUTO_OFFSET_RESET = os.getenv("AUTO_OFFSET_RESET", "latest")

def main():
    consumer = KafkaConsumer(
        TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        group_id=GROUP_ID,
        auto_offset_reset=AUTO_OFFSET_RESET,
        enable_auto_commit=True,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
    )

    print(f"[+] Listening on response topic: {TOPIC}")
    for msg in consumer:
        bundle = msg.value
        bundle_id = bundle.get("id")
        # 尝试从 observed-data.extensions 里找 x-mitigation-ext
        decision = None
        for o in bundle.get("objects", []):
            if isinstance(o, dict) and o.get("type") == "observed-data":
                exts = o.get("extensions", {}) or {}
                mit = (exts.get("x-mitigation-ext") or {}).get("mitigation") or {}
                decision = mit.get("decision")
                break

        print(f"[RECV] topic={getattr(msg,'topic',None)} partition={msg.partition} offset={msg.offset} "
              f"bundle_id={bundle_id} decision={decision}")

if __name__ == "__main__":
    main()
