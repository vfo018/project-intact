#!/usr/bin/env python3
"""
Simple Kafka Producer using confluent-kafka
Sends JSON messages to 'test_topic'
"""

import json
import time
from kafka import KafkaProducer

# Configuration
KAFKA_BOOTSTRAP_SERVERS = "51.178.36.152:9092"
TOPIC = "test_topic"


def main():
    # Create producer
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        client_id="test-producer",
        value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode('utf-8') if isinstance(v, dict) else str(v).encode('utf-8')
    )
    
    print(f"Sending messages to topic '{TOPIC}'...")
    print("-" * 50)
    
    # Sample JSON messages
    message = {
        "type": "bundle",
        "id": "bundle--9b497c8c-36be-4fd6-91ce-a6bffe5d935c",
        "objects": [
            {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--4e05ef27-91ea-49a2-bc97-557af4598980",
            "created": "2024-09-17T13:00:20.389Z",
            "modified": "2024-09-17T13:00:20.389Z",
            "name": "MMT-PROBE",
            "identity_class": "organization",
            "extensions": {
                "x-probe-id-ext": {
                "extension_type": "property-extension",
                "probe-id": "MMT-PROBE-1"
                }
            }
            },
            {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": "observed-data--502482d5-9d5d-4253-9f0d-5e478d86ad05",
            "created": "2024-09-17T13:00:20.389Z",
            "modified": "2024-09-17T13:00:20.389Z",
            "first_observed": "2024-09-13T20:38:00.538Z",
            "last_observed": "2024-09-13T20:40:24.020Z",
            "number_observed": 1,
            "object_refs": [
                "ipv4-addr--79871b1c-c8ea-4795-947c-3d21fbb61cd9",
                "ipv4-addr--88109c90-4c16-474d-ac2f-2a6202a18279",
                "x-attack-type--0af837dc-651c-45d8-b5bf-ed9d05f6b35f"
            ],
            "created_by_ref": "identity--4e05ef27-91ea-49a2-bc97-557af4598980",
            "extensions": {
                "x-observed-data-ext": {
                "extension_type": "property-extension",
                "description": "Detection of a potential attack by the ML algorithm"
                }
            }
            },
            {
            "type": "ipv4-addr",
            "id": "ipv4-addr--79871b1c-c8ea-4795-947c-3d21fbb61cd9",
            "value": "192.168.62.53"
            },
            {
            "type": "ipv4-addr",
            "id": "ipv4-addr--88109c90-4c16-474d-ac2f-2a6202a18279",
            "value": "192.168.126.67"
            },
            {
            "type": "x-attack-type",
            "id": "x-attack-type--0af837dc-651c-45d8-b5bf-ed9d05f6b35f",
            "name": "cyberattack_ocpp16_dos_flooding_heartbeat",
            "created": "2025-03-03T14:42:50.000Z",
            "modified": "2025-03-03T14:42:50.000Z",
            "external_references": [
                {
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/techniques/T1498/",
                "external_id": "T1498"
                }
            ],
            "extensions": {
                "x-attack-type-ext": {
                "extension_type": "new-sdo"
                },
                "x-simulation-ext": {
                "extension_type": "property-extension",
                "simulation": "Simulated attack with id = 25"
                }
            }
            }
        ]
    }
    
    producer.send(TOPIC, value=message)
    producer.flush()
    #print(f"Sent: {alert}")
    time.sleep(10)
    # except KeyboardInterrupt:
    #     print("Stopped by user.")
    #finally:
    producer.close()
    
    print("Done")


if __name__ == "__main__":
    main()
