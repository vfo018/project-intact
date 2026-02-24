#!/usr/bin/env python3
"""
Simple Kafka Consumer using confluent-kafka
Consumes messages from 'test_topic'
"""

import json
from kafka import KafkaConsumer

# Configuration
KAFKA_BOOTSTRAP_SERVERS = "51.178.36.152:9092"
TOPIC = "test_topic"
GROUP_ID = "test-consumer-group"


def main():
    # Create consumer
    consumer = KafkaConsumer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        auto_offset_reset="earliest",  # Start from beginning if no offset
        enable_auto_commit=True,
        value_deserializer=lambda x: json.loads(x.decode('utf-8'))
    )
    
    # Subscribe to topic
    consumer.subscribe([TOPIC])
    
    print(f"Consuming from topic '{TOPIC}'...")
    print("   Press Ctrl+C to stop")
    print("-" * 50)
    
    message_count = 0
    
    try:
        while True:
            for message in consumer:
                message_count += 1
                print(f"\nMessage #{message_count}")
                print(f"   Partition: {message.partition}, Offset: {message.offset}")
                print("    Value:")
                print(json.dumps(message.value, indent=2, ensure_ascii=False))

            
    except KeyboardInterrupt:
        print(f"\nStopped. Total messages consumed: {message_count}")
    finally:
        consumer.close()


if __name__ == "__main__":
    main()
