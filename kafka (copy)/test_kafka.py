#!/usr/bin/env python3
"""
Kafka Testing Script using confluent-kafka

This script provides utilities to:
- Create and delete topics
- List existing topics
- Produce messages to topics
- Consume messages from topics

Requirements:
    pip install confluent-kafka

Usage:
    python test_kafka.py
"""

import json
import time
import sys
from confluent_kafka import Producer, Consumer, KafkaError, KafkaException, TopicPartition
from confluent_kafka.admin import AdminClient, NewTopic, NewPartitions

# Kafka server configuration
KAFKA_BOOTSTRAP_SERVERS = "51.178.36.152:9092"


def get_admin_client():
    """Create and return a Kafka AdminClient."""
    return AdminClient({"bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS})


def create_topic(topic_name: str, num_partitions: int = 1, replication_factor: int = 1):
    """
    Create a new Kafka topic.
    
    Args:
        topic_name: Name of the topic to create
        num_partitions: Number of partitions for the topic
        replication_factor: Replication factor for the topic
    """
    admin_client = get_admin_client()
    
    new_topic = NewTopic(
        topic=topic_name,
        num_partitions=num_partitions,
        replication_factor=replication_factor
    )
    
    futures = admin_client.create_topics([new_topic])
    
    for topic, future in futures.items():
        try:
            future.result()  # Block until the topic is created
            print(f"✅ Topic '{topic}' created successfully!")
        except KafkaException as e:
            print(f"❌ Failed to create topic '{topic}': {e}")


def delete_topic(topic_name: str):
    """
    Delete a Kafka topic.
    
    Args:
        topic_name: Name of the topic to delete
    """
    admin_client = get_admin_client()
    
    futures = admin_client.delete_topics([topic_name])
    
    for topic, future in futures.items():
        try:
            future.result()  # Block until the topic is deleted
            print(f"✅ Topic '{topic}' deleted successfully!")
        except KafkaException as e:
            print(f"❌ Failed to delete topic '{topic}': {e}")


def purge_topic_messages(topic_name: str):
    """
    Delete all messages from a Kafka topic by deleting and recreating it.
    
    Note: Kafka doesn't support directly deleting messages. This function
    provides two approaches:
    1. Delete records up to high watermark (keeps topic config)
    2. Delete and recreate the topic (simple but loses custom config)
    
    Args:
        topic_name: Name of the topic to purge
    """
    admin_client = get_admin_client()
    
    try:
        # First, get topic metadata to find partitions
        metadata = admin_client.list_topics(topic=topic_name, timeout=10)
        
        if topic_name not in metadata.topics:
            print(f"❌ Topic '{topic_name}' not found.")
            return False
        
        topic_metadata = metadata.topics[topic_name]
        num_partitions = len(topic_metadata.partitions)
        
        print(f"\n🗑️  Purging messages from topic '{topic_name}'...")
        print(f"   Found {num_partitions} partition(s)")
        
        # Create a consumer to get high watermarks
        consumer_config = {
            "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
            "group.id": f"purge-consumer-{int(time.time())}",
            "auto.offset.reset": "earliest"
        }
        consumer = Consumer(consumer_config)
        
        # Get high watermark for each partition and delete records
        delete_records = {}
        
        for partition_id in topic_metadata.partitions.keys():
            tp = TopicPartition(topic_name, partition_id)
            low, high = consumer.get_watermark_offsets(tp, timeout=10)
            print(f"   Partition {partition_id}: offsets {low} -> {high} ({high - low} messages)")
            
            if high > 0:
                # Create TopicPartition with offset set to high watermark
                delete_records[tp] = high
        
        consumer.close()
        
        if not delete_records:
            print("\n📭 Topic is already empty, no messages to delete.")
            return True
        
        # Use delete_records API to delete all messages up to high watermark
        # This requires Kafka 0.11+ and confluent-kafka 1.4+
        try:
            # Create TopicPartition objects with the offset to delete up to
            partitions_to_delete = [
                TopicPartition(topic_name, tp.partition, offset)
                for tp, offset in delete_records.items()
            ]
            
            futures = admin_client.delete_records(partitions_to_delete)
            
            for tp, future in futures.items():
                try:
                    result = future.result()
                    print(f"   ✅ Partition {tp.partition}: deleted records up to offset {result.low_watermark}")
                except Exception as e:
                    print(f"   ❌ Partition {tp.partition}: failed to delete - {e}")
            
            print(f"\n✅ Successfully purged messages from topic '{topic_name}'!")
            return True
            
        except AttributeError:
            # Fallback: delete_records not available, use delete and recreate approach
            print("\n⚠️  delete_records API not available. Using delete and recreate approach...")
            
            # Get replication factor from first partition
            replication_factor = len(list(topic_metadata.partitions.values())[0].replicas)
            
            # Delete the topic
            futures = admin_client.delete_topics([topic_name])
            for topic, future in futures.items():
                future.result()
            
            print(f"   Topic '{topic_name}' deleted.")
            
            # Wait a moment for deletion to propagate
            time.sleep(2)
            
            # Recreate the topic with same configuration
            new_topic = NewTopic(
                topic=topic_name,
                num_partitions=num_partitions,
                replication_factor=replication_factor
            )
            
            futures = admin_client.create_topics([new_topic])
            for topic, future in futures.items():
                future.result()
            
            print(f"   Topic '{topic_name}' recreated with {num_partitions} partitions.")
            print(f"\n✅ Successfully purged messages from topic '{topic_name}'!")
            return True
            
    except KafkaException as e:
        print(f"❌ Failed to purge topic messages: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False


def list_topics():
    """List all available Kafka topics."""
    admin_client = get_admin_client()
    
    try:
        metadata = admin_client.list_topics(timeout=10)
        print("\n📋 Available Kafka Topics:")
        print("-" * 50)
        
        topics = sorted(metadata.topics.keys())
        if not topics:
            print("  No topics found.")
        else:
            for topic in topics:
                topic_metadata = metadata.topics[topic]
                num_partitions = len(topic_metadata.partitions)
                print(f"  • {topic} (partitions: {num_partitions})")
        
        print("-" * 50)
        print(f"Total: {len(topics)} topics\n")
        return topics
    except KafkaException as e:
        print(f"❌ Failed to list topics: {e}")
        return []


def get_topic_details(topic_name: str):
    """
    Get detailed information about a specific topic.
    
    Args:
        topic_name: Name of the topic to inspect
    """
    admin_client = get_admin_client()
    
    try:
        metadata = admin_client.list_topics(topic=topic_name, timeout=10)
        
        if topic_name not in metadata.topics:
            print(f"❌ Topic '{topic_name}' not found.")
            return None
        
        topic_metadata = metadata.topics[topic_name]
        print(f"\n📊 Topic Details: {topic_name}")
        print("-" * 50)
        print(f"  Partitions: {len(topic_metadata.partitions)}")
        
        for partition_id, partition in topic_metadata.partitions.items():
            print(f"    Partition {partition_id}:")
            print(f"      Leader: {partition.leader}")
            print(f"      Replicas: {partition.replicas}")
            print(f"      ISRs: {partition.isrs}")
        
        print("-" * 50)
        return topic_metadata
    except KafkaException as e:
        print(f"❌ Failed to get topic details: {e}")
        return None


def produce_message(topic_name: str, message: str, key: str = None):
    """
    Produce a single message to a Kafka topic.
    
    Args:
        topic_name: Name of the topic to produce to
        message: Message content (string or dict)
        key: Optional message key
    """
    producer_config = {
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
        "client.id": "test-producer"
    }
    
    producer = Producer(producer_config)
    
    def delivery_callback(err, msg):
        if err:
            print(f"❌ Message delivery failed: {err}")
        else:
            print(f"✅ Message delivered to {msg.topic()} [partition {msg.partition()}] at offset {msg.offset()}")
    
    try:
        # Convert dict to JSON string if needed
        if isinstance(message, dict):
            message = json.dumps(message)
        
        producer.produce(
            topic=topic_name,
            key=key.encode("utf-8") if key else None,
            value=message.encode("utf-8"),
            callback=delivery_callback
        )
        producer.flush(timeout=10)
        
    except Exception as e:
        print(f"❌ Failed to produce message: {e}")
    finally:
        producer.flush()


def produce_messages(topic_name: str, messages: list, keys: list = None):
    """
    Produce multiple messages to a Kafka topic.
    
    Args:
        topic_name: Name of the topic to produce to
        messages: List of messages (strings or dicts)
        keys: Optional list of message keys (must match length of messages)
    """
    producer_config = {
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
        "client.id": "test-producer"
    }
    
    producer = Producer(producer_config)
    delivered_count = 0
    failed_count = 0
    
    def delivery_callback(err, msg):
        nonlocal delivered_count, failed_count
        if err:
            failed_count += 1
            print(f"❌ Message delivery failed: {err}")
        else:
            delivered_count += 1
    
    try:
        for i, message in enumerate(messages):
            key = keys[i] if keys and i < len(keys) else None
            
            # Convert dict to JSON string if needed
            if isinstance(message, dict):
                message = json.dumps(message)
            
            producer.produce(
                topic=topic_name,
                key=key.encode("utf-8") if key else None,
                value=message.encode("utf-8"),
                callback=delivery_callback
            )
            
            # Poll to handle delivery reports periodically
            producer.poll(0)
        
        # Wait for all messages to be delivered
        producer.flush(timeout=30)
        
        print(f"\n📤 Message Production Summary:")
        print(f"  ✅ Delivered: {delivered_count}")
        print(f"  ❌ Failed: {failed_count}")
        
    except Exception as e:
        print(f"❌ Failed to produce messages: {e}")
    finally:
        producer.flush()


def consume_messages(topic_name: str, group_id: str = "test-consumer-group", 
                     timeout_seconds: int = 30, max_messages: int = None,
                     from_beginning: bool = True):
    """
    Consume messages from a Kafka topic.
    
    Args:
        topic_name: Name of the topic to consume from
        group_id: Consumer group ID
        timeout_seconds: Maximum time to wait for messages
        max_messages: Maximum number of messages to consume (None for unlimited)
        from_beginning: If True, start from the beginning of the topic
    """
    consumer_config = {
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
        "group.id": group_id,
        "client.id": "test-consumer",
        "auto.offset.reset": "earliest" if from_beginning else "latest",
        "enable.auto.commit": True,
        "session.timeout.ms": 6000
    }
    
    consumer = Consumer(consumer_config)
    
    try:
        consumer.subscribe([topic_name])
        print(f"\n🔄 Consuming messages from '{topic_name}'...")
        print(f"   (Timeout: {timeout_seconds}s, Max messages: {max_messages or 'unlimited'})")
        print("-" * 60)
        
        message_count = 0
        start_time = time.time()
        
        while True:
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed >= timeout_seconds:
                print(f"\n⏱️  Timeout reached ({timeout_seconds}s)")
                break
            
            # Check max messages
            if max_messages and message_count >= max_messages:
                print(f"\n📊 Max messages reached ({max_messages})")
                break
            
            # Poll for message
            msg = consumer.poll(timeout=1.0)
            
            if msg is None:
                continue
            
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    print(f"📭 End of partition reached: {msg.topic()} [{msg.partition()}]")
                    continue
                else:
                    raise KafkaException(msg.error())
            
            message_count += 1
            
            # Decode message
            key = msg.key().decode("utf-8") if msg.key() else None
            value = msg.value().decode("utf-8") if msg.value() else None
            
            # Try to parse JSON
            try:
                value_parsed = json.loads(value)
                value_display = json.dumps(value_parsed, indent=2)
            except (json.JSONDecodeError, TypeError):
                value_display = value
            
            print(f"\n📨 Message #{message_count}:")
            print(f"   Topic: {msg.topic()}")
            print(f"   Partition: {msg.partition()}")
            print(f"   Offset: {msg.offset()}")
            print(f"   Key: {key}")
            print(f"   Value: {value_display}")
            print(f"   Timestamp: {msg.timestamp()}")
        
        print("-" * 60)
        print(f"📊 Total messages consumed: {message_count}\n")
        return message_count
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Consumption interrupted by user.")
    except Exception as e:
        print(f"❌ Error consuming messages: {e}")
    finally:
        consumer.close()


def interactive_menu():
    """Display an interactive menu for Kafka operations."""
    while True:
        print("\n" + "=" * 60)
        print("🔷 KAFKA TESTING MENU 🔷")
        print("=" * 60)
        print("1. List all topics")
        print("2. Create a new topic")
        print("3. Delete a topic")
        print("4. Get topic details")
        print("5. Produce a message")
        print("6. Produce multiple test messages")
        print("7. Consume messages")
        print("8. Run full test (create topic, produce, consume)")
        print("9. Purge all messages from a topic")
        print("0. Exit")
        print("=" * 60)
        
        choice = input("Enter your choice: ").strip()
        
        if choice == "1":
            list_topics()
            
        elif choice == "2":
            topic_name = input("Enter topic name: ").strip()
            partitions = input("Number of partitions (default 1): ").strip()
            partitions = int(partitions) if partitions else 1
            create_topic(topic_name, num_partitions=partitions)
            
        elif choice == "3":
            topic_name = input("Enter topic name to delete: ").strip()
            confirm = input(f"Are you sure you want to delete '{topic_name}'? (yes/no): ").strip().lower()
            if confirm == "yes":
                delete_topic(topic_name)
            else:
                print("Deletion cancelled.")
                
        elif choice == "4":
            topic_name = input("Enter topic name: ").strip()
            get_topic_details(topic_name)
            
        elif choice == "5":
            topic_name = input("Enter topic name: ").strip()
            key = input("Enter message key (or press Enter for no key): ").strip() or None
            message = input("Enter message: ").strip()
            produce_message(topic_name, message, key)
            
        elif choice == "6":
            topic_name = input("Enter topic name: ").strip()
            count = input("Number of messages to produce (default 5): ").strip()
            count = int(count) if count else 5
            
            messages = [
                {"id": i, "message": f"Test message #{i}", "timestamp": time.time()}
                for i in range(1, count + 1)
            ]
            produce_messages(topic_name, messages)
            
        elif choice == "7":
            topic_name = input("Enter topic name: ").strip()
            timeout = input("Timeout in seconds (default 30): ").strip()
            timeout = int(timeout) if timeout else 30
            max_msgs = input("Max messages (press Enter for unlimited): ").strip()
            max_msgs = int(max_msgs) if max_msgs else None
            
            # Use a unique group ID to read from beginning
            group_id = f"test-consumer-{int(time.time())}"
            consume_messages(topic_name, group_id=group_id, timeout_seconds=timeout, 
                           max_messages=max_msgs, from_beginning=True)
            
        elif choice == "8":
            run_full_test()
        
        elif choice == "9":
            topic_name = input("Enter topic name to purge: ").strip()
            confirm = input(f"Are you sure you want to delete ALL messages from '{topic_name}'? (yes/no): ").strip().lower()
            if confirm == "yes":
                purge_topic_messages(topic_name)
            else:
                print("Purge cancelled.")
            
        elif choice == "0":
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please try again.")


def run_full_test():
    """Run a complete test of Kafka operations."""
    test_topic = f"test-topic-{int(time.time())}"
    
    print("\n" + "=" * 60)
    print("🧪 RUNNING FULL KAFKA TEST")
    print("=" * 60)
    
    # Step 1: List existing topics
    print("\n📌 Step 1: List existing topics")
    list_topics()
    
    # Step 2: Create a test topic
    print(f"\n📌 Step 2: Create test topic '{test_topic}'")
    create_topic(test_topic, num_partitions=2)
    time.sleep(1)  # Wait for topic to be fully created
    
    # Step 3: Verify topic was created
    print("\n📌 Step 3: Verify topic creation")
    list_topics()
    
    # Step 4: Produce messages
    print("\n📌 Step 4: Produce test messages")
    test_messages = [
        {"id": 1, "type": "info", "content": "This is the first test message"},
        {"id": 2, "type": "warning", "content": "This is the second test message"},
        {"id": 3, "type": "error", "content": "This is the third test message"},
        {"id": 4, "type": "debug", "content": "This is the fourth test message"},
        {"id": 5, "type": "info", "content": "This is the fifth test message"},
    ]
    produce_messages(test_topic, test_messages)
    
    # Step 5: Consume messages
    print("\n📌 Step 5: Consume messages")
    group_id = f"test-consumer-{int(time.time())}"
    consume_messages(test_topic, group_id=group_id, timeout_seconds=10, max_messages=10)
    
    # Step 6: Clean up (optional)
    print(f"\n📌 Step 6: Clean up")
    cleanup = input(f"Delete test topic '{test_topic}'? (yes/no): ").strip().lower()
    if cleanup == "yes":
        delete_topic(test_topic)
    else:
        print(f"Topic '{test_topic}' kept for further testing.")
    
    print("\n" + "=" * 60)
    print("✅ FULL KAFKA TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🚀 KAFKA TESTING SCRIPT")
    print(f"   Server: {KAFKA_BOOTSTRAP_SERVERS}")
    print("=" * 60)
    
    # Check for command-line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "list":
            list_topics()
        elif command == "create" and len(sys.argv) > 2:
            create_topic(sys.argv[2])
        elif command == "delete" and len(sys.argv) > 2:
            delete_topic(sys.argv[2])
        elif command == "produce" and len(sys.argv) > 3:
            produce_message(sys.argv[2], sys.argv[3])
        elif command == "consume" and len(sys.argv) > 2:
            consume_messages(sys.argv[2], timeout_seconds=30)
        elif command == "test":
            run_full_test()
        else:
            print("Usage:")
            print("  python test_kafka.py                    # Interactive menu")
            print("  python test_kafka.py list               # List topics")
            print("  python test_kafka.py create <topic>     # Create topic")
            print("  python test_kafka.py delete <topic>     # Delete topic")
            print("  python test_kafka.py produce <topic> <message>  # Produce message")
            print("  python test_kafka.py consume <topic>    # Consume messages")
            print("  python test_kafka.py test               # Run full test")
    else:
        # Run interactive menu
        interactive_menu()
