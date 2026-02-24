from confluent_kafka import Consumer

conf = {
    "bootstrap.servers": "kafka:9092",   # 在集群内部访问 Kafka
    "group.id": "cmot-dev",
    "auto.offset.reset": "latest",
}

consumer = Consumer(conf)
consumer.subscribe(["mmt-reports"])

print("Start consuming from topic 'mmt-reports'...")
while True:
    msg = consumer.poll(1.0)
    if msg is None:
        continue
    if msg.error():
        print("Error:", msg.error())
        continue
    print("Got message:", msg.value().decode("utf-8"))

