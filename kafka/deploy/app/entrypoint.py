import os
import runpy
import sys

def main():
    mode = os.getenv("MODE", "mitigator").strip().lower()

    mapping = {
        "mitigator": "stix_mitigator.py",
        "attack_simulator": "stix_attack_simulator.py",
        "response_consumer": "response_consumer.py",
        "test_consumer": "test_consumer.py",
        "test_consumer_v2": "test_consumer_v2.py",
        "test_producer": "test_producer.py",
        "test_kafka": "test_kafka.py",
    }

    script = mapping.get(mode)
    if not script:
        print(f"[ERR] Unknown MODE={mode}. Valid: {', '.join(mapping.keys())}")
        sys.exit(2)

    print(f"[+] MODE={mode} -> running {script}")
    runpy.run_path(script, run_name="__main__")

if __name__ == "__main__":
    main()
