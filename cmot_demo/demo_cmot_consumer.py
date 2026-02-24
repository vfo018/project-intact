import json
from confluent_kafka import Consumer


# 1) Load knowledge base from JSON file
with open("cmot_knowledge_base.json", "r") as f:
    KB = json.load(f)


# --------- Helper functions: query the knowledge base ----------

def find_attack(kb, use_case):
    """Find the attack entry in 'attacks' matching the given use_case (e.g. 'UC1.5')."""
    for attack in kb.get("attacks", []):
        if attack.get("Use case") == use_case:
            return attack
    return None


def find_target_nic(attack, target_ip=None):
    """
    From attack['Linked_Nics'], find the NIC that matches target_ip if provided,
    otherwise return the first NIC entry.
    """
    nics = attack.get("Linked_Nics") or []
    if target_ip:
        for nic in nics:
            if nic.get("ip") == target_ip:
                return nic
    return nics[0] if nics else None


def find_topology_node(kb, node_name):
    """Find a node in the 'topology' section by its name (e.g. 'AMF', 'SMF', 'UPF')."""
    for topo in kb.get("topology", []):
        for node in topo.get("nodes", []):
            if node.get("name") == node_name:
                return node
    return None


def find_remediations(kb, use_case, node_name, max_results=3):
    """
    Find remediation entries applicable to the given use_case + node_name.

    The matrices in 'time', 'energy', 'Monetary_cost', and 'Risk_factor_reduction'
    are 2 x N:
      - row 0: UC2.* (vulnerabilities)
      - row 1: UC1.* (attacks)
    Column index is (UC number - 1), e.g. UC1.5 -> index 4.

    We select entries that:
      - link to this use_case in 'Linked_attack' or 'Linked_vulnerabilities'
      - AND contain this node_name in 'Linked_node'.

    Then we score and sort them by:
      - highest risk_reduction
      - then smallest time
      - then smallest cost
    """
    prefix, num_str = use_case.split(".")   # "UC1", "5"
    idx_num = int(num_str) - 1             # 0-based column index
    row_idx = 1 if prefix == "UC1" else 0  # row 1 for UC1.*, row 0 for UC2.*

    results = []

    for rem in kb.get("remediation", []):
        linked_attacks = rem.get("Linked_attack", [])
        linked_vulns = rem.get("Linked_vulnerabilities", [])

        if use_case not in linked_attacks and use_case not in linked_vulns:
            continue

        if node_name not in rem.get("Linked_node", []):
            continue

        def safe_get(matrix):
            try:
                return matrix[row_idx][idx_num]
            except Exception:
                return None

        t = safe_get(rem.get("time", []))
        e = safe_get(rem.get("energy", []))
        c = safe_get(rem.get("Monetary_cost", []))
        r = safe_get(rem.get("Risk_factor_reduction", []))

        results.append({
            "id": rem["id"],
            "short_description": rem["short_description"],
            "time": t,
            "energy": e,
            "cost": c,
            "risk_reduction": r,
        })

    # Sort by: higher risk_reduction first, then smaller time, then smaller cost
    results.sort(
        key=lambda x: (-(x["risk_reduction"] or 0),
                       x["time"] if x["time"] is not None else 999,
                       x["cost"] if x["cost"] is not None else 999)
    )

    return results[:max_results]


def explain_alert(alert, kb=KB):
    """
    Core function: take a single alert JSON (dict) and return a human-readable explanation.
    """
    use_case = alert.get("use_case") or alert.get("Use case")
    target_ip = alert.get("target_ip") or alert.get("dst_ip")

    if not use_case:
        return "❌ This alert does not contain a 'use_case' field, so it cannot be mapped."

    # 1) Look up the attack definition
    attack = find_attack(kb, use_case)
    if not attack:
        return f"❌ No attack definition found in the knowledge base for {use_case}."

    attack_name = attack.get("attack_name", "Unknown attack")

    # 2) Find which interface/IP is targeted
    nic = find_target_nic(attack, target_ip)
    linked_nodes = attack.get("Linked_node") or []

    node_name = None
    if linked_nodes:
        if len(linked_nodes) == 1:
            node_name = linked_nodes[0]
        else:
            # Simple heuristic: see if the NIC name contains the node name (AMF/SMF/UPF, etc.)
            if nic:
                nic_name = (nic.get("name") or "").lower()
                for ln in linked_nodes:
                    if ln.lower() in nic_name:
                        node_name = ln
                        break
        if not node_name:
            node_name = linked_nodes[0]

    if nic:
        where = f"{node_name} – interface {nic.get('name')} – IP {nic.get('ip')}"
    else:
        where = node_name or "Unknown node"

    # 3) Look up the topology node and its neighbours
    topo_node = find_topology_node(kb, node_name) if node_name else None
    neighbours = []
    if topo_node:
        for conn in topo_node.get("connections", []):
            neighbours.append(f"{conn['name']}({conn.get('NIC')})")

    # 4) Look up recommended remediation actions
    rems = find_remediations(kb, use_case, node_name) if node_name else []

    # 5) Build a human-readable explanation
    lines = []
    lines.append(f"⚠️ Detected use case {use_case}: {attack_name}")
    if target_ip:
        lines.append(f"   - Target IP from alert: {target_ip}")
    lines.append(f"   - Mapped 5G component / interface: {where}")
    if neighbours:
        lines.append("   - Directly connected components: " + ", ".join(neighbours))
    if rems:
        lines.append("   - Recommended remediation actions (sorted by risk reduction):")
        for r in rems:
            lines.append(
                f"     • {r['id']}: {r['short_description']} "
                f"(time={r['time']}, cost={r['cost']}, risk_reduction={r['risk_reduction']})"
            )
    else:
        lines.append("   - No suitable remediation entry found in the knowledge base.")

    return "\n".join(lines)


# --------- Kafka consumer main loop ----------

def main():
    """
    Start a Kafka consumer that listens on topic 'mmt-reports', parses each
    message as JSON, and prints an explanation based on the knowledge base.
    """
    conf = {
        # IMPORTANT: must be localhost because we are using kubectl port-forward
        "bootstrap.servers": "localhost:9092",
        "group.id": "cmot-dev",
        "auto.offset.reset": "latest",
    }

    consumer = Consumer(conf)
    consumer.subscribe(["mmt-reports"])
    print("Using Kafka bootstrap servers:", conf["bootstrap.servers"])

    print("✅ Started consuming from Kafka topic 'mmt-reports'...\n")

    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                print("Kafka Error:", msg.error())
                continue

            raw = msg.value().decode("utf-8")
            print("\n================ RAW MESSAGE ==================")
            print(raw)

            try:
                alert = json.loads(raw)
            except json.JSONDecodeError:
                print("❌ Message is not valid JSON, skipping.")
                continue

            print("\n================ EXPLANATION ==================")
            print(explain_alert(alert))
            print("================================================\n")

    except KeyboardInterrupt:
        print("⏹️ Keyboard interrupt received, stopping consumer...")

    finally:
        consumer.close()


if __name__ == "__main__":
    main()

