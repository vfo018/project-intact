# intact-kafka-tools Helm Chart

This Helm chart deploys the Kafka-based prototype components for the INTACT predictive threat intelligence pipeline.

It packages the following components (containerized in one image and selected by `MODE`):

- **Mitigator** (`stix_mitigator.py`)
- **Attack Simulator** (`stix_attack_simulator.py`)
- **Response Consumer** (`response_consumer.py`)

These components communicate through Kafka topics using STIX 2.1 messages.

## Overview

The prototype demonstrates the following Kafka message flow:

1. **Attack Simulator** publishes simulated STIX attack bundles to the input topic.
2. **Mitigator** consumes STIX alerts from the input topic, selects a mitigation action, and publishes a response STIX bundle to the output topic.
3. **Response Consumer** listens to the response topic and prints received mitigation decisions for validation.

This chart is intended for integration testing and demo deployment in the INTACT environment.

## Prerequisites

Before installing this chart, ensure that the following are available:

- A Kubernetes cluster
- Helm v3+
- A Kafka broker reachable from the cluster
- Access to the container image registry (GHCR)

### Kafka requirement

This chart does **not** deploy Kafka. It expects an existing Kafka broker/service (for example, a Kafka instance already deployed by project partners).

## Container Image

Default image used by this chart:

- `ghcr.io/vfo018/intact-kafka-tools:0.1.0`

Update the image repository/tag in `values.yaml` if needed.

## Chart Structure

```text
intact-kafka-tools/
├── Chart.yaml
├── values.yaml
└── templates
    ├── _helpers.tpl
    ├── mitigator-deployment.yaml
    ├── attack-simulator-deployment.yaml
    └── response-consumer-deployment.yaml
