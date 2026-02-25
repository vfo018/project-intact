# project-intact

This repository contains integration scripts, deployment assets, and prototype components used for the INTACT project experiments and demonstrations.

## Repository structure

- `kafka/`  
  Kafka-based STIX message simulation, mitigation decision engine, response consumers, and deployment assets.

- `kafka/deploy/app/`  
  Docker build context for the Python-based Kafka tools image (simulator / mitigator / consumers).

- `kafka/deploy/helm/intact-kafka-tools/`  
  Helm chart for deploying the Kafka tools components on Kubernetes:
  - mitigator
  - attack simulator
  - response consumer

- `ubitech/k8s/`  
  UBITECH-related Kubernetes manifests / Helm chart resources used in the INTACT integration context.

- `test/`  
  Test scripts and experimental utilities.

## Main deliverable in this repository

The current deployment package for the predictive threat intelligence prototype is located at:

`kafka/deploy/helm/intact-kafka-tools/`

Please refer to the README inside that directory for deployment and configuration details.

## Container image

The Kafka tools container image is published to GitHub Container Registry (GHCR).  
The image reference used by the Helm chart can be configured in:

`kafka/deploy/helm/intact-kafka-tools/values.yaml`

## Notes

This repository includes prototype and integration code used for demonstration and validation purposes.  
Configuration values (Kafka bootstrap servers, topics, modes, etc.) should be adjusted to match the target environment before deployment.
