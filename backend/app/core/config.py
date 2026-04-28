"""Sentinel-X Ultimate - Configuration."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "Sentinel-X Ultimate"
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"

    # Elasticsearch
    ELASTICSEARCH_URL: str = "http://localhost:9200"
    ELASTICSEARCH_INDEX_PREFIX: str = "sentinel"

    # Kafka
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_TOPIC_RAW_TRAFFIC: str = "raw-traffic"
    KAFKA_TOPIC_ALERTS: str = "alerts"
    KAFKA_TOPIC_THREAT_INTEL: str = "threat-intel"
    KAFKA_CONSUMER_GROUP: str = "sentinel-x"

    # ML Model paths
    ML_MODEL_DIR: str = "ml_models"
    BASELINE_MODEL_PATH: str = "ml_models/baseline_model.pt"
    PREDICTION_MODEL_PATH: str = "ml_models/prediction_model.pt"
    INTENT_MODEL_PATH: str = "ml_models/intent_model.pt"

    # Honeynet
    HONEYNET_SUBNET: str = "10.99.0.0/16"
    HONEYNET_MAX_INSTANCES: int = 50

    # Moving Target Defense
    MTD_ROTATION_INTERVAL_SECONDS: int = 300
    MTD_ENABLED: bool = True

    # Digital Twin
    DIGITAL_TWIN_SYNC_INTERVAL: int = 60

    # Red Team
    RED_TEAM_SIMULATION_INTERVAL: int = 3600
    RED_TEAM_MAX_CONCURRENT: int = 5

    # Threat Intelligence
    THREAT_INTEL_SYNC_INTERVAL: int = 900
    THREAT_INTEL_PEERS: list[str] = []

    # Identity
    IDENTITY_RISK_THRESHOLD: float = 0.75
    IDENTITY_LOCKOUT_THRESHOLD: float = 0.95

    # Genetic Algorithm
    GENETIC_POPULATION_SIZE: int = 100
    GENETIC_GENERATIONS: int = 50
    GENETIC_MUTATION_RATE: float = 0.1

    # Logging
    LOG_LEVEL: str = "INFO"

    model_config = {"env_prefix": "SENTINEL_"}


settings = Settings()
