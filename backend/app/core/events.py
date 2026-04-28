"""Application lifecycle events."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.app.core.config import settings

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    logger.info("Starting %s v%s", settings.PROJECT_NAME, settings.VERSION)
    # Startup: initialize services, load ML models, connect to Kafka/ES
    app.state.services_ready = True
    yield
    # Shutdown: graceful cleanup
    logger.info("Shutting down %s", settings.PROJECT_NAME)
