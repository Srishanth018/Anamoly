import json
import uuid
import pandas as pd
from datetime import datetime
from src.ingestion.log_normalizer import LogNormalizer
from src.database.db_manager import DatabaseManager

class StreamLogIngestor:
    """Ingests single or batch JSON telemetry payloads in real-time into the detection pipeline."""

    def __init__(self, db_manager: DatabaseManager = None):
        self.db = db_manager or DatabaseManager()

    def ingest_payload(self, payload: dict) -> str:
        """Normalizes and persists a real-time event JSON payload into SQLite events table."""
        if "event_id" not in payload or not payload["event_id"]:
            payload["event_id"] = f"EVT_{uuid.uuid4().hex[:10].upper()}"

        if "timestamp" not in payload or not payload["timestamp"]:
            payload["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        df = pd.DataFrame([payload])
        norm_df = LogNormalizer.normalize(df)

        self.db.insert_events(norm_df)
        return norm_df["event_id"].iloc[0]
