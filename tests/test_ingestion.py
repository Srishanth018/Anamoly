import pytest
import os
from src.database.db_manager import DatabaseManager
from src.ingestion.api_ingestor import StreamLogIngestor

def test_stream_log_ingestor(tmp_path):
    db_file = os.path.join(tmp_path, "test_sec.db")
    db = DatabaseManager(db_path=str(db_file), force_reinit=True)
    
    ingestor = StreamLogIngestor(db_manager=db)
    
    payload = {
        "user_id": "U199",
        "source_ip": "192.168.1.50",
        "device_id": "DEV_TEST",
        "event_type": "LOGIN",
        "action": "LOGIN_SUCCESS",
        "bytes_transferred": 1000,
        "session_id": "S_TEST_101"
    }
    
    evt_id = ingestor.ingest_payload(payload)
    assert evt_id is not None
    
    res = db.run_query("SELECT * FROM events WHERE user_id = 'U199'")
    assert len(res) == 1
    assert res["source_ip"].iloc[0] == "192.168.1.50"
