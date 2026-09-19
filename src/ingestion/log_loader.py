import os
import pandas as pd
import json

class LogLoader:
    """Loads raw security logs from CSV or JSON files."""

    @staticmethod
    def load_logs(file_path: str) -> pd.DataFrame:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")

        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".csv":
            df = pd.read_csv(file_path)
        elif ext == ".json":
            df = pd.read_json(file_path)
        elif ext == ".jsonl":
            df = pd.read_json(file_path, lines=True)
        else:
            raise ValueError(f"Unsupported log file extension: {ext}")

        return df
