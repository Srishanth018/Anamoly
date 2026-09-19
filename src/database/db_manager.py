import os
import sqlite3
import pandas as pd
import json

class DatabaseManager:
    """Manages SQLite database connections, schema initialization, and data insertion/retrieval."""

    def __init__(self, db_path: str = "database/security.db", schema_path: str = "database/schema.sql", force_reinit: bool = False):
        self.db_path = db_path
        self.schema_path = schema_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db(force=force_reinit)

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self, force: bool = False):
        """Initializes database schema from schema.sql if database does not exist or if force is True."""
        db_exists = os.path.exists(self.db_path) and os.path.getsize(self.db_path) > 0
        if not db_exists or force:
            if os.path.exists(self.schema_path):
                with open(self.schema_path, "r") as f:
                    schema_sql = f.read()
                with self.get_connection() as conn:
                    conn.executescript(schema_sql)
                    conn.commit()

    def insert_users(self, users_df: pd.DataFrame):
        with self.get_connection() as conn:
            users_df.to_sql("users", conn, if_exists="replace", index=False)

    def insert_devices(self, devices_df: pd.DataFrame):
        with self.get_connection() as conn:
            devices_df.to_sql("devices", conn, if_exists="replace", index=False)

    def insert_events(self, events_df: pd.DataFrame):
        with self.get_connection() as conn:
            # Ensure timestamps are strings/ISO formatted
            df = events_df.copy()
            if "timestamp" in df.columns:
                df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
            df.to_sql("events", conn, if_exists="append", index=False)

    def insert_sessions(self, sessions_df: pd.DataFrame):
        with self.get_connection() as conn:
            df = sessions_df.copy()
            for col in ["start_time", "end_time"]:
                if col in df.columns:
                    df[col] = pd.to_datetime(df[col]).dt.strftime("%Y-%m-%d %H:%M:%S")
            df.to_sql("sessions", conn, if_exists="append", index=False)

    def insert_baselines(self, baselines_df: pd.DataFrame):
        with self.get_connection() as conn:
            baselines_df.to_sql("baselines", conn, if_exists="replace", index=False)

    def insert_alerts(self, alerts_df: pd.DataFrame):
        with self.get_connection() as conn:
            df = alerts_df.copy()
            if "timestamp" in df.columns:
                df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
            # Convert list/dict columns to json string if necessary
            for col in ["reasons_json", "mitre_techniques_json"]:
                if col in df.columns:
                    df[col] = df[col].apply(lambda x: json.dumps(x) if isinstance(x, (list, dict)) else str(x))
            df.to_sql("alerts", conn, if_exists="append", index=False)

    def run_query(self, query: str, params: tuple = ()) -> pd.DataFrame:
        with self.get_connection() as conn:
            return pd.read_sql_query(query, conn, params=params)

    def execute(self, query: str, params: tuple = ()):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor

    def update_alert_status(self, alert_id: str, new_status: str):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (new_status, alert_id))
            conn.commit()
            return cursor.rowcount
