"""
SQLite-backed alert storage using SQLAlchemy Core (no heavy ORM needed for
this scale). Stores every flow that any detector flagged, along with which
detector(s) flagged it, so the dashboard and the evaluation harness can
query a single source of truth.
"""

import datetime as dt
import json
import os

from sqlalchemy import (Column, DateTime, Float, Integer, MetaData, String,
                         Table, create_engine, insert, select)

from src.utils.config_loader import load_config
from src.utils.logger import get_logger

log = get_logger(__name__)

metadata = MetaData()

alerts_table = Table(
    "alerts", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("timestamp", DateTime, default=dt.datetime.utcnow),
    Column("flow_id", String),
    Column("src_ip", String),
    Column("dst_ip", String),
    Column("dst_port", Integer),
    Column("protocol", String),
    Column("detector", String),          # "signature" | "ml" | "llm"
    Column("verdict", String),           # benign | suspicious | malicious
    Column("severity", String),
    Column("confidence", Float),
    Column("technique", String),
    Column("mitre_id", String),
    Column("explanation", String),
    Column("recommended_action", String),
    Column("ground_truth_label", String),  # for evaluation only
    Column("raw_json", String),
)


class AlertStore:
    def __init__(self, db_path: str = None):
        cfg = load_config()
        path = db_path or cfg["_abs"](cfg["alerts"]["db_path"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.engine = create_engine(f"sqlite:///{path}")
        metadata.create_all(self.engine)
        log.info(f"Alert store initialized at {path}")

    def insert_alert(self, **kwargs):
        kwargs.setdefault("timestamp", dt.datetime.utcnow())
        if "raw_json" in kwargs and not isinstance(kwargs["raw_json"], str):
            kwargs["raw_json"] = json.dumps(kwargs["raw_json"])
        with self.engine.begin() as conn:
            conn.execute(insert(alerts_table).values(**kwargs))

    def fetch_recent(self, limit: int = 200):
        with self.engine.connect() as conn:
            result = conn.execute(
                select(alerts_table).order_by(alerts_table.c.id.desc()).limit(limit)
            )
            return [dict(row._mapping) for row in result]

    def fetch_by_detector(self, detector: str, limit: int = 500):
        with self.engine.connect() as conn:
            result = conn.execute(
                select(alerts_table)
                .where(alerts_table.c.detector == detector)
                .order_by(alerts_table.c.id.desc())
                .limit(limit)
            )
            return [dict(row._mapping) for row in result]

    def clear(self):
        with self.engine.begin() as conn:
            conn.execute(alerts_table.delete())
