import sqlite3
import json
from datetime import datetime, timezone


class AuditLog:
    def __init__(self, db_path: str = "audit.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT NOT NULL,
                tool      TEXT NOT NULL,
                args      TEXT NOT NULL,
                approved  INTEGER NOT NULL,
                reason    TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def log(self, *, tool: str, args: dict, approved: bool, reason: str):
        self.conn.execute(
            "INSERT INTO events (ts, tool, args, approved, reason) VALUES (?,?,?,?,?)",
            (
                datetime.now(timezone.utc).isoformat(),
                tool,
                json.dumps(args),
                int(approved),
                reason,
            ),
        )
        self.conn.commit()

    def all_events(self) -> list[dict]:
        cursor = self.conn.execute(
            "SELECT ts, tool, args, approved, reason FROM events ORDER BY id"
        )
        return [
            {
                "ts": r[0],
                "tool": r[1],
                "args": json.loads(r[2]),
                "approved": bool(r[3]),
                "reason": r[4],
            }
            for r in cursor.fetchall()
        ]

    def clear(self):
        self.conn.execute("DELETE FROM events")
        self.conn.commit()
