"""SQLite storage for FUCO usage and job statistics."""

import logging
import math
import os
import sqlite3
import statistics
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Union

import config


logger = logging.getLogger(__name__)

EVENT_TYPES = frozenset(("ai", "analyzer", "responder"))
EVENT_FIELDS = frozenset(
    (
        "username",
        "status",
        "duration_ms",
        "analyzer_name",
        "responder_name",
        "data_type",
        "mode",
        "indicators_count",
        "reports_count",
        "ai_input_count",
        "provider_latency_ms",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "source",
    )
)
COUNT_FIELDS = frozenset(
    ("indicators_count", "reports_count", "ai_input_count",
     "input_tokens", "output_tokens", "total_tokens")
)
NUMBER_FIELDS = frozenset(("duration_ms", "provider_latency_ms"))

Timestamp = Union[datetime, str]


def _percentile(values, percentile):
    ordered = sorted(value for value in values if value is not None)
    if not ordered:
        return None
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def _event_summary(events):
    status_counts = defaultdict(int)
    durations = []
    indicators = 0
    for event in events:
        status = event["status"] or "Unknown"
        status_counts[status] += 1
        if event["duration_ms"] is not None:
            durations.append(event["duration_ms"])
        if event["indicators_count"] is not None:
            indicators += event["indicators_count"]

    success_count = status_counts["Success"]
    observed_count = len(events) - status_counts["Submitted"]
    return {
        "jobs": len(events),
        "success_count": success_count,
        "failure_count": status_counts["Failure"],
        "deleted_count": status_counts["Deleted"],
        "timeout_count": status_counts["Timeout"],
        "invalid_data_type_count": status_counts["Invalid data type"],
        "unobserved_count": status_counts["Submitted"],
        "observed_count": observed_count,
        "success_rate": (
            round(success_count * 100.0 / observed_count, 1)
            if observed_count else None
        ),
        "duration_median_ms": (
            statistics.median(durations) if durations else None
        ),
        "duration_p95_ms": _percentile(durations, 0.95),
        "indicators_processed": indicators,
    }


def _ranked_groups(events, name_field):
    groups = defaultdict(list)
    for event in events:
        name = event[name_field] or "Unknown"
        data_type = event["data_type"] or "unknown"
        groups[(data_type, name)].append(event)

    ranked = []
    for (data_type, name), group_events in groups.items():
        metrics = _event_summary(group_events)
        ranked.append({
            "name": name,
            "data_type": data_type,
            **metrics,
        })

    def used_key(item):
        return (-item["jobs"], item["data_type"], item["name"].casefold())

    return {
        "most_used": sorted(ranked, key=used_key)[:5],
        "least_used": sorted(
            ranked,
            key=lambda item: (
                item["jobs"], item["data_type"], item["name"].casefold()
            ),
        )[:5],
        "most_reliable": sorted(
            (item for item in ranked if item["success_rate"] is not None),
            key=lambda item: (
                -item["success_rate"], -item["jobs"], item["data_type"],
                item["name"].casefold(),
            ),
        )[:5],
        "least_reliable": sorted(
            (item for item in ranked if item["success_rate"] is not None),
            key=lambda item: (
                item["success_rate"], -item["jobs"], item["data_type"],
                item["name"].casefold(),
            ),
        )[:5],
    }


def record_event_safely(manager, event_type: str, **fields: object) -> Optional[int]:
    """Persist telemetry without changing the outcome of the measured operation."""
    if manager is None:
        return None
    try:
        return manager.record_event(event_type, **fields)
    except Exception:
        logger.exception("Unable to persist %s statistics event", event_type)
        return None


def update_event_safely(
    manager, event_type: str, job_id: str, **fields: object
) -> bool:
    """Update telemetry without changing the outcome of the measured operation."""
    if manager is None:
        return False
    try:
        return manager.update_event(event_type, job_id, **fields)
    except Exception:
        logger.exception(
            "Unable to update %s statistics event for job %s", event_type, job_id
        )
        return False


def duration_milliseconds(start, end) -> Optional[float]:
    """Convert Cortex start/end timestamps to a non-negative duration."""
    def parse(value):
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            try:
                seconds = value / 1000 if value > 100000000000 else value
                return datetime.fromtimestamp(seconds, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                return None
        if isinstance(value, str) and value:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                try:
                    return parse(float(value))
                except (ValueError, OverflowError, OSError):
                    return None
        return None

    start_at = parse(start)
    end_at = parse(end)
    if start_at is None or end_at is None:
        return None
    duration = (end_at - start_at).total_seconds() * 1000
    return duration if duration >= 0 else None


def _validate_event_type(event_type: str) -> None:
    if event_type not in EVENT_TYPES:
        raise ValueError("event_type must be one of: ai, analyzer, responder")


def _validate_fields(fields: Dict[str, object]) -> None:
    unknown_fields = set(fields) - EVENT_FIELDS
    if unknown_fields:
        names = ", ".join(sorted(unknown_fields))
        raise ValueError("Unsupported statistics field(s): {}".format(names))

    for name in COUNT_FIELDS.intersection(fields):
        value = fields[name]
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value < 0
        ):
            raise ValueError("{} must be a non-negative integer or None".format(name))

    for name in NUMBER_FIELDS.intersection(fields):
        value = fields[name]
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or value < 0
        ):
            raise ValueError("{} must be a non-negative number or None".format(name))

    for name, value in fields.items():
        if name not in COUNT_FIELDS and name not in NUMBER_FIELDS:
            if value is not None and not isinstance(value, str):
                raise ValueError("{} must be a string or None".format(name))


def _utc_timestamp(value: Timestamp) -> str:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Timestamp must be an ISO 8601 string") from exc
    if not isinstance(value, datetime):
        raise TypeError("Timestamp must be a datetime or ISO 8601 string")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


class StatisticsManager:
    """Create and query the statistics database without creating its directory."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        retention_days: Optional[int] = None,
    ) -> None:
        configured_path = config.STATS_DB_PATH if db_path is None else db_path
        self.db_path = os.fspath(configured_path)
        if not isinstance(self.db_path, str) or not self.db_path:
            raise ValueError("Statistics database path must be a non-empty string")

        configured_retention = (
            config.STATS_RETENTION_DAYS if retention_days is None else retention_days
        )
        self.retention_days = self._validate_retention_days(configured_retention)

    @staticmethod
    def _validate_retention_days(days: int) -> int:
        if isinstance(days, bool) or not isinstance(days, int) or days <= 0:
            raise ValueError("retention_days must be a positive integer")
        return days

    @contextmanager
    def _connection(self):
        connection = None
        try:
            connection = sqlite3.connect(self.db_path, timeout=30)
            connection.row_factory = sqlite3.Row
            yield connection
            connection.commit()
        except sqlite3.Error:
            if connection is not None:
                connection.rollback()
            logger.exception(
                "Statistics database operation failed for %s", self.db_path
            )
            raise
        finally:
            if connection is not None:
                connection.close()

    def initialize(self) -> None:
        """Create the event table and its indexes; existing data is preserved."""
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS statistics_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL
                        CHECK (event_type IN ('ai', 'analyzer', 'responder')),
                    job_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    username TEXT,
                    status TEXT,
                    duration_ms REAL,
                    analyzer_name TEXT,
                    responder_name TEXT,
                    data_type TEXT,
                    mode TEXT,
                    indicators_count INTEGER,
                    reports_count INTEGER,
                    ai_input_count INTEGER,
                    provider_latency_ms REAL,
                    input_tokens INTEGER,
                    output_tokens INTEGER,
                    total_tokens INTEGER,
                    source TEXT,
                    UNIQUE (event_type, job_id)
                );
                CREATE INDEX IF NOT EXISTS idx_statistics_events_created_at
                    ON statistics_events (created_at);
                CREATE INDEX IF NOT EXISTS idx_statistics_events_username
                    ON statistics_events (username);
                CREATE INDEX IF NOT EXISTS idx_statistics_events_event_type
                    ON statistics_events (event_type);
                CREATE INDEX IF NOT EXISTS idx_statistics_events_analyzer_name
                    ON statistics_events (analyzer_name);
                CREATE INDEX IF NOT EXISTS idx_statistics_events_responder_name
                    ON statistics_events (responder_name);
                """
            )

    def record_event(
        self,
        event_type: str,
        job_id: Optional[str] = None,
        **fields: object
    ) -> int:
        """Insert an event or return the existing ID for a duplicate job."""
        _validate_event_type(event_type)
        _validate_fields(fields)
        if job_id is not None and (not isinstance(job_id, str) or not job_id):
            raise ValueError("job_id must be a non-empty string or None")

        now = _utc_timestamp(datetime.now(timezone.utc))
        columns = ["event_type", "job_id", "created_at", "updated_at"]
        values: List[object] = [event_type, job_id, now, now]
        for field in sorted(fields):
            columns.append(field)
            values.append(fields[field])
        placeholders = ", ".join("?" for _ in columns)
        column_list = ", ".join(columns)

        with self._connection() as connection:
            cursor = connection.execute(
                "INSERT INTO statistics_events ({}) SELECT {} "
                "WHERE NOT EXISTS (SELECT 1 FROM statistics_events "
                "WHERE event_type = ? AND job_id = ?)".format(
                    column_list, placeholders
                ),
                values + [event_type, job_id],
            )
            if cursor.rowcount:
                return int(cursor.lastrowid)

            existing = connection.execute(
                "SELECT id FROM statistics_events "
                "WHERE event_type = ? AND job_id = ?",
                (event_type, job_id),
            ).fetchone()
            if existing is None:
                raise RuntimeError("Unable to retrieve the inserted statistics event")
            return int(existing["id"])

    def update_event(
        self, event_type: str, job_id: str, **fields: object
    ) -> bool:
        """Update an existing job event, returning whether a row was found."""
        _validate_event_type(event_type)
        _validate_fields(fields)
        if not isinstance(job_id, str) or not job_id:
            raise ValueError("job_id must be a non-empty string")
        if not fields:
            raise ValueError("At least one event field must be provided")

        assignments = ["{} = ?".format(field) for field in sorted(fields)]
        values = [fields[field] for field in sorted(fields)]
        assignments.append("updated_at = ?")
        values.extend(
            (_utc_timestamp(datetime.now(timezone.utc)), event_type, job_id)
        )
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE statistics_events SET {} "
                "WHERE event_type = ? AND job_id = ?".format(
                    ", ".join(assignments)
                ),
                values,
            )
            return cursor.rowcount > 0

    def aggregate_events(
        self,
        start_at: Optional[Timestamp] = None,
        end_at: Optional[Timestamp] = None,
        event_type: Optional[str] = None,
        username: Optional[str] = None,
    ) -> List[Dict[str, object]]:
        """Return aggregate counts and timings grouped by event type."""
        filters = []
        parameters: List[object] = []
        if start_at is not None:
            filters.append("created_at >= ?")
            parameters.append(_utc_timestamp(start_at))
        if end_at is not None:
            filters.append("created_at < ?")
            parameters.append(_utc_timestamp(end_at))
        if event_type is not None:
            _validate_event_type(event_type)
            filters.append("event_type = ?")
            parameters.append(event_type)
        if username is not None:
            filters.append("username = ?")
            parameters.append(username)

        where_clause = " WHERE " + " AND ".join(filters) if filters else ""
        query = """
            SELECT event_type,
                   COUNT(*) AS event_count,
                   SUM(CASE WHEN status = 'Success' THEN 1 ELSE 0 END)
                       AS success_count,
                   SUM(CASE WHEN status = 'Failure' THEN 1 ELSE 0 END)
                       AS failure_count,
                   SUM(CASE WHEN status = 'Timeout' THEN 1 ELSE 0 END)
                       AS timeout_count,
                   SUM(CASE WHEN status = 'Submitted' THEN 1 ELSE 0 END)
                       AS unobserved_count,
                   AVG(duration_ms) AS average_duration_ms,
                   AVG(provider_latency_ms) AS average_provider_latency_ms,
                   SUM(input_tokens) AS input_tokens,
                   SUM(output_tokens) AS output_tokens,
                   SUM(total_tokens) AS total_tokens
            FROM statistics_events
            {}
            GROUP BY event_type
            ORDER BY event_type
        """.format(where_clause)
        with self._connection() as connection:
            rows = connection.execute(query, parameters).fetchall()
            return [dict(row) for row in rows]

    def list_usernames(
        self,
        start_at: Optional[Timestamp] = None,
        end_at: Optional[Timestamp] = None,
    ) -> List[str]:
        """Return distinct non-empty usernames with events in the time range."""
        filters = ["username IS NOT NULL", "username != ''"]
        parameters: List[object] = []
        if start_at is not None:
            filters.append("created_at >= ?")
            parameters.append(_utc_timestamp(start_at))
        if end_at is not None:
            filters.append("created_at < ?")
            parameters.append(_utc_timestamp(end_at))

        with self._connection() as connection:
            rows = connection.execute(
                "SELECT DISTINCT username FROM statistics_events WHERE {} "
                "ORDER BY username".format(" AND ".join(filters)),
                parameters,
            ).fetchall()
            return [str(row["username"]) for row in rows]

    def dashboard_data(
        self,
        start_at: Optional[Timestamp] = None,
        end_at: Optional[Timestamp] = None,
        username: Optional[str] = None,
    ) -> Dict[str, object]:
        """Return privacy-safe dashboard aggregates for the selected scope."""
        filters = []
        parameters: List[object] = []
        if start_at is not None:
            filters.append("created_at >= ?")
            parameters.append(_utc_timestamp(start_at))
        if end_at is not None:
            filters.append("created_at < ?")
            parameters.append(_utc_timestamp(end_at))
        if username is not None:
            filters.append("username = ?")
            parameters.append(username)

        where_clause = " WHERE " + " AND ".join(filters) if filters else ""
        query = """
            SELECT created_at, event_type, status, duration_ms,
                   analyzer_name, responder_name, data_type, indicators_count,
                   reports_count, ai_input_count, provider_latency_ms,
                   input_tokens, output_tokens, total_tokens, source
            FROM statistics_events
            {}
            ORDER BY created_at
        """.format(where_clause)
        with self._connection() as connection:
            rows = connection.execute(query, parameters).fetchall()
            events = [dict(row) for row in rows]

        ai_events = [event for event in events if event["event_type"] == "ai"]
        analyzer_events = [
            event for event in events if event["event_type"] == "analyzer"
        ]
        responder_events = [
            event for event in events if event["event_type"] == "responder"
        ]
        daily = defaultdict(lambda: {
            "fresh": 0, "refresh": 0, "cache": 0, "failures": 0
        })
        for event in ai_events:
            day = event["created_at"][:10]
            source = event["source"] or "unknown"
            if source in ("fresh", "refresh", "cache"):
                daily[day][source] += 1
            if event["status"] == "Failure":
                daily[day]["failures"] += 1

        provider_latencies = [
            event["provider_latency_ms"] for event in ai_events
            if event["provider_latency_ms"] is not None
        ]
        ai_tokens = {}
        for token_field in ("input_tokens", "output_tokens", "total_tokens"):
            available = [
                event[token_field] for event in ai_events
                if event[token_field] is not None
            ]
            ai_tokens[token_field] = sum(available) if available else None

        return {
            "ai": {
                "assessments": len(ai_events),
                "success_count": sum(
                    event["status"] == "Success" for event in ai_events
                ),
                "failure_count": sum(
                    event["status"] == "Failure" for event in ai_events
                ),
                "fresh_count": sum(
                    event["source"] == "fresh" for event in ai_events
                ),
                "refresh_count": sum(
                    event["source"] == "refresh" for event in ai_events
                ),
                "cache_hit_count": sum(
                    event["source"] == "cache" for event in ai_events
                ),
                "provider_call_count": sum(
                    event["source"] in ("fresh", "refresh")
                    for event in ai_events
                ),
                "latency_median_ms": (
                    statistics.median(provider_latencies)
                    if provider_latencies else None
                ),
                "latency_p95_ms": _percentile(provider_latencies, 0.95),
                "indicators_count": sum(
                    event["indicators_count"] or 0 for event in ai_events
                ),
                "reports_count": sum(
                    event["reports_count"] or 0 for event in ai_events
                ),
                "ai_input_count": sum(
                    event["ai_input_count"] or 0 for event in ai_events
                ),
                "tokens": ai_tokens,
                "token_events": sum(
                    event["total_tokens"] is not None for event in ai_events
                ),
                "daily": [
                    {"date": day, **daily[day]} for day in sorted(daily)
                ],
            },
            "analyzer": {
                **_event_summary(analyzer_events),
                **_ranked_groups(analyzer_events, "analyzer_name"),
            },
            "responder": {
                **_event_summary(responder_events),
                **_ranked_groups(responder_events, "responder_name"),
            },
        }

    def cleanup(
        self,
        retention_days: Optional[int] = None,
        now: Optional[Timestamp] = None,
    ) -> int:
        """Delete events older than the configured retention window."""
        days = (
            self.retention_days
            if retention_days is None
            else self._validate_retention_days(retention_days)
        )
        current_time = (
            datetime.now(timezone.utc) if now is None else _utc_timestamp(now)
        )
        if isinstance(current_time, str):
            current_time = datetime.fromisoformat(current_time)
        cutoff = _utc_timestamp(current_time - timedelta(days=days))
        with self._connection() as connection:
            cursor = connection.execute(
                "DELETE FROM statistics_events WHERE created_at < ?", (cutoff,)
            )
            return cursor.rowcount
