CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sysmon_event_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    event_data TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New',
    evidence TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (event_id)
        REFERENCES security_events(id)
);

-- Prevent duplicate real Sysmon events.
CREATE UNIQUE INDEX IF NOT EXISTS unique_sysmon_event
ON security_events (
    endpoint,
    json_extract(event_data, '$.System.Channel'),
    json_extract(event_data, '$.EventRecordID'),
    timestamp
)
WHERE json_extract(event_data, '$.EventRecordID') IS NOT NULL;

-- Store collection progress for each endpoint and channel.
CREATE TABLE IF NOT EXISTS collection_checkpoints (
    endpoint TEXT NOT NULL,
    channel TEXT NOT NULL,
    last_record_id INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY(endpoint, channel)
)