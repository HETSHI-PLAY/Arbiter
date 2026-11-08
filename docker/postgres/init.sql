-- =============================================================================
-- Arbiter — PostgreSQL Schema Initialization Script
-- Supports Wazuh alert telemetry, incident investigation, and threat intelligence
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS wazuh;

CREATE TABLE IF NOT EXISTS wazuh.alerts (
    id BIGSERIAL PRIMARY KEY,
    alert_id TEXT NOT NULL DEFAULT '',
    timestamp TEXT,
    tenant TEXT NOT NULL DEFAULT 'Default',
    agent_name TEXT,
    agent_ip TEXT,
    rule_id TEXT,
    rule_level INTEGER,
    description TEXT NOT NULL DEFAULT '',
    rule_groups JSONB NOT NULL DEFAULT '[]',
    decoder TEXT,
    location TEXT,
    source_ip TEXT,
    mitre_ids JSONB NOT NULL DEFAULT '[]',
    cve TEXT,
    data JSONB NOT NULL DEFAULT '{}',
    raw JSONB NOT NULL,
    log_signature TEXT DEFAULT '',
    hit_count INTEGER DEFAULT 1,
    first_seen TEXT,
    last_seen TEXT,
    wazuh_ids JSONB DEFAULT '[]',
    duplicate_instances JSONB DEFAULT '[]',
    parsed_details JSONB DEFAULT '{}',
    is_reviewed BOOLEAN NOT NULL DEFAULT false,
    reviewed_at TIMESTAMPTZ,
    reviewer_notes TEXT DEFAULT '',
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(alert_id, timestamp, agent_name, rule_id)
);

CREATE TABLE IF NOT EXISTS wazuh.analysis_groups (
    id UUID PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    analysis TEXT NOT NULL DEFAULT '',
    conclusion TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    severity TEXT NOT NULL DEFAULT 'medium',
    source TEXT NOT NULL DEFAULT 'human',
    verdict TEXT NOT NULL DEFAULT 'needs_review',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS wazuh.alert_group_members (
    alert_pk BIGINT REFERENCES wazuh.alerts(id) ON DELETE CASCADE,
    group_id UUID REFERENCES wazuh.analysis_groups(id) ON DELETE CASCADE,
    PRIMARY KEY(alert_pk, group_id)
);

-- Fallback mock table for public.ip_intel_cache so open-source users without IP Intel don't crash
CREATE TABLE IF NOT EXISTS public.ip_intel_cache (
    ip TEXT PRIMARY KEY,
    abuse_score INTEGER,
    vt_malicious INTEGER,
    country_code TEXT,
    isp TEXT,
    attack_types TEXT[] DEFAULT '{}',
    total_alert_count INTEGER DEFAULT 1,
    last_seen TIMESTAMPTZ DEFAULT now()
);

-- Performance indices
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_source_ip ON wazuh.alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_rule_id ON wazuh.alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_timestamp ON wazuh.alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_tenant ON wazuh.alerts(tenant);
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_sig ON wazuh.alerts(tenant, log_signature);
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_reviewed ON wazuh.alerts(is_reviewed);
-- Scoped stats and triage performance indices
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_tenant_timestamp ON wazuh.alerts(tenant, timestamp);
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_rule_level ON wazuh.alerts(rule_level);
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_agent_name ON wazuh.alerts(agent_name);
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_status ON wazuh.alerts((parsed_details->>'status'));
-- Note: highly-cardinal user_agent, url_path, referer, and arbitrary text pattern
-- dimensions intentionally do not carry broad btree indexes to prevent bloat on high-volume ingest.
