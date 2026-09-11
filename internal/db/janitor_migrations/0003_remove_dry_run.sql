-- New Janitor runs always mutate accounts. Keep dry_run and its historical constraints so
-- previous preview records remain auditable; only remove the profile coupling and default new
-- rows to false. The application does not expose a dry-run mode anymore.
ALTER TABLE janitor.run_events
    DROP CONSTRAINT run_events_dry_run_check,
    DROP CONSTRAINT run_events_state_check;

ALTER TABLE janitor.run_events
    ALTER COLUMN dry_run SET DEFAULT FALSE;

ALTER TABLE janitor.run_events
    ADD CONSTRAINT run_events_state_check CHECK (
        (
            event_kind = 'started' AND status = 'started' AND outcome = 'pending' AND reason = 'pending'
            AND notification_status = 'not_attempted'
            AND considered = 0 AND skipped = 0 AND locked_or_would_lock = 0 AND failures = 0
        )
        OR (
            event_kind = 'finished' AND status = 'succeeded' AND outcome = 'dry_run'
            AND billing_environment = 'test' AND dry_run AND failures = 0
            AND notification_status = 'not_attempted'
            AND (
                (reason = 'would_disable' AND locked_or_would_lock > 0)
                OR (reason = 'no_eligible_accounts' AND locked_or_would_lock = 0)
            )
        )
        OR (
            event_kind = 'finished' AND status = 'succeeded' AND outcome = 'success'
            AND NOT dry_run AND failures = 0
            AND (
                (reason = 'disabled' AND locked_or_would_lock > 0)
                OR (reason = 'no_eligible_accounts' AND locked_or_would_lock = 0)
            )
        )
        OR (
            event_kind = 'finished' AND status = 'failed' AND outcome = 'operational_failure'
            AND reason IN ('database', 'mas', 'entitlement_view', 'notification', 'audit', 'cancelled', 'lock', 'lock_readback')
            AND failures > 0
        )
    );
