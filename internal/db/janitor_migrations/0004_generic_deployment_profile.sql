-- Keep historical audit rows while allowing deployments outside the original host names.
ALTER TABLE janitor.run_events
    DROP CONSTRAINT run_events_profile_check,
    ADD CONSTRAINT run_events_profile_check CHECK (
        server_name ~ '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
        AND billing_environment IN ('test', 'live')
    );
