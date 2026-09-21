-- Janitor keeps only the email cursor. Run-event rows were an application audit ledger,
-- duplicating ordinary service logs without serving lifecycle behavior.
DROP TABLE IF EXISTS janitor.run_events;
