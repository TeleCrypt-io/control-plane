# Controlplane internal packages

`internal/` contains implementation shared by the Controlplane executables. Go prevents an
unrelated repository from importing these packages. The public entry points are deliberately
small `main` packages in `cmd/`:

- `cmd/registration` serves `POST /agents` and provisions a newly registered user's Matrix agent.
- `cmd/janitor` is a one-shot, non-listening maintenance process.
- `cmd/plan` serves the authenticated account, plan, and subscription UI at `/plan`.

## Package responsibilities

| Package | Responsibility | Deliberate boundary |
| --- | --- | --- |
| `agent` | Coordinates Matrix-agent provisioning after a user registers. | No database or MAS-admin credential. |
| `config` | Loads and validates the narrowly scoped configuration of each executable. | Rejects incomplete or inconsistent runtime configuration. |
| `db` | Janitor's pre-created private schema and read-only access to Cashier's two Janitor views. | Does not create payments, subscriptions, or provider records. |
| `janitor` | Runs one database-locked sweep that finds stale unclaimed accounts, locks them through MAS, and sends the owner digest when mail is configured. It never unlocks an account; uncertain lock/readback outcomes fail the run. | No HTTP listener. |
| `masadmin` | MAS admin OAuth client used only by Janitor. It retains complete upstream response diagnostics after credential and identity redaction. | Never used by Registration or Plan. |
| `masreg` | MAS public registration, dynamic-client, and device-OAuth client used by Registration. It retains complete sanitized upstream response diagnostics internally. | Does not use MAS-admin authority or a client secret; public failures cross the HTTP boundary only as a finite stage/kind code. |
| `registrationhttp` | Registration request parsing and response shaping. | Public surface is limited to the registration endpoint. |
| `plan` | MAS OIDC, browser sessions, CSRF/origin checks, rendering, and signed Cashier commands. | Has no Dodo, Synapse-admin, or Postgres credential. |

Public topology, deployment-identity selection, and the Janitor database role contract are owned
by the root README. The private Cashier command details and Plan asset provenance are documented
with the `plan` package in `internal/plan/README.md`.

The Synapse `tier_controller` is intentionally not under `internal/`: it runs inside the external
Synapse process and is released as the separately installable `telecrypt-tier-controller` wheel.
