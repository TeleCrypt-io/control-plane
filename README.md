# TeleCrypt.io Controlplane

Public source for the Registration, Janitor and Plan services, plus the versioned Synapse policy
wheel. The public interfaces and package metadata are defined by the source and release assets.

The repository contains no payment credentials, billing migrations or populated runtime
configuration. See [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

## Pricing transition boundaries

Plan uses ordinary MAS OIDC and its own bearer credential for the private Cashier contract. It
has no MAS-admin or Synapse-admin credential, and exposes team membership, fixed plan state and
billing links only. Plan, Janitor, and Synapse receive distinct Cashier credentials; each process
must receive only its own credential.
Sponsor account lock and unlock actions are not part of Plan.
The four fixed checkout links and permanent billing portal URL are supplied through
`PLAN_BILLING_LINK_1` through `PLAN_BILLING_LINK_4` and `PLAN_BILLING_PORTAL_URL`; Plan renders them as ordinary HTTPS
links and never creates provider sessions.
Attached members have a self-service `/plan/members/leave` action. Plan verifies the caller is
present in Cashier's membership view and reuses the member-removal command;
Cashier is responsible for allowing only the caller's own membership and for enforcing that the
billing owner cannot leave while other members remain.

Janitor is a scheduled one-shot process. It uses MAS and Synapse admin APIs for account
lifecycle work, its own bearer credential for Cashier's narrow lifecycle/reporting API, reads
Dodo once with a read-only key, and emails discrepancy reports without changing provider,
membership or billing state. It has no HTTP service or Cashier token exchange.

Cashier owns the lifecycle timestamps and exposes only due actions and narrow command functions
to Janitor. The approved lifecycle rule is suspension after 48 hours for never-paid new accounts,
14 days of former-plan benefits after any loss of paid access including successful refunds, then
suspension, with removal eligibility after 90 days continuously suspended for every unpaid
account. The updated policy is being implemented in Cashier; Janitor executes Cashier's
authoritative due actions and does not invent a second clock. Paid entitlement restoration is
projected by Cashier's verified provider webhook. Operator MAS locks remain separate and are
never cleared by this run.

The Synapse policy reads the native local `user_type` (`wild`, `verified`, or
`uploads_blocked`) for upload and messaging decisions. Storage rooms are identified by the
fixed `m.room.power_levels` marker
`org.matrix.msc3089.branch = 100`; creation establishes one owner at level 100 and leaves
members as readers through the native power-level defaults.

The policy sends media accounting to Cashier with its own bearer credential at the private
`/internal/cashier/file_upload_webhook` and `/internal/cashier/file_delete_webhook` routes.
Notifications happen after the media operation commits: failures are logged, do not reject or
roll back that operation, and may leave usage accounting temporarily behind.
