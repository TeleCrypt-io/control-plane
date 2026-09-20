# TeleCrypt.io Controlplane

Public source for the Registration, Janitor and Plan services, plus the versioned Synapse policy
wheel. The public interfaces and package metadata are defined by the source and release assets.

The repository contains no payment credentials, billing migrations or populated runtime
configuration. See [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

## Pricing transition boundaries

Plan uses ordinary MAS OIDC and the signed private Cashier contract. It has no MAS-admin or
Synapse-admin credential, and exposes team membership, fixed plan state and billing links only.
Sponsor account lock and unlock actions are not part of Plan.
The four fixed checkout links and permanent billing portal URL are supplied through
`PLAN_BILLING_LINK_1` through `PLAN_BILLING_LINK_4` and `PLAN_BILLING_PORTAL_URL`; Plan renders them as ordinary HTTPS
links and never creates provider sessions.
Attached members have a self-service `/plan/members/leave` action. Plan verifies the caller is
present in Cashier's signed membership view and reuses the signed member-removal command;
Cashier is responsible for allowing only the caller's own membership and for enforcing that the
billing owner cannot leave while other members remain.

Janitor is a scheduled one-shot process. It uses MAS and Synapse admin APIs for account
lifecycle work, reads Dodo once with a read-only key, and emails discrepancy reports without
changing provider, membership or billing state. It has no HTTP service or Cashier token
exchange.

Cashier owns the lifecycle timestamps and exposes only due actions and narrow command functions
to Janitor. Janitor applies the approved 48-hour initial-Free suspension, 14-day departure
grace, 30-day initial-Free removal, and 90-day post-departure removal using those authoritative
actions. Paid entitlement restoration is immediate through Cashier's signed webhook projection;
Janitor never invents a second clock or calls Cashier over HTTP.
Operator MAS locks remain separate and are never cleared by this run.

The Synapse policy reads the native local `user_type` (`wild`, `verified`, or
`uploads_blocked`) for upload and messaging decisions. Storage rooms are identified by the
fixed `m.room.power_levels` marker
`org.matrix.msc3089.branch = 100`; creation establishes one owner at level 100 and leaves
members as readers through the native power-level defaults.

The policy's media spam callback queues best-effort upload accounting to Cashier at the fixed
pod-local `http://127.0.0.1:9011/internal/cashier/file_upload_webhook`; media deletion sends
only its stable media ID to the corresponding private route. Notification failures are logged
and do not reject media operations.
