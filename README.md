# TeleCrypt.io Controlplane

Public source for the Registration, Janitor and Plan services, plus the versioned Synapse policy
wheel. The public interfaces and package metadata are defined by the source and release assets.

The repository contains no payment credentials, billing migrations or populated runtime
configuration. See [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

## Pricing transition boundaries

Plan uses ordinary MAS OIDC and the signed private Cashier contract. It has no MAS-admin or
Synapse-admin credential, and exposes team membership, fixed plan state and billing links only.
Sponsor account lock and unlock actions are not part of Plan.

Janitor is a scheduled one-shot process. It uses MAS and Synapse admin APIs for account
lifecycle work, reads Dodo once with a read-only key, and emails discrepancy reports without
changing provider, membership or billing state. It has no HTTP service or Cashier token
exchange.

The Synapse policy reads the native local `user_type` (`wild`, `verified`, or
`uploads_blocked`) for upload and messaging decisions. Storage rooms are identified by the
fixed `m.room.power_levels` marker
`org.matrix.msc3089.branch = 100`; creation establishes one owner at level 100 and leaves
members as readers through the native power-level defaults.

The policy's media spam callback queues best-effort upload accounting to Cashier at the fixed
pod-local `http://127.0.0.1:9011/internal/cashier/file_upload_webhook`; media deletion sends
only its stable media ID to the corresponding private route. Notification failures are logged
and do not reject media operations.
