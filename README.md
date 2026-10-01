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

## Private service endpoints

Janitor requires `MAS_ADMIN_URL` and `SYNAPSE_ADMIN_URL`. Plan requires
`MAS_INTERNAL_URL` for its ordinary OIDC calls and receives no administrative
credentials. Configure these URLs to the Matrix host's private ingress. The Synapse
module requires `cashier_internal_url` in its module configuration, pointing to
Cashier's private ingress. Per-service bearer credentials remain distinct.
Plan and Registration listen on all container interfaces; Salt publishes their
ports only on host loopback behind the private application ingress.

## Checks and releases

GitHub Actions runs the Go and policy checks on pull requests and pushes to
`main`. Pushing an annotated numeric `X.Y.Z` tag runs those checks, builds and
publishes the control-plane image to GHCR, smoke-tests the published image,
then creates a GitHub release containing the tested policy wheel and an image
digest binding. The workflow verifies the wheel checksum, tag object, and
source commit and serializes publication for each tag.

The checks can also run locally with `scripts/check.sh`. Install Go 1.26.4,
Python 3.12.14, and Docker; set `TEST_DATABASE_URL` to a disposable PostgreSQL
17 database. The script runs Go tests and vet, builds the policy wheel using
hash-pinned test requirements, then pulls the pinned Synapse image and tests
the wheel inside it. Generated wheel output stays in `dist/tier-controller`.

Publishing a component release does not deploy or promote an environment.
Salt Pillar selects the published image for deployment, and Salt SSH pulls it
on the target host; image builds run in GitHub Actions.
