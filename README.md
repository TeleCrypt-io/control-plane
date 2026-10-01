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

## Manual checks and releases

Releases are prepared by an operator from a clean checkout of a published,
annotated numeric `X.Y.Z` tag. Pushing a tag does not run a build or publish anything.
Run these commands on a build workstation, never on a deployment VM. Use one
operator at a time for a release tag.

Install Go 1.26.4, Git, Bash, jq, GitHub CLI, and Docker with Buildx. Authenticate
`gh` with access to this repository's releases and GHCR packages; `GH_TOKEN`
may provide the token instead. Release publication logs Docker into GHCR with
that token. Supply `TEST_DATABASE_URL` for a disposable PostgreSQL 17 database
owned by the test user (the former CI used PostgreSQL 17.11).
Python 3.12.14, venv/pip, curl, and GNU coreutils are also required. The check
builds the policy wheel using the hash-pinned test requirements and runs its tests
inside the pinned Synapse image. pip uses its ordinary download cache. Generated
wheel output stays in `dist/tier-controller`; temporary venvs are removed.

```sh
export TEST_DATABASE_URL='postgres://test_user:test_password@127.0.0.1:5432/telecrypt_test?sslmode=disable'
scripts/check.sh
# After creating/pushing the annotated release tag and checking it out:
scripts/release.sh X.Y.Z
```

`release.sh` reruns checks before publication. It preserves the image runtime
checks and the source commit, annotated tag, and image digest in the release
asset. Images remain pinned by digest in the server repository; a component
release does not deploy or promote an environment. Temporary publication files
are removed on exit; Docker's standard image/build cache remains available for
reuse and ordinary operator cleanup.
