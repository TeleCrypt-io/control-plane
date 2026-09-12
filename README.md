# TeleCrypt.io Controlplane

Public source for the non-payment control-plane components of a TeleCrypt Matrix deployment:

Current TeleCrypt project facts and decisions are maintained only in the canonical
[`llms.txt`](https://telecrypt.io/llms.txt); this README documents the components implemented here.

- `registration` provisions Matrix agent accounts without holding a database connection.
- `janitor` runs a single-flight sweep that locks stale accounts and, when mail is configured, sends owner digests. It never unlocks accounts and reads only the two Cashier-owned Janitor views.
- `plan` is the browser-facing account and plan-management UI at the stable `/plan` URL. It uses MAS OIDC and a narrow signed private Cashier API.
- `synapse/tier_controller` is the fail-closed Synapse capability-policy module.

Cashier, Dodo integration, subscription records, payment-provider credentials, and database migrations for billing are private to the `cashier` repository. This public image contains no Cashier binary or payment-provider SDK.

## Release contract

Every source version uses an exact annotated tag. GitHub Actions tests the source and, only for a
new tag, publishes two distinct artifact types. The tag is the deployment coordinate; immutable
GitHub Release asset evidence binds the published release contents.

- The Go services are released only as `ghcr.io/telecrypt-io/controlplane:<release>`. The image
  contains Registration, Janitor, and Plan; no executable archives are attached to GitHub Releases.
- The GitHub Release, titled exactly `<release>`, contains exactly the
  `telecrypt_tier_controller-<release>-py3-none-any.whl` and the canonical
  `controlplane-<release>.digest.json` image-binding asset. License and notice files remain
  inside the tested wheel; they are not separate release assets. This is the public distribution
  channel for the Synapse module and its provenance record.

The image carries the project `LICENSE` and `NOTICE`. The wheel carries the project license and
notice in its metadata; it has no runtime third-party Python dependencies.

The wheel version must equal the source/image tag. The standalone `telecrypt-synapse` repository
selects an exact wheel when adopting tier-controller changes. A Go-service-only release does not
require rebuilding Synapse or changing its selected wheel. The shared tag is the exact cross-repository release coordinate, not a claim that
the GitHub Release distributes the Go services. Deployment
configuration, credentials, operating procedures, and production acceptance material remain
private in Harness.

The Go image builder resolves the exact modules recorded in `go.mod` and `go.sum`. One BuildKit
graph exports both the tested local archive and a run-scoped GHCR staging reference; the archive is
loaded and smoke-tested before the version tag is created from the exact verified full-manifest digest.
The release workflow records that digest, source commit, and annotated tag object in the canonical
JSON asset. The resulting GitHub Release is immutable and covers the published tag and its two
release assets. The workflow proves that a version tag is absent before creating it and refuses
every pre-existing exact version tag; an existing exact immutable Release is reused only as a
complete, independently verified release.

## Repository layout

- `cmd/` contains the minimal `main` packages for the three independently deployed processes:
  Registration, Janitor, and Plan.
- `internal/` contains their shared Go implementation. Go deliberately prevents packages below
  `internal/` from being imported by unrelated repositories.
- `synapse/tier_controller/` contains the public Python package released as the exact wheel for
  `telecrypt-synapse`; it is not copied into the Controlplane container image.

## Browser service boundary

Plan owns the public `/plan` URL, MAS PKCE/OIDC, browser cookies, Origin protection, local MXID
validation, and the plan UI. Paying owners can manually lock/unlock members of their own team;
Plan verifies the active plan and seat through Cashier, then uses the existing MAS admin client
credential (`MAS_ADMIN_CLIENT_ID` / `MAS_ADMIN_CLIENT_SECRET`) for the account action. It has no Dodo, Synapse-admin, or Postgres credentials. Commands are
signed to the private Cashier service, which alone handles checkout, payment webhooks, entitlement
mutation, and Dodo customer portal links.

The two test profiles, `telecrypt.io` with `BILLING_ENVIRONMENT=test` during the temporary
pre-launch acceptance and `stage.telecrypt.io` with `BILLING_ENVIRONMENT=test` on the isolated
stage environment, visibly render `TEST / SANDBOX — no real charges` on every
Plan page. The later `telecrypt.io` with `BILLING_ENVIRONMENT=live` profile never renders that
banner. Payment card data is entered only on the Dodo-hosted checkout or customer-portal page,
never at TeleCrypt.

Plan and Janitor accept exactly these three frozen profiles:

| `SERVER_NAME` | `BILLING_ENVIRONMENT` | Use |
| --- | --- | --- |
| `telecrypt.io` | `test` | Temporary v1 acceptance on the production public surface |
| `stage.telecrypt.io` | `test` | Isolated test environment |
| `telecrypt.io` | `live` | Final launched production |

`SERVER_NAME` owns public, Matrix, and database topology. `BILLING_ENVIRONMENT` is an explicit
nonsecret input for Plan and Janitor and selects test/live behavior; neither value is inferred from
credentials or the other field. Every other server-name, billing-environment, or pair is rejected.
The public MAS, Registration, and Plan URLs are derived as `/auth`, `/agents`, and `/plan` on the
backend origin: `https://backend.telecrypt.io` for the production public surface and
`https://backend.stage.telecrypt.io` for the stage profile. Registration is topology-only;
Plan and Janitor perform the exact frozen-profile check before billing-sensitive behavior.

Janitor excludes the fixed `@cashier:<SERVER_NAME>` service account used by Cashier's
`SYNAPSE_ADMIN_TOKEN`. Other accounts receive the normal eligibility checks.

Janitor runs one single-flight sweep per invocation and reads Cashier-owned entitlement and identity views through
`JANITOR_DB_URL`, using a separate database credential from Cashier's `CASHIER_DB_URL`. The
URL must use the exact profile database and Janitor role: `telecrypt.io` uses
`telecrypt_billing` with `telecrypt_janitor_user`, while `stage.telecrypt.io` uses
`stage_telecrypt_billing` with `stage_telecrypt_janitor_user`. No other host label is an active
billing profile. The Janitor role is owner-precreated for the private
`janitor` schema, is read-only on Cashier's private `cashier` schema, and has schema-owner DDL
authority (including CREATE, ALTER, and DROP) only within that private `janitor` schema so the
one-shot can apply its exact migration. The application writes only its own
`janitor_digest_cursor`, `run_events`, and `schema_migrations` tables; PUBLIC and other roles must have no ACL on
the Janitor schema. Cashier's billing migration history remains private to the Cashier repository.
Cashier grants it schema usage and read access to only the
`janitor_deployment_identity` and `janitor_lock_exclusions` views.
The private `cashier` schema and both read-side views must remain owned by the exact profile Cashier role
(`telecrypt_cashier_user` for `telecrypt.io` or `stage_telecrypt_cashier_user` for
`stage.telecrypt.io`);
Cashier durably binds both `SERVER_NAME` and the explicit billing environment (`live` or `test`) in
that identity row. Janitor rejects any server or billing-environment drift before it can sweep.

Supported migration histories upgrade forward in order. Unknown or incompatible history needs
operator diagnosis before migration continues; no backward migration path is provided.

## Registration credential contract

`POST /agents` is the public, rate-limited component for creating an agent account. It
uses only MAS's public password-registration forms, dynamic registration of a public native OAuth
client (`token_endpoint_auth_method: none`), and MAS's device-authorization pages through the
new account's short-lived cookie session. It never receives a MAS/Synapse admin credential, a
personal access token, or a static OAuth client secret, and it never uses Matrix
`m.login.password`.

The one response contains the MXID, generated MAS password, access/refresh tokens, expiry,
device ID, homeserver, and `issuer`/`client_id`/`token_endpoint` needed to refresh directly with
MAS. The password is a recovery credential; agents should use the refresh token. Registration stores
none of those values, logs no credential-exchange details, and sends `Cache-Control: no-store`.
The fixed in-process limiter allows 60 registration attempts per 60-second window per instance. It
is a global backstop; client-facing fairness and any per-client controls belong at the
Caddy/network boundary.

## Development

Requires Go `1.26.4`.

```sh
go test ./...
go vet ./...
```

Run database-backed tests only against an isolated disposable database. Do not commit credentials, database URLs, signing keys, payment-provider keys, or live account data.

The opt-in MAS integration test creates a throwaway account, OAuth client, and device. Run it
only against an isolated disposable MAS/Synapse stack on the local machine. The test accepts only
HTTP loopback URLs on the same origin, with MAS mounted at `/auth` and the Matrix origin at `/`.
The explicit confirmation variable is required so the test cannot be enabled by accident:

```sh
MASREG_INTEGRATION_DISPOSABLE=YES \
MASREG_INTEGRATION_MAS_BASE_URL=http://127.0.0.1:8008/auth \
MASREG_INTEGRATION_MATRIX_ORIGIN=http://127.0.0.1:8008 \
go test -tags=integration ./internal/masreg -run '^TestRegisterAndAuthorizeDeviceDisposableMAS$' -count=1
```

Never point these variables at `telecrypt.io`, `stage.telecrypt.io`, or a shared test environment.
The generated account, client, device, password, and tokens are disposable test data and must not
be retained.

## License

Copyright © 2026 TeleCrypt.io. This work is licensed under the Business Source License 1.1; see [LICENSE](LICENSE).
