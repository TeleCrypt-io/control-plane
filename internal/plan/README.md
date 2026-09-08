# Plan service boundary

`internal/plan` is the deployed public, browser-facing owner of `/plan`. It owns MAS OIDC,
browser sessions, origin/CSRF protection, rendering, and the user-facing plan, seat, checkout,
and billing-portal actions. MAS embeds this stable URL in its account-management iframe through
`plan_management_iframe_uri`; it also works as a standalone page.

It must not receive Dodo credentials, Dodo webhook secrets, Synapse-admin credentials, or a
billing database URL.  It calls the private Cashier only through `CashierClient`.

Plan's browser API is rooted at `/api/plan`; `/api/team*` routes are not exposed. The
current public boundary must preserve this contract: successful plan and seat-state mutations at
`/api/plan*` return HTTP 204 with an empty body; checkout and portal actions return HTTP 200 JSON
containing their payment or portal link; structured plan reads also remain HTTP 200 JSON. The MAS
callback remains `/plan/callback`, but malformed, expired, and foreign-server sessions are rejected
rather than being migrated implicitly.

## Intended private protocol

Cashier exposes an internal-only versioned API corresponding exactly to `CashierClient`. The
internal team-domain paths are private protocol names and are not public Plan terminology:

- `GET /internal/v1/plan-state`
- `POST /internal/v1/teams`
- `POST /internal/v1/team/seats`
- `DELETE /internal/v1/team/seats/{mxid}`
- `POST /internal/v1/team/checkout`
- `POST /internal/v1/team/portal`
- `POST /internal/v1/team/seat-count`

Plan signs a short-lived EdDSA compact JWS with exactly `sub`, `aud`, `exp`, `method`, `path`,
`request_id`, and `body_sha256` claims. `path` is the exact escaped request path sent on the wire
(including percent-encoding for a seat MXID); `body_sha256` is the raw URL-safe-base64 SHA-256 of
the exact request bytes. Plan serializes once, signs those bytes, and sends those same bytes.
Commands additionally send `X-TeleCrypt-Request-ID` equal to `request_id`; plan-state uses a
generated request identifier but needs no header. Cashier verifies the assertion, uses its own
plan ownership lookup, and persists idempotency for money-affecting commands. The endpoint is
reachable only on the private Plan-to-Cashier Compose network; Caddy publishes only Cashier's
signed Dodo webhook endpoint.

The package owns the public browser flow, MAS OIDC, session cookies, exact-origin protection, and
rendering. An unavailable Cashier client fails closed for authenticated billing views and commands;
it never falls back to direct Dodo, Synapse, or database access. Cashier action bodies are never
forwarded to the browser; only the local, structured seat-capacity guidance is rewritten for users.
Plan rejects requested seat quantities above 1,000.

## Plan UI ownership and release integration

`assets/product.css`, `assets/plan.html`, `assets/plan.css`, and `assets/plan.js` are embedded in the
Plan binary. They need no browser-side package manager, CDN, or runtime dependency.
`product.css` is a byte-identical vendored copy of the exact framework-neutral shared UI core used
by the shared UI library; `plan.css` contains only Plan-specific composition and responsive layout. The page thus
uses the same light canvas, white surfaces, system typography, compact controls, and neutral borders
without giving this Go service a frontend build pipeline.

The shared library remains the source of those visual tokens and component conventions. Updating
the vendored file requires an exact shared-library release plus a byte-identity check before the
Controlplane release. `assets/SHARED_UI_PROVENANCE.json` records the exact shared source commit and
content hash used by this checkout. Product assets are not inferred from service favicons: Plan embeds
TeleCrypt's original `logo-mark.png` locally, so the page has no runtime asset dependency.

Before release, integrate these files into a reviewed immutable Controlplane release, run the
Plan rendering and security tests plus an authenticated visual regression against the exact
release artifact, and record that exact release for promotion. No deployment should be made from
this working tree.
