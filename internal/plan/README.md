# Plan service boundary

Current public project facts and component responsibilities are authoritative in
[`llms.txt`](https://www.telecrypt.io/llms.txt); this document describes the Plan package implementation.

`internal/plan` is the deployed public, browser-facing owner of `/plan`. It owns MAS OIDC,
browser sessions, origin/CSRF protection, rendering, and the user-facing plan, seat, checkout,
and billing-portal actions. MAS embeds this stable URL in its account-management iframe through
`plan_management_iframe_uri`; it also works as a standalone page.

It must not receive Dodo credentials, Dodo webhook secrets, Synapse-admin credentials, or a
billing database URL.  It calls the private Cashier through `CashierClient` for billing and team ownership.
For manual member access, Plan also uses the existing MAS admin credential and internal
`127.0.0.1:8081` listener in the shared application pod. Every lock/unlock request first obtains
Cashier state for the signed-in principal and requires an active plan and a target seat in that
owner's team. The browser cannot supply an owner or MAS user ID. Plan resolves the local Matrix
username through MAS and applies the reversible account lock. Payment does not automatically
unlock members.

MAS locks block existing sessions while locked; unlocking restores those sessions. Synapse caches
MAS introspection responses for two minutes, so existing-session denial and recovery can each take
up to two minutes. The account lock also propagates through MAS's provisioning queue. Real
acceptance polls existing Matrix access for denial and recovery beyond the cache lifetime. Plan displays MAS lock state alongside each paid member.

Plan's browser API is rooted at `/api/plan`; `/api/team*` routes are not exposed. The
current public boundary must preserve this contract: successful plan and seat-state mutations at
`/api/plan*` return HTTP 204 with an empty body; checkout and portal actions return HTTP 200 JSON
containing their payment or portal link; structured plan reads also remain HTTP 200 JSON. The MAS
callback remains `/plan/callback`, but malformed, expired, and foreign-server sessions are rejected
rather than being migrated implicitly.

## Cashier integration

`CashierClient` implements the [Cashier-owned private Plan API contract](https://github.com/TeleCrypt-io/cashier/blob/main/README.md#private-plan-api).
Keep its protocol documentation with Cashier rather than maintaining a second contract here.

The package owns the public browser flow, MAS OIDC, session cookies, exact-origin protection, and
rendering. An unavailable Cashier client fails closed for authenticated billing views and commands;
it never falls back to direct Dodo, Synapse, or database access. Cashier action bodies are never
forwarded to the browser; only the local, structured seat-capacity guidance is rewritten for users.


## Plan UI ownership and release integration

Plan keeps its HTML and Plan-specific CSS and JavaScript embedded in the binary. The shared product
stylesheet and TeleCrypt branding are loaded directly from the stable public URLs owned by
`www.telecrypt.io`:

- `https://www.telecrypt.io/ui/product.css`
- `https://www.telecrypt.io/logo-mark.png`
- `https://www.telecrypt.io/favicon-32x32.png`

Storage Web and Plan therefore use one editable source for their shared presentation. `plan.css`
contains only Plan-specific composition and responsive layout. The landing website keeps its own
independent design and does not load the product stylesheet. MAS authentication and account screens
also keep their existing upstream design; MAS embeds this Plan page for team and billing management.

The public asset URLs are intentionally unversioned and use the website's normal browser and CDN
caching. A stylesheet or branding change can affect both consumers as caches refresh, so visual
changes must be checked in Storage Web and Plan before publishing the website change. Application
releases remain exact and immutable; the release record should identify both the application release
and the website release observed during acceptance. Plan does not vendor shared assets or maintain a
second checksum/provenance file.

Before release, run the Plan rendering and security tests plus an authenticated visual regression
against the exact Controlplane release artifact, and verify the three public asset URLs return the
expected content types. No deployment should be made from this working tree.
