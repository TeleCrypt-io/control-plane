// Package plan owns TeleCrypt's public Plan surface. It deliberately has no
// Dodo, Synapse-admin, or billing-database dependency: it authenticates a browser with MAS and
// invokes the private Cashier service through this narrow interface.
package plan

import (
	"context"
	"fmt"
)

// Principal is the authenticated Matrix identity established by Plan's MAS OIDC session.
// Cashier uses it to authorize the private request against its own team and membership state.
type Principal struct {
	MXID string
}

// Plan is the billing-safe subset of a user's plan shown to its administrator. Provider
// identifiers and billing credentials are intentionally never returned to the browser-facing
// Plan service.
type Plan struct {
	// TierID is the stable billing identifier. DisplayName is presentation only;
	// Plan must never use it as an authorization or provider key.
	TierID             int16  `json:"tier_id"`
	DisplayName        string `json:"display_name"`
	MonthlyCents       int64  `json:"monthly_cents"`
	StorageBytes       int64  `json:"storage_bytes"`
	MemberLimit        int    `json:"member_limit"`
	UsageBytes         int64  `json:"usage_bytes"`
	SubscriptionStatus string `json:"subscription_status"`
	HasBillingAccount  bool   `json:"has_billing_account"`
}

func (p Plan) MonthlyPrice() string {
	return fmt.Sprintf("€%.2f/month", float64(p.MonthlyCents)/100)
}

func (p Plan) StorageAllowance() string {
	return formatStorageBytes(p.StorageBytes)
}

func (p Plan) StorageUsage() string {
	return formatStorageBytes(p.UsageBytes)
}

func formatStorageBytes(bytes int64) string {
	if bytes < 0 {
		return "unavailable"
	}
	const (
		gb = int64(1_000_000_000)
		tb = 1_000 * gb
	)
	switch {
	case bytes >= tb && bytes%tb == 0:
		return fmt.Sprintf("%d TB", bytes/tb)
	case bytes >= gb && bytes%gb == 0:
		return fmt.Sprintf("%d GB", bytes/gb)
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}

// Member is a Matrix account attached to a team.
type Member struct {
	MXID string `json:"mxid"`
}

// PlanState is all information the Plan renderer needs for one authenticated principal.
type PlanState struct {
	Plan    *Plan    `json:"plan"`
	Members []Member `json:"members"`
}

// BillingLink is a configured public static checkout link for one fixed tier.
// Plan never creates provider sessions or sends provider API requests.
type BillingLink struct {
	TierID      int
	DisplayName string
	URL         string
}

// CashierClient is the complete public-Plan-to-private-Cashier contract. It intentionally
// omits provider webhooks, arbitrary subscription lookup, Synapse administration, and direct
// database access. Every command is performed for principal; Cashier must derive ownership from
// that identity rather than accepting browser-supplied ownership identifiers.
//
// Implementations must use the shared pod's private connection. Cashier derives ownership from
// the authenticated principal and ordinary database constraints make repeated commands harmless.
type CashierClient interface {
	PlanState(ctx context.Context, principal Principal) (PlanState, error)
	AttachMember(ctx context.Context, principal Principal, mxid string) error
	// RemoveMember detaches a target for an owner.
	RemoveMember(ctx context.Context, principal Principal, mxid string) error
	// LeaveMember detaches the authenticated member; Cashier enforces the owner rule.
	LeaveMember(ctx context.Context, principal Principal) error
}
