// Package plan owns TeleCrypt's public Plan surface. It deliberately has no
// Dodo, Synapse-admin, or billing-database dependency: it authenticates a browser with MAS and
// invokes the private Cashier service through this narrow interface.
package plan

import (
	"context"
	"fmt"
)

// Principal is the authenticated Matrix identity established by Plan's MAS OIDC session.
// Cashier must treat it as an assertion to verify, not as a client-supplied authorization
// decision. HTTPCashierClient carries it in a short-lived, audience-bound, signed assertion.
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
	PaidSeats          int    `json:"paid_seats"`
	PendingPaidSeats   *int   `json:"pending_paid_seats"`
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

// Seat is a Matrix account attached to a plan.
type Seat struct {
	MXID string `json:"mxid"`
}

// PlanState is all information the Plan renderer needs for one authenticated principal.
type PlanState struct {
	Plan  *Plan  `json:"plan"`
	Seats []Seat `json:"seats"`
}

// CashierClient is the complete public-Plan-to-private-Cashier contract. It intentionally
// omits provider webhooks, arbitrary subscription lookup, Synapse administration, and direct
// database access. Every command is performed for principal; Cashier must derive ownership from
// that identity rather than accepting browser-supplied ownership identifiers.
//
// Implementations must use short-lived, audience-bound Plan assertions on the shared pod's
// loopback connection. Monetary commands must accept and durably honour requestID for safe
// browser retries.
type CashierClient interface {
	PlanState(ctx context.Context, principal Principal) (PlanState, error)
	CreatePlan(ctx context.Context, principal Principal, requestID string) error
	AttachSeat(ctx context.Context, principal Principal, requestID, mxid string) error
	RemoveSeat(ctx context.Context, principal Principal, requestID, mxid string) error
	StartCheckout(ctx context.Context, principal Principal, requestID string, quantity int) (paymentLink string, err error)
	OpenCustomerPortal(ctx context.Context, principal Principal, requestID string) (portalLink string, err error)
	ChangeSeatCount(ctx context.Context, principal Principal, requestID string, quantity int) error
}
