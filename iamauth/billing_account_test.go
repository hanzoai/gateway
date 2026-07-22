package iamauth

import "testing"

// WHO PAYS IS NOT A CLIENT'S TO NAME.
//
// The edge declares, validates, strips and mints `billing_account` — but nothing
// proved it, because for a long time nothing set the claim and nothing read the
// header: it was an attribution hint. It is not one anymore. IAM now mints the
// claim from the real grant context and ai/object.Payer resolves the PAYING
// account from it, so this header is money and the strip is a security control.

// TestInjectIdentity_BillingAccount: the validated claim becomes the header, for
// every owner kind IAM can mint. The wire is `<kind>:<subject>` — the contract
// ai/object.ParseAccount reads back (the repos share no code, so this pins it).
func TestInjectIdentity_BillingAccount(t *testing.T) {
	for _, account := range []string{
		"person:hanzo/alice",   // a person in the shared signup org pays for themselves
		"org:acme",             // a real tenant pools; also a client_credentials machine
		"project:acme/website", // a project-scoped token pays the project
	} {
		t.Run(account, func(t *testing.T) {
			r := req(nil)
			InjectIdentity(r, &Claims{Owner: "acme", BillingAccount: account})
			if got := r.Header.Get("X-Billing-Account-Id"); got != account {
				t.Fatalf("X-Billing-Account-Id = %q, want the minted claim %q", got, account)
			}
		})
	}
}

// TestInjectIdentity_NoBillingAccountClaimMintsNoHeader: a token minted before the
// claim shipped names no payer, so the edge OMITS the header rather than inventing
// one — Payer's legacy rule then answers, billing the account it always did.
func TestInjectIdentity_NoBillingAccountClaimMintsNoHeader(t *testing.T) {
	r := req(nil)
	InjectIdentity(r, &Claims{Owner: "acme"})
	if got := r.Header.Get("X-Billing-Account-Id"); got != "" {
		t.Fatalf("X-Billing-Account-Id = %q, want omitted when the token names no payer", got)
	}
}

// TestStripIdentityHeaders_BillingAccountForgery is the money test at the edge: a
// client-supplied X-Billing-Account-Id must never survive to a backend. Payer reads
// this header, so a surviving forgery is a caller naming its own payer — a
// signup-org member pointing their spend at the shared org pool.
func TestStripIdentityHeaders_BillingAccountForgery(t *testing.T) {
	r := req(map[string]string{"X-Billing-Account-Id": "org:hanzo"}) // the shared pool
	StripIdentityHeaders(r)
	if got := r.Header.Get("X-Billing-Account-Id"); got != "" {
		t.Fatalf("a client-forged X-Billing-Account-Id survived the strip: %q", got)
	}
}

// TestBillingAccount_ForgedHeaderIsOverwrittenByTheClaim proves the two halves
// compose the way the edge actually runs them: strip on ingress, then mint from
// the validated claim. A caller naming the shared pool ends up billed to the person
// account IAM signed for them.
func TestBillingAccount_ForgedHeaderIsOverwrittenByTheClaim(t *testing.T) {
	r := req(map[string]string{"X-Billing-Account-Id": "org:hanzo"}) // forged: the pool
	StripIdentityHeaders(r)
	InjectIdentity(r, &Claims{Owner: "hanzo", BillingAccount: "person:hanzo/mallory"})
	if got := r.Header.Get("X-Billing-Account-Id"); got != "person:hanzo/mallory" {
		t.Fatalf("X-Billing-Account-Id = %q, want the validated claim — the forgery must not decide who pays", got)
	}
}

// TestBillingAccountHeader_IsBothMintedAndStripped pins the invariant the whole
// boundary rests on: every header the edge MINTS must also be STRIPPED on ingress,
// or a client could forge one the edge never overwrites (it mints nothing for a
// pre-claim token — exactly when a restored forgery would be the only value).
func TestBillingAccountHeader_IsBothMintedAndStripped(t *testing.T) {
	const h = "X-Billing-Account-Id"
	if !contains(MintedIdentityHeaders, h) {
		t.Fatalf("%s missing from MintedIdentityHeaders", h)
	}
	if !contains(StripIdentityHeaderNames, h) {
		t.Fatalf("%s missing from StripIdentityHeaderNames — a forged value could survive", h)
	}
}
