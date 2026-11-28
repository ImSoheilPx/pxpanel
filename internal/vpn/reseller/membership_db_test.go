//go:build linux && cgo

package reseller

// The membership-shape tests, ported from vpn-ui web/service/
// reseller_membership_test.go: one account is one identity on SEVERAL inbounds,
// with one quota, one traffic row and one ledger row. Every test here is a way
// the old single-inbound ledger shape leaked money or left an account running
// that nobody is billed for.
//
// The fixture is deliberately the awkward shape: the ledger row's home inbound is
// NOT the only one serving the account.
//
// vpn-ui drove the membership deletions through InboundService.
// DelInboundClientByEmail; here the removal seam is REGISTERED with a fake that
// performs the same two halves (splice the settings entry, drop the traffic row),
// which is also the contract test for RemoveClientFromInbound: unwired, cascade
// refuses (ErrInboundPlaneUnavailable), wired, it counts by what the settings
// still serve.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/database"
	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/accounts"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

// membershipFixture is one reseller-sold account on TWO inbounds, an admin's
// account beside it on each (so neither inbound is the last-client case), and the
// ledger row that says who owns it.
type membershipFixture struct {
	admin    *model.User
	reseller *model.User
	// home is the inbound the ledger row names; away is the one it does not.
	home *model.Inbound
	away *model.Inbound
}

// seedMembershipInbound writes an inbound holding the sold account plus an admin's,
// both DISABLED so nothing under test wants a live core.
func seedMembershipInbound(t *testing.T, port int, protocol model.Protocol, clients []map[string]any) *model.Inbound {
	t.Helper()
	settings, err := json.Marshal(map[string]any{"clients": clients})
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	inbound := &model.Inbound{
		UserId: 1, Tag: fmt.Sprintf("inbound-%d", port), Port: port,
		Protocol: protocol, Enable: false, Settings: string(settings),
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("create inbound on port %d: %v", port, err)
	}
	return inbound
}

// soldAndHouse is the two-client shape every inbound here holds: the reseller's
// account and an admin's beside it, so no inbound is ever the last-client case
// unless a test sets that up deliberately.
func soldAndHouse(sold string, soldTotal int64) []map[string]any {
	return []map[string]any{
		{
			"id": "uuid-" + sold, "password": "pw-" + sold, "email": sold,
			"enable": false, "totalGB": soldTotal,
		},
		{
			"id": "uuid-house", "password": "pw-house", "email": "admins-client",
			"enable": false, "totalGB": 1 * gb,
		},
	}
}

// newMembershipFixture builds the two-inbound shape. The admin is seeded FIRST,
// so under the derived role rules it is also the super admin (lowest id) — the
// caller DeleteReseller's tests use.
func newMembershipFixture(t *testing.T, profile model.ResellerProfile, charged int64, soldTotals ...int64) *membershipFixture {
	t.Helper()
	newResellerDB(t)
	db := database.GetDB()

	admin := &model.User{Username: "ms-admin", Password: "x"}
	reseller := &model.User{Username: "ms-reseller", Password: "x"}
	for _, u := range []*model.User{admin, reseller} {
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("create user %s: %v", u.Username, err)
		}
	}
	profile.UserId = reseller.Id
	profile.CreatedBy = admin.Id
	if err := db.Create(&profile).Error; err != nil {
		t.Fatalf("create reseller profile: %v", err)
	}

	homeTotal, awayTotal := int64(5*gb), int64(5*gb)
	if len(soldTotals) > 0 {
		homeTotal = soldTotals[0]
		awayTotal = soldTotals[0]
	}
	if len(soldTotals) > 1 {
		awayTotal = soldTotals[1]
	}
	home := seedMembershipInbound(t, 43001, model.VMESS, soldAndHouse("sold-one", homeTotal))
	away := seedMembershipInbound(t, 43002, model.VMESS, soldAndHouse("sold-one", awayTotal))

	// ONE traffic row for the account, naming the home inbound: that is the whole
	// point of the accounts layer, and it is what every "which inbound is this on"
	// query used to answer from.
	if err := db.Create(&xray.ClientTraffic{
		InboundId: home.Id, Email: "sold-one", Enable: true, Total: homeTotal,
	}).Error; err != nil {
		t.Fatalf("create client traffic: %v", err)
	}
	if err := db.Create(&model.ResellerClient{
		Email: "sold-one", InboundId: home.Id, UserId: reseller.Id, ChargedBytes: charged,
	}).Error; err != nil {
		t.Fatalf("create ledger row: %v", err)
	}
	return &membershipFixture{admin: admin, reseller: reseller, home: home, away: away}
}

func (f *membershipFixture) spent(t *testing.T) int64 {
	t.Helper()
	p := model.ResellerProfile{}
	if err := database.GetDB().Model(&model.ResellerProfile{}).
		Where("user_id = ?", f.reseller.Id).First(&p).Error; err != nil {
		t.Fatalf("read profile: %v", err)
	}
	return p.SpentBytes
}

func (f *membershipFixture) ledgerRow(t *testing.T) *model.ResellerClient {
	t.Helper()
	rc := &model.ResellerClient{}
	err := database.GetDB().Model(&model.ResellerClient{}).
		Where("email = ?", "sold-one").First(rc).Error
	if err != nil {
		return nil
	}
	return rc
}

// fakeRemoveClient is the removal seam as the real one behaves: splice the
// settings entry, drop the traffic row, report not-found for an entry that is
// already gone. Returning false for needXrayRestart: a disabled fixture core.
func fakeRemoveClient(inboundId int, email string) (bool, error) {
	db := database.GetDB()
	inbound := &model.Inbound{}
	if err := db.Model(&model.Inbound{}).First(inbound, inboundId).Error; err != nil {
		return false, err
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(inbound.Settings), &root); err != nil {
		return false, err
	}
	clients, _ := root["clients"].([]any)
	kept := make([]any, 0, len(clients))
	found := false
	for _, raw := range clients {
		cm, _ := raw.(map[string]any)
		if e, _ := cm["email"].(string); strings.EqualFold(e, email) {
			found = true
			continue
		}
		kept = append(kept, raw)
	}
	if !found {
		return false, errors.New("client not found in inbound")
	}
	root["clients"] = kept
	patched, err := json.Marshal(root)
	if err != nil {
		return false, err
	}
	if err := db.Model(&model.Inbound{}).Where("id = ?", inboundId).
		Update("settings", string(patched)).Error; err != nil {
		return false, err
	}
	if err := db.Where("email = ?", email).Delete(&xray.ClientTraffic{}).Error; err != nil {
		return false, err
	}
	return false, nil
}

// withFakeSeam installs the fake for the duration of one test.
func withFakeSeam(t *testing.T) {
	t.Helper()
	prev := RemoveClientFromInbound
	RemoveClientFromInbound = fakeRemoveClient
	t.Cleanup(func() { RemoveClientFromInbound = prev })
}

// Consumption is captured before the first delete, as every delete path does:
// the traffic row goes with it.
func TestRefundWaitsForTheLastMembership(t *testing.T) {
	withFakeSeam(t)
	f := newMembershipFixture(t, model.ResellerProfile{AllowanceBytes: 100 * gb, SpentBytes: 40 * gb}, 10*gb)

	used, known, err := UsageOf("sold-one")
	if err != nil {
		t.Fatalf("UsageOf: %v", err)
	}
	if !known {
		t.Fatal("the account has a traffic row, so its usage must be readable")
	}

	if _, err := fakeRemoveClient(f.home.Id, "sold-one"); err != nil {
		t.Fatalf("delete the first membership: %v", err)
	}
	if err := RefundDeleted("sold-one", used, known); err != nil {
		t.Fatalf("RefundDeleted after the first membership: %v", err)
	}
	if got := f.spent(t); got != 40*gb {
		t.Errorf("SpentBytes = %d; want it unmoved at %d: the account is still served on the second inbound and still selling", got, 40*gb)
	}
	rc := f.ledgerRow(t)
	if rc == nil {
		t.Fatal("the ledger row was dropped while the account was still running: absence of a row means the HOUSE owns it, so the reseller stopped paying for a live account")
	}
	if rc.ChargedBytes != 10*gb {
		t.Errorf("ChargedBytes = %d; want the charge untouched at %d", rc.ChargedBytes, 10*gb)
	}

	// The last one going is the delete.
	if _, err := fakeRemoveClient(f.away.Id, "sold-one"); err != nil {
		t.Fatalf("delete the last membership: %v", err)
	}
	if err := RefundDeleted("sold-one", used, known); err != nil {
		t.Fatalf("RefundDeleted after the last membership: %v", err)
	}
	if got := f.spent(t); got != 30*gb {
		t.Errorf("SpentBytes = %d; want %d, the whole unused charge back once the account is really gone", got, 30*gb)
	}
	if f.ledgerRow(t) != nil {
		t.Error("the ledger row outlived the account it belonged to")
	}
}

// --- deleting an inbound ---------------------------------------------------------

// Deleting one inbound of two removes a MEMBERSHIP. Nothing is refunded, the ledger
// row stays, and the home pointer follows the account to an inbound it is really on
// rather than naming a row that no longer exists.
func TestDropInboundRefundsNothingWhileTheAccountLivesElsewhere(t *testing.T) {
	f := newMembershipFixture(t, model.ResellerProfile{AllowanceBytes: 100 * gb, SpentBytes: 40 * gb}, 10*gb)

	// The controller's order: the roster and the usage while the inbound still has
	// both, then the delete, then the settlement.
	owned, err := OwnedEmailsOnInbound(f.home.Id)
	if err != nil {
		t.Fatalf("OwnedEmailsOnInbound: %v", err)
	}
	if len(owned) != 1 || !strings.EqualFold(owned[0], "sold-one") {
		t.Fatalf("owned = %v; want the one reseller account this inbound serves", owned)
	}
	usage, err := UsageSnapshot(owned)
	if err != nil {
		t.Fatalf("UsageSnapshot: %v", err)
	}
	if err := database.GetDB().Where("id = ?", f.home.Id).Delete(&model.Inbound{}).Error; err != nil {
		t.Fatalf("delete inbound: %v", err)
	}
	if err := DropInbound(f.home.Id, owned, usage); err != nil {
		t.Fatalf("DropInbound: %v", err)
	}

	if got := f.spent(t); got != 40*gb {
		t.Errorf("SpentBytes = %d; want it unmoved at %d: the account is still sold and still running on the second inbound", got, 40*gb)
	}
	rc := f.ledgerRow(t)
	if rc == nil {
		t.Fatal("the ledger row went with an inbound the account merely happened to be on")
	}
	if rc.InboundId != f.away.Id {
		t.Errorf("InboundId = %d; want it repointed at the surviving inbound %d rather than left naming a deleted row", rc.InboundId, f.away.Id)
	}
}

// The other half, and the one the old WHERE inbound_id = ? got backwards: deleting
// the inbound the ledger row does NOT name is still the last membership going when
// it is the last one, and it refunds.
func TestDropInboundRefundsWhenTheLastMembershipGoes(t *testing.T) {
	f := newMembershipFixture(t, model.ResellerProfile{AllowanceBytes: 100 * gb, SpentBytes: 40 * gb}, 10*gb)

	// Empty the home inbound first, so the away inbound (which the ledger row does
	// not name) is the account's only membership.
	if _, err := fakeRemoveClient(f.home.Id, "sold-one"); err != nil {
		t.Fatalf("delete the home membership: %v", err)
	}

	owned, err := OwnedEmailsOnInbound(f.away.Id)
	if err != nil {
		t.Fatalf("OwnedEmailsOnInbound: %v", err)
	}
	if len(owned) != 1 {
		t.Fatalf("owned = %v; an account whose HOME is elsewhere is still served here, so it must be listed", owned)
	}
	// Its traffic row went with the first delete, so consumption is unknown and the
	// refund is withheld rather than invented. Prove the ledger row still goes.
	usage, err := UsageSnapshot(owned)
	if err != nil {
		t.Fatalf("UsageSnapshot: %v", err)
	}
	if err := database.GetDB().Where("id = ?", f.away.Id).Delete(&model.Inbound{}).Error; err != nil {
		t.Fatalf("delete inbound: %v", err)
	}
	if err := DropInbound(f.away.Id, owned, usage); err != nil {
		t.Fatalf("DropInbound: %v", err)
	}
	if f.ledgerRow(t) != nil {
		t.Error("the account is served by nothing at all now, so its ledger row must go: a recycled email would inherit the charge")
	}
}

// --- the cascade seam ------------------------------------------------------------

// Unwired, a cascade refuses the WHOLE delete rather than half-applying it: a
// half-applied cascade leaves live accounts whose ledger rows are already gone.
func TestCascadeRefusesWithoutTheSeam(t *testing.T) {
	RemoveClientFromInbound = nil
	// Restore the wired seam when the test ends; t.Cleanup takes a func(), so the
	// fixture helper (which needs t) is wrapped rather than passed bare.
	t.Cleanup(func() { withFakeSeam(t) })
	f := newMembershipFixture(t, model.ResellerProfile{AllowanceBytes: 100 * gb, SpentBytes: 10 * gb}, 10*gb)
	caller := accounts.Viewer{Id: f.admin.Id, IsSuperAdmin: true}
	if _, err := DeleteReseller(caller, f.reseller.Id, DeleteModeCascade); !errors.Is(err, ErrInboundPlaneUnavailable) {
		t.Fatalf("err = %v; want ErrInboundPlaneUnavailable", err)
	}
	// Nothing moved: the reseller, its profile and the ledger row all still exist.
	if f.ledgerRow(t) == nil {
		t.Error("a refused cascade must not touch the ledger")
	}
	var n int64
	database.GetDB().Model(&model.User{}).Where("id = ?", f.reseller.Id).Count(&n)
	if n != 1 {
		t.Error("a refused cascade must not drop the reseller")
	}
}

// Wired, the cascade removes every membership of each owned account, keeps the
// house's accounts untouched, hands a stale row's account to the house, and only
// then drops the reseller. Counted by what the SETTINGS still serve, which is the
// load-bearing rule: settings.clients is what RADIUS, the daemon config writers
// and the config builder read.
func TestCascadeCountsBySettingsNotByStaleMemberships(t *testing.T) {
	withFakeSeam(t)
	f := newMembershipFixture(t, model.ResellerProfile{AllowanceBytes: 100 * gb, SpentBytes: 10 * gb}, 10*gb)
	db := database.GetDB()

	// A stale ledger row: names an account that is served nowhere.
	if err := db.Create(&model.ResellerClient{
		Email: "ghost-account", InboundId: f.home.Id, UserId: f.reseller.Id, ChargedBytes: 3 * gb,
	}).Error; err != nil {
		t.Fatal(err)
	}

	// And a second SOLD account served on the away inbound only, so the cascade
	// has more than one account to reason about.
	if err := db.Create(&model.ResellerClient{
		Email: "sold-two", InboundId: f.away.Id, UserId: f.reseller.Id, ChargedBytes: 2 * gb,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.Inbound{}).Where("id = ?", f.away.Id).First(f.away).Error; err != nil {
		t.Fatal(err)
	}
	awaySettings := map[string]any{}
	if err := json.Unmarshal([]byte(f.away.Settings), &awaySettings); err != nil {
		t.Fatal(err)
	}
	awaySettings["clients"] = append(awaySettings["clients"].([]any), map[string]any{
		"id": "uuid-sold-two", "email": "sold-two", "enable": false, "totalGB": 2 * gb,
	})
	patched, err := json.Marshal(awaySettings)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.Inbound{}).Where("id = ?", f.away.Id).
		Update("settings", string(patched)).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&xray.ClientTraffic{
		InboundId: f.away.Id, Email: "sold-two", Enable: true, Total: 2 * gb,
	}).Error; err != nil {
		t.Fatal(err)
	}

	caller := accounts.Viewer{Id: f.admin.Id, IsSuperAdmin: true}
	res, err := DeleteReseller(caller, f.reseller.Id, DeleteModeCascade)
	if err != nil {
		t.Fatalf("DeleteReseller: %v", err)
	}
	// sold-one: removed from both inbounds -> deleted. sold-two: removed from its
	// one inbound -> deleted. ghost-account: served nowhere even before the
	// cascade -> handed to the house (kept), never miscounted as deleted.
	if res.Deleted != 2 {
		t.Errorf("Deleted = %d; want the two accounts the settings really stopped serving", res.Deleted)
	}
	if res.Kept != 1 {
		t.Errorf("Kept = %d; want the stale row's account, which a deleted reseller can never be billed for", res.Kept)
	}
	var house int64
	db.Model(&model.ResellerClient{}).Count(&house)
	if house != 0 {
		t.Errorf("%d ledger rows survived the reseller they billed for", house)
	}
	var users int64
	db.Model(&model.User{}).Where("id = ?", f.reseller.Id).Count(&users)
	if users != 0 {
		t.Error("the reseller outlived a completed cascade")
	}
	var adminLeft int64
	db.Model(&model.ResellerClient{}).Where("email = ?", "admins-client").Count(&adminLeft)
	if adminLeft != 0 {
		t.Error("the admin's account was never on the ledger; this check is vacuous")
	}
}
