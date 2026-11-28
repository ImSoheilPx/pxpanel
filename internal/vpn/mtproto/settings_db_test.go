//go:build linux && cgo

package mtproto

// Database-backed halves of the mtproto tests (vpn-ui web/service
// mtproto_settings_test.go / mtproto_compat_test.go). Gated to linux+cgo and
// wired to the injected handle exactly like radius's eap_db_test.go: the panel
// database is CGO sqlite (internal/database), so dependency builds and Windows
// hosts compile the cgo-free halves instead; CI runs this file.

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/database"
	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/logger"
	vpn "github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
	vpnrange "github.com/ImSoheilPx/pxpanel/internal/vpn/range"

	"github.com/op/go-logging"
)

// newInboundDB brings up a fresh temp database and points vpn.DB() at it
// (vpn-ui inbound_email_test.go's helper, minus its Xray-process plumbing —
// the mtproto paths here never touch the core).
func newInboundDB(t *testing.T) {
	t.Helper()
	logger.InitLogger(logging.ERROR)
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	vpn.SetDB(database.GetDB)
}

// TestMtprotoLiftClientSettingsToInbound pins the one-shot upgrade of an inbound
// stored before these settings moved. It runs on the ORDINARY startup path
// (GenerateAllConfigs), not from MigrateDB, which never runs on a plain binary
// upgrade.
func TestMtprotoLiftClientSettingsToInbound(t *testing.T) {
	newInboundDB(t)
	db := vpn.DB()
	s := &MtprotoService{}

	// The legacy shape: the lifted settings on the clients, nothing on the inbound.
	// Modes differ per account, only one holds a FakeTLS domain, and the two device
	// caps disagree. bob also carries an ad tag, which must be left exactly where it
	// is: that field did not move.
	legacy := `{"clients":[
		{"id":"alice","email":"alice","secret":"00112233445566778899aabbccddeeff","enable":true,
		 "modeClassic":true,"tlsDomain":"ignored.example","userLimit":2,"comment":"keep me"},
		{"id":"bob","email":"bob","secret":"ffeeddccbbaa99887766554433221100","enable":true,
		 "modeTls":true,"tlsDomain":"www.cloudflare.com","adtagEnable":true,
		 "adtag":"0123456789abcdef0123456789abcdef","userLimit":7}
	]}`
	inbound := &model.Inbound{
		UserId: 1, Tag: "inbound-9443", Port: 9443, Protocol: defaults.ProtoMTProto,
		Enable: true, Settings: legacy,
	}
	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}

	if err := s.LiftClientSettingsToInbound(); err != nil {
		t.Fatalf("LiftClientSettingsToInbound: %v", err)
	}

	read := func() *mtprotoSettings {
		t.Helper()
		var stored model.Inbound
		if err := db.Where("id = ?", inbound.Id).First(&stored).Error; err != nil {
			t.Fatalf("re-read inbound: %v", err)
		}
		out := &mtprotoSettings{}
		if err := json.Unmarshal([]byte(stored.Settings), out); err != nil {
			t.Fatalf("stored settings do not parse: %v", err)
		}
		return out
	}

	got := read()
	// Modes: the UNION, which is what the listener already accepted. bob gains
	// classic and alice gains tls; that granularity is what is being removed.
	if !got.ModeClassic || got.ModeSecure || !got.ModeTls {
		t.Errorf("modes = classic:%v secure:%v tls:%v, want the union classic+tls",
			got.ModeClassic, got.ModeSecure, got.ModeTls)
	}
	// The first FakeTLS account's domain, which telemt already emulated for the whole
	// process; alice's is deliberately ignored because she has no tls mode.
	if got.TlsDomain != "www.cloudflare.com" {
		t.Errorf("tlsDomain = %q, want the first FakeTLS account's domain", got.TlsDomain)
	}
	// The MAX, the one real behaviour change: alice was capped at 2 and comes out at 7.
	if got.UserLimit == nil || *got.UserLimit != 7 {
		t.Errorf("userLimit = %v, want the max across accounts (7)", got.UserLimit)
	}

	// Client fields this service does not model must survive the rewrite: the merge
	// writes back the raw object, not a re-marshalled struct.
	var stored model.Inbound
	if err := db.Where("id = ?", inbound.Id).First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stored.Settings, "keep me") {
		t.Error("the rewrite dropped a client field it does not model (comment)")
	}

	// The ad tag stayed on bob and did NOT reach the inbound. Both halves matter:
	// seeding it upward would have flattened two customers' tags into one, and the
	// stored key is what the rendered config still reads.
	var lifted map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stored.Settings), &lifted); err != nil {
		t.Fatal(err)
	}
	if _, seeded := lifted["adtag"]; seeded {
		t.Error("the migration seeded an inbound-level adtag; the tag is per client")
	}
	if _, seeded := lifted["adtagEnable"]; seeded {
		t.Error("the migration seeded an inbound-level adtagEnable; the tag is per client")
	}
	if parsed, perr := s.parseSettings(&stored); perr != nil {
		t.Fatal(perr)
	} else if !s.anyAdtag(parsed) {
		t.Error("bob's ad tag did not survive the migration: the whole inbound would silently go back to Xray routing")
	}

	// Idempotent: GenerateAllConfigs calls this every 10 seconds off the traffic job,
	// so a second pass must not touch anything (and must not re-derive the union after
	// an operator narrows the modes).
	got.ModeTls = false
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Model(model.Inbound{}).Where("id = ?", inbound.Id).Update("settings", string(raw)).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.LiftClientSettingsToInbound(); err != nil {
		t.Fatal(err)
	}
	if after := read(); after.ModeTls {
		t.Error("a second pass re-derived the modes from the clients, undoing an operator edit")
	}
}

// An inbound with no accounts (or none holding a mode) must not migrate to "no modes":
// that config grants everything. It falls back to the fresh-inbound default instead.
func TestMtprotoLiftEmptyInboundGetsTheFreshDefaults(t *testing.T) {
	newInboundDB(t)
	db := vpn.DB()
	s := &MtprotoService{}

	inbound := &model.Inbound{
		UserId: 1, Tag: "inbound-9444", Port: 9444, Protocol: defaults.ProtoMTProto,
		Enable: true, Settings: `{"clients":[]}`,
	}
	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
	if err := s.LiftClientSettingsToInbound(); err != nil {
		t.Fatalf("LiftClientSettingsToInbound: %v", err)
	}

	var stored model.Inbound
	if err := db.Where("id = ?", inbound.Id).First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	got := &mtprotoSettings{}
	if err := json.Unmarshal([]byte(stored.Settings), got); err != nil {
		t.Fatal(err)
	}
	if !got.ModeClassic || !got.ModeSecure || !got.ModeTls {
		t.Errorf("modes = %v/%v/%v, want all three on (the fresh-inbound default)",
			got.ModeClassic, got.ModeSecure, got.ModeTls)
	}
	if got.TlsDomain != "www.google.com" {
		t.Errorf("tlsDomain = %q, want the default", got.TlsDomain)
	}
	if got.UserLimit == nil || *got.UserLimit != 10 {
		t.Errorf("userLimit = %v, want an explicit 10 (the fresh-inbound default) for an empty inbound", got.UserLimit)
	}
}

// Accounts that predate the userLimit field resolved to ONE device each
// (effectiveUserLimit(nil)), so the lifted value has to be an explicit 1. Writing 0
// would read as "no limit" and quietly widen every legacy inbound to 16 devices.
func TestMtprotoLiftKeepsTheLegacySingleDeviceCap(t *testing.T) {
	newInboundDB(t)
	db := vpn.DB()
	s := &MtprotoService{}

	inbound := &model.Inbound{
		UserId: 1, Tag: "inbound-9445", Port: 9445, Protocol: defaults.ProtoMTProto,
		Enable: true, Settings: `{"clients":[{"id":"a","email":"a","secret":"00112233445566778899aabbccddeeff","enable":true,"modeSecure":true}]}`,
	}
	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
	if err := s.LiftClientSettingsToInbound(); err != nil {
		t.Fatalf("LiftClientSettingsToInbound: %v", err)
	}

	var stored model.Inbound
	if err := db.Where("id = ?", inbound.Id).First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	got := &mtprotoSettings{}
	if err := json.Unmarshal([]byte(stored.Settings), got); err != nil {
		t.Fatal(err)
	}
	if got.UserLimit == nil || *got.UserLimit != 1 {
		t.Errorf("userLimit = %v, want an explicit 1 (what an absent per-client value meant)", got.UserLimit)
	}
	if vpnrange.EffectiveUserLimit(got.UserLimit) != 1 {
		t.Errorf("effective device cap = %d, want 1", vpnrange.EffectiveUserLimit(got.UserLimit))
	}
}

// seedMtprotoInbound puts one inbound into a fresh temp database.
func seedMtprotoInbound(t *testing.T, port int, settings string) *model.Inbound {
	t.Helper()
	inbound := &model.Inbound{
		UserId: 1, Tag: fmt.Sprintf("inbound-%d", port), Port: port,
		Protocol: defaults.ProtoMTProto, Enable: true, Settings: settings,
	}
	if err := vpn.DB().Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
	return inbound
}

// storedInbound re-reads an inbound from the database.
func storedInbound(t *testing.T, id int) *model.Inbound {
	t.Helper()
	var out model.Inbound
	if err := vpn.DB().Where("id = ?", id).First(&out).Error; err != nil {
		t.Fatalf("re-read inbound %d: %v", id, err)
	}
	return &out
}

// A database that arrives ALREADY OLD: a restored backup, an imported foreign DB, or
// the migrate CLI. None of those goes through panel startup, and the reader's tolerance
// is not enough on its own, because the panel's inbound form posts back what it read.
//
// (vpn-ui drove this through InboundService.MigrateDB, which also calls the lift; the
// MigrateDB hook itself lands with the migration wave, so the test drives the lift the
// startup path uses. The property under test — an old DB must end up lifted — is the
// same one.)
func TestMtprotoImportPathLiftsLegacySettings(t *testing.T) {
	newInboundDB(t)
	s := &MtprotoService{}
	seeded := seedMtprotoInbound(t, 9451, mtprotoLegacyBlob)

	s.LiftClientSettingsToInbound() // the migrate / import / restore hook's lift

	stored := storedInbound(t, seeded.Id)
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stored.Settings), &root); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"modeClassic", "modeSecure", "modeTls", "tlsDomain", "userLimit"} {
		if _, ok := root[key]; !ok {
			t.Fatalf("an imported legacy inbound still has no inbound-level %q after the lift", key)
		}
	}
	// Same config as the equivalent already-migrated inbound, which is the property the
	// whole exercise is for. Port and tag are matched so only the settings can differ.
	stored.Id, stored.Port, stored.Tag = 3, 9443, "inbound-9443"
	if got, want := renderMtproto(t, stored), renderMtproto(t, mtprotoInboundFrom(mtprotoMigratedBlob)); got != want {
		t.Errorf("an imported legacy inbound renders a different config:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// The lift and the mirror both run from GenerateAllConfigs, which the traffic job calls
// every 10 seconds, so they have to settle after one pass and stay settled. The
// generated config is the thing that must not churn: telemt watches its config file with
// inotify and reloads on any write, so a config that differs pass to pass would make it
// reload forever.
func TestMtprotoLiftAndMirrorAreIdempotent(t *testing.T) {
	newInboundDB(t)
	seeded := seedMtprotoInbound(t, 9452, mtprotoLegacyBlob)
	s := &MtprotoService{}

	pass := func() (settings, config string) {
		t.Helper()
		if err := s.LiftClientSettingsToInbound(); err != nil {
			t.Fatalf("lift: %v", err)
		}
		if err := s.MirrorInboundSettingsToClients(); err != nil {
			t.Fatalf("mirror: %v", err)
		}
		stored := storedInbound(t, seeded.Id)
		return stored.Settings, renderMtproto(t, stored)
	}

	settings1, config1 := pass()
	settings2, config2 := pass()
	settings3, config3 := pass()

	// The anti-churn property, and the one that actually costs something when it breaks.
	if config1 != config2 || config2 != config3 {
		t.Errorf("the generated config changed between passes; telemt would reload on every traffic tick:\n1: %s\n2: %s\n3: %s",
			config1, config2, config3)
	}
	// The stored blob settles too, so the passes stop writing to the database at all.
	if settings2 != settings1 {
		t.Errorf("the second pass rewrote the settings:\n1: %s\n2: %s", settings1, settings2)
	}
	if settings3 != settings2 {
		t.Errorf("the third pass rewrote the settings:\n2: %s\n3: %s", settings2, settings3)
	}
	// A no-op pass must also leave an operator's later narrowing alone, which is what the
	// key-presence test buys: re-deriving the union from the clients would undo the edit.
	narrowed := `{"modeClassic":false,"modeSecure":true,"modeTls":false,"tlsDomain":"www.cloudflare.com","userLimit":4,"clients":[]}`
	if err := vpn.DB().Model(model.Inbound{}).Where("id = ?", seeded.Id).
		Update("settings", narrowed).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.LiftClientSettingsToInbound(); err != nil {
		t.Fatal(err)
	}
	after, err := s.parseSettings(storedInbound(t, seeded.Id))
	if err != nil {
		t.Fatal(err)
	}
	if after.ModeClassic || after.ModeTls {
		t.Error("a later pass re-derived the modes from the clients, undoing an operator edit")
	}
}

// The downgrade mirror. The previous binary reads the modes, the domain and the cap only
// from the clients, and DROPS a client whose mode set is empty (it disappears from
// [access.users] entirely). So an account added after the upgrade, which carries none of
// those keys, would be unable to connect on a rollback with nothing in the log saying
// why. The mirror is what stops that.
func TestMtprotoMirrorSurvivesADowngrade(t *testing.T) {
	newInboundDB(t)
	seeded := seedMtprotoInbound(t, 9453, mtprotoMigratedBlob)
	db := vpn.DB()
	s := &MtprotoService{}

	// A client added after the upgrade: exactly what the panel's form posts, which is
	// email/secret/enable and no dead fields at all.
	withNewClient := `{"modeClassic":true,"modeSecure":true,"modeTls":true,
		"tlsDomain":"www.cloudflare.com","userLimit":4,"clients":[
		{"id":"alice","email":"alice","secret":"00112233445566778899aabbccddeeff","enable":true},
		{"id":"carol","email":"carol","secret":"aabbccddeeff00112233445566778899","enable":true}
	]}`
	if err := db.Model(model.Inbound{}).Where("id = ?", seeded.Id).Update("settings", withNewClient).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.MirrorInboundSettingsToClients(); err != nil {
		t.Fatalf("mirror: %v", err)
	}

	// Read the stored clients back through the PRE-MOVE struct, which is what the old
	// binary decodes them with.
	var stored struct {
		Clients []mtprotoLegacyClient `json:"clients"`
	}
	if err := json.Unmarshal([]byte(storedInbound(t, seeded.Id).Settings), &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.Clients) != 2 {
		t.Fatalf("got %d clients, want 2", len(stored.Clients))
	}
	for i, c := range stored.Clients {
		if !c.ModeClassic || !c.ModeSecure || !c.ModeTls {
			t.Errorf("client %d has modes %v/%v/%v: the old binary drops an account with an empty mode set",
				i, c.ModeClassic, c.ModeSecure, c.ModeTls)
		}
		if c.TlsDomain != "www.cloudflare.com" {
			t.Errorf("client %d has tlsDomain %q, want the inbound's domain", i, c.TlsDomain)
		}
		// The RAW cap, so an explicit 0 still means "no limit" over there and resolves
		// through the same effectiveUserLimit.
		if c.UserLimit == nil || *c.UserLimit != 4 {
			t.Errorf("client %d has userLimit %v, want the inbound's 4", i, c.UserLimit)
		}
	}

	// And the mirrored blob still means the same thing to THIS binary if the inbound-level
	// keys are ever lost again (an old binary's write, a partial API update): the union of
	// the mirrored modes is the inbound's set, and the largest mirrored cap is its cap. So
	// the round-trip through the old shape is lossless rather than merely survivable.
	legacyAgain := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(storedInbound(t, seeded.Id).Settings), &legacyAgain); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"modeClassic", "modeSecure", "modeTls", "tlsDomain", "userLimit"} {
		delete(legacyAgain, key)
	}
	stripped, err := json.Marshal(legacyAgain)
	if err != nil {
		t.Fatal(err)
	}
	policy := MtprotoInboundPolicyOf(string(stripped))
	if !policy.ModeClassic || !policy.ModeSecure || !policy.ModeTls {
		t.Errorf("re-resolving the mirrored blob lost modes: %v/%v/%v",
			policy.ModeClassic, policy.ModeSecure, policy.ModeTls)
	}
	if policy.TlsDomain != "www.cloudflare.com" {
		t.Errorf("re-resolving the mirrored blob gave tlsDomain %q", policy.TlsDomain)
	}
	if policy.UserLimit == nil || *policy.UserLimit != 4 {
		t.Errorf("re-resolving the mirrored blob gave userLimit %v", policy.UserLimit)
	}
}

// The mirror writes keys nothing here reads, so it must not move the generated config by
// a single byte: generateServerConfig compares against the file on disk and telemt
// reloads on any write.
func TestMtprotoMirrorDoesNotMoveTheGeneratedConfig(t *testing.T) {
	newInboundDB(t)
	seeded := seedMtprotoInbound(t, 9454, mtprotoMigratedBlob)
	before := renderMtproto(t, storedInbound(t, seeded.Id))

	s := &MtprotoService{}
	if err := s.MirrorInboundSettingsToClients(); err != nil {
		t.Fatalf("mirror: %v", err)
	}
	after := storedInbound(t, seeded.Id)
	if after.Settings == mtprotoMigratedBlob {
		t.Fatal("the mirror wrote nothing, so this test is not proving anything")
	}
	if got := renderMtproto(t, after); got != before {
		t.Errorf("the mirror changed the generated config:\n--- before ---\n%s\n--- after ---\n%s", before, got)
	}
}
