package awg

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
)

// PORT NOTE: awg_devices_test.go's wg-c mirror cases live in internal/vpn/wgc
// (their service lives there now). The DB-backed flows of vpn-ui's suite are
// controllers-wave material (see wgc's test doc note).

// User Limit K must yield K SEPARATE configs: K keypairs and K distinct tunnel IPs.
//
// The bug this pins: at K=2 the panel minted one keypair and rendered one config, so
// importing it on two machines gave both the same Address (and, sharing a keypair, they
// could not both stay connected -- the server keeps one endpoint per peer).
func TestAwgUserLimitYieldsOneConfigPerDevice(t *testing.T) {
	k := 2
	inb := &model.Inbound{
		Id: 7, Protocol: defaults.ProtoAWG, Port: 51821, Enable: true,
		Settings: `{"ipRanges":["10.8.7.2-10.8.7.254"],"userLimit":2,
			"clients":[{"email":"two@t","enable":true}]}`,
	}

	var s AwgService
	if _, err := s.ReconcileKeys(inb); err != nil {
		t.Fatalf("ReconcileKeys: %v", err)
	}

	// K device slots, each with its own keypair.
	var parsed awgSettings
	if err := json.Unmarshal([]byte(inb.Settings), &parsed); err != nil {
		t.Fatalf("settings: %v", err)
	}
	devs := parsed.Clients[0].deviceList()
	if len(devs) != k {
		t.Fatalf("device slots = %d, want %d (User Limit must provision one keypair per device)", len(devs), k)
	}
	if devs[0].PrivKey == devs[1].PrivKey || devs[0].PubKey == devs[1].PubKey {
		t.Fatal("devices share a keypair: both would fight over the peer's single endpoint, so only one could stay online")
	}

	cfgs, err := s.RenderClientConfigs(inb, "two@t", "example.test")
	if err != nil {
		t.Fatalf("RenderClientConfigs: %v", err)
	}
	if len(cfgs) != k {
		t.Fatalf("configs = %d, want %d (one per device to import on separate machines)", len(cfgs), k)
	}

	// The load-bearing assertion: distinct Address per device, each a /32.
	seenIP := map[string]bool{}
	for i, c := range cfgs {
		if seenIP[c.IP] {
			t.Fatalf("config %d reuses tunnel IP %s: two devices would be assigned the same IPv4", i, c.IP)
		}
		seenIP[c.IP] = true
		if !strings.HasSuffix(c.IP, "/32") {
			t.Errorf("config %d IP = %s, want a /32 (a block-wide Address is what collided before)", i, c.IP)
		}
		if !strings.Contains(c.Config, "Address = "+c.IP) {
			t.Errorf("config %d Address line does not carry %s", i, c.IP)
		}
		// Obfuscation must still be present on every device's config.
		if !strings.Contains(c.Config, "Jc = ") || !strings.Contains(c.Config, "H1 = ") {
			t.Errorf("config %d lost its AmneziaWG obfuscation params", i)
		}
	}

	// Each config must carry its OWN private key, else they are the same credential.
	keyOf := func(cfg string) string {
		for _, line := range strings.Split(cfg, "\n") {
			if v, ok := strings.CutPrefix(line, "PrivateKey = "); ok {
				return v
			}
		}
		return ""
	}
	if keyOf(cfgs[0].Config) == keyOf(cfgs[1].Config) {
		t.Fatal("both configs carry the same PrivateKey")
	}
}

// Every device IP must fall inside the account's block CIDR. That CIDR is the single key
// used for nft accounting, Xray source routing and the speed-limit sidecar, so a device
// outside it would browse untracked: unbilled, unrouted and unlimited.
func TestAwgAccountBlockCoversEveryDevice(t *testing.T) {
	inb := &model.Inbound{
		Id: 11, Protocol: defaults.ProtoAWG, Port: 51821, Enable: true,
		Settings: `{"ipRanges":["10.8.11.2-10.8.11.254"],"userLimit":4,
			"clients":[{"email":"cover@t","enable":true}]}`,
	}
	var s AwgService
	if _, err := s.ReconcileKeys(inb); err != nil {
		t.Fatalf("ReconcileKeys: %v", err)
	}
	settings, err := s.parseSettings(inb)
	if err != nil {
		t.Fatalf("parseSettings: %v", err)
	}
	cidr := s.awgAccountCIDR(inb, settings, 0)
	_, block, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("account CIDR %q: %v", cidr, err)
	}
	ips := s.awgDeviceIPs(inb, settings, 0)
	if len(ips) != 4 {
		t.Fatalf("device IPs = %d, want 4", len(ips))
	}
	for _, ip := range ips {
		if !block.Contains(net.ParseIP(ip)) {
			t.Errorf("device IP %s is outside the account block %s: its traffic would be unbilled and unlimited", ip, cidr)
		}
	}
}

// Lowering the User Limit must revoke the surplus device keys, or the limit is unenforceable.
func TestAwgLoweringUserLimitTrimsDevices(t *testing.T) {
	inb := &model.Inbound{
		Id: 8, Protocol: defaults.ProtoAWG, Port: 51821, Enable: true,
		Settings: `{"ipRanges":["10.8.8.2-10.8.8.254"],"userLimit":4,
			"clients":[{"email":"trim@t","enable":true}]}`,
	}
	var s AwgService
	if _, err := s.ReconcileKeys(inb); err != nil {
		t.Fatalf("ReconcileKeys: %v", err)
	}

	// Drop to 2 and reconcile again.
	inb.Settings = strings.Replace(inb.Settings, `"userLimit":4`, `"userLimit":2`, 1)
	if _, err := s.ReconcileKeys(inb); err != nil {
		t.Fatalf("ReconcileKeys (lowered): %v", err)
	}
	var parsed awgSettings
	if err := json.Unmarshal([]byte(inb.Settings), &parsed); err != nil {
		t.Fatalf("settings: %v", err)
	}
	if got := len(parsed.Clients[0].deviceList()); got != 2 {
		t.Fatalf("device slots after lowering = %d, want 2 (stale keys would still connect)", got)
	}
}

// A single-device account (K<=1) keeps exactly one config, so the common case is unchanged.
func TestAwgSingleDeviceUnchanged(t *testing.T) {
	inb := &model.Inbound{
		Id: 9, Protocol: defaults.ProtoAWG, Port: 51821, Enable: true,
		Settings: `{"ipRanges":["10.8.9.2-10.8.9.254"],"userLimit":1,
			"clients":[{"email":"one@t","enable":true}]}`,
	}
	var s AwgService
	if _, err := s.ReconcileKeys(inb); err != nil {
		t.Fatalf("ReconcileKeys: %v", err)
	}
	cfgs, err := s.RenderClientConfigs(inb, "one@t", "example.test")
	if err != nil {
		t.Fatalf("RenderClientConfigs: %v", err)
	}
	if len(cfgs) != 1 {
		t.Fatalf("configs = %d, want 1", len(cfgs))
	}
	if cfgs[0].Remark != "" {
		t.Errorf("single-device config should not be labelled a device slot, got %q", cfgs[0].Remark)
	}
}

// ReconcileKeys must mint the AWG obfuscation defaults + four DISTINCT magic headers
// (they are what obfuscates the handshake; duplicates would defeat the point).
func TestAwgReconcileMintsObfuscation(t *testing.T) {
	inb := &model.Inbound{
		Id: 13, Protocol: defaults.ProtoAWG, Port: 51821, Enable: true,
		Settings: `{"ipRanges":["10.8.13.2-10.8.13.254"],"userLimit":1,
			"clients":[{"email":"obfs@t","enable":true}]}`,
	}
	var s AwgService
	if _, err := s.ReconcileKeys(inb); err != nil {
		t.Fatalf("ReconcileKeys: %v", err)
	}
	var parsed awgSettings
	if err := json.Unmarshal([]byte(inb.Settings), &parsed); err != nil {
		t.Fatalf("settings: %v", err)
	}
	obfs := parsed.resolveObfs()
	if obfs.Jc != 4 || obfs.Jmin != 8 || obfs.Jmax != 80 || obfs.S1 != 77 || obfs.S2 != 90 {
		t.Errorf("obfuscation defaults not applied: %+v", obfs)
	}
	headers := map[string]bool{obfs.H1: true, obfs.H2: true, obfs.H3: true, obfs.H4: true}
	if len(headers) != 4 {
		t.Errorf("magic headers are not distinct: %v", headers)
	}
	for h := range headers {
		if h == "" {
			t.Error("a magic header is empty")
		}
	}
	cfgs, err := s.RenderClientConfigs(inb, "obfs@t", "example.test")
	if err != nil || len(cfgs) != 1 {
		t.Fatalf("RenderClientConfigs: %d configs, err=%v", len(cfgs), err)
	}
	for _, line := range []string{
		"Jc = 4", "Jmin = 8", "Jmax = 80", "S1 = 77", "S2 = 90",
		"H1 = " + obfs.H1, "H4 = " + obfs.H4,
	} {
		if !strings.Contains(cfgs[0].Config, line+"\n") {
			t.Errorf("client config missing %q:\n%s", line, cfgs[0].Config)
		}
	}
}

// The interface name must stay inside IFNAMSIZ (the pxpanel-awg prefix costs 11 of the
// 15 characters) and keep the exact shape the manifest's ownership test matches.
func TestAwgIfaceNameShape(t *testing.T) {
	for _, id := range []int{0, 1, 12, 4096, 9999} {
		name := awgIfaceName(id)
		if len(name) > 15 {
			t.Errorf("awgIfaceName(%d) = %q exceeds IFNAMSIZ-1 (the pxpanel-awg prefix leaves 4 digits)", id, name)
		}
		if !manifest.AwgOwnedName(name) {
			t.Errorf("awgIfaceName(%d) = %q is not matched by the ownership name shape; the stale-link sweep would never reclaim it", id, name)
		}
	}
}
