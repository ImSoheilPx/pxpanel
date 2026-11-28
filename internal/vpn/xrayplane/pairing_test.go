// Paired-inbound builder tests: the ported vpn-ui pairing shapes.
package xrayplane

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

func TestTproxyPortConvention(t *testing.T) {
	if got := TproxyPort(&model.Inbound{Id: 42}); got != 12342 {
		t.Errorf("TproxyPort(42) = %d, want 12342 (panel-wide 12300+N)", got)
	}
}

// The dokodemo builder is the byte-identical body all nine tunnel protocols
// carried; pin the shape the nftables TPROXY rules and Xray both depend on.
func TestGetDokodemoConfigShape(t *testing.T) {
	cfg := GetDokodemoConfig(&model.Inbound{Id: 7, Protocol: defaults.ProtoL2TP, Tag: "l2tp-1"})
	if cfg.Protocol != "dokodemo-door" {
		t.Errorf("protocol = %q, want dokodemo-door", cfg.Protocol)
	}
	if cfg.Port != 12307 {
		t.Errorf("port = %d, want 12307", cfg.Port)
	}
	if cfg.Tag != "l2tp-1" {
		t.Errorf("tag = %q, want the inbound's own tag so operator rules target it", cfg.Tag)
	}
	var settings struct {
		Network        string `json:"network"`
		FollowRedirect bool   `json:"followRedirect"`
	}
	if err := json.Unmarshal(cfg.Settings, &settings); err != nil {
		t.Fatalf("settings decode: %v", err)
	}
	if settings.Network != "tcp,udp" || !settings.FollowRedirect {
		t.Errorf("settings = %+v, want tcp,udp + followRedirect (TPROXY capture)", settings)
	}
	var stream struct {
		Sockopt struct {
			Tproxy string `json:"tproxy"`
			Mark   int    `json:"mark"`
		} `json:"sockopt"`
	}
	if err := json.Unmarshal(cfg.StreamSettings, &stream); err != nil {
		t.Fatalf("streamSettings decode: %v", err)
	}
	if stream.Sockopt.Tproxy != "tproxy" || stream.Sockopt.Mark != 255 {
		t.Errorf("sockopt = %+v, want tproxy/mark 255 (the mark the nftables rules match)", stream.Sockopt)
	}
}

// The mtproto pairing: password auth, no UDP, tls sniffing, per-client identity
// on the socks username.
func TestMtprotoSocksConfigShape(t *testing.T) {
	accounts := []SocksAccount{
		{User: MtprotoSystemAccount, Pass: MtprotoSystemAccount},
		{User: "a@x", Pass: "a@x"},
	}
	cfg := MtprotoSocksConfig(&model.Inbound{Id: 3, Tag: "mt-1"}, accounts)
	if cfg == nil {
		t.Fatal("MtprotoSocksConfig returned nil for a routed inbound")
	}
	if cfg.Protocol != "socks" || cfg.Port != 12303 || cfg.Tag != "mt-1" {
		t.Errorf("shape = %s:%d tag %q, want socks:12303 tag mt-1", cfg.Protocol, cfg.Port, cfg.Tag)
	}
	var settings struct {
		Auth     string         `json:"auth"`
		Accounts []SocksAccount `json:"accounts"`
		UDP      bool           `json:"udp"`
	}
	if err := json.Unmarshal(cfg.Settings, &settings); err != nil {
		t.Fatalf("settings decode: %v", err)
	}
	if settings.Auth != "password" || settings.UDP {
		t.Errorf("auth = %q udp = %v, want password/false", settings.Auth, settings.UDP)
	}
	if len(settings.Accounts) != 2 || settings.Accounts[0].User != MtprotoSystemAccount {
		t.Errorf("accounts = %+v, want the system account first", settings.Accounts)
	}
	if string(cfg.Sniffing) != socksSniffingMtproto {
		t.Errorf("sniffing = %s, want %s", cfg.Sniffing, socksSniffingMtproto)
	}
}

// The ssh pairing is mtproto with UDP ASSOCIATE and a different sniffing set.
func TestSshSocksConfigShape(t *testing.T) {
	cfg := SshSocksConfig(&model.Inbound{Id: 9, Tag: "ssh-1"}, []SocksAccount{{User: "a@x", Pass: "a@x"}})
	if cfg == nil {
		t.Fatal("SshSocksConfig returned nil for an inbound with accounts")
	}
	var settings struct {
		UDP bool `json:"udp"`
	}
	if err := json.Unmarshal(cfg.Settings, &settings); err != nil {
		t.Fatalf("settings decode: %v", err)
	}
	if !settings.UDP {
		t.Error("ssh socks udp = false, want true (the udpgw bridge needs UDP ASSOCIATE)")
	}
	if string(cfg.Sniffing) != socksSniffingSsh {
		t.Errorf("sniffing = %s, want %s", cfg.Sniffing, socksSniffingSsh)
	}

	// No accounts -> nil: a socks inbound with none would reject every egress.
	if got := SshSocksConfig(&model.Inbound{Id: 9}, nil); got != nil {
		t.Errorf("SshSocksConfig with no accounts = %+v, want nil", got)
	}
}

// The default mtproto reader: activeClients semantics (email+secret, sorted, NO
// enable filter — ported as-is), the system account first, dedup by email.
func TestDefaultMtprotoAccounts(t *testing.T) {
	settings := `{"clients":[
		{"email":"b@x","secret":"s2","enable":false},
		{"email":"a@x","secret":"s1","enable":true},
		{"email":"dup@x","secret":"s3","enable":true},
		{"email":"dup@x","secret":"s4","enable":true},
		{"email":"nosecret@x","secret":"","enable":true}
	]}`
	accounts, routed := defaultMtprotoAccounts(settings)
	if !routed {
		t.Fatal("routed = false, want true (no adtag)")
	}
	want := []string{MtprotoSystemAccount, "a@x", "b@x", "dup@x"}
	if len(accounts) != len(want) {
		t.Fatalf("accounts = %+v, want %v", accounts, want)
	}
	for i, w := range want {
		if accounts[i].User != w {
			t.Errorf("accounts[%d].User = %q, want %q (sorted, system first, deduped)", i, accounts[i].User, w)
		}
	}

	// anyAdtag: ANY tagged account takes the whole inbound off Xray routing.
	tagged := `{"clients":[{"email":"a@x","secret":"s1","adtagEnable":true,"adtag":"12345"}]}`
	if accounts, routed := defaultMtprotoAccounts(tagged); routed || accounts != nil {
		t.Errorf("tagged inbound: accounts=%v routed=%v, want nil/false (middle-proxy egresses directly)", accounts, routed)
	}
	// Enable-without-tag is a no-op. Enable field alone never routes.
	if _, routed := defaultMtprotoAccounts(`{"clients":[{"email":"","secret":"s"}]}`); !routed {
		t.Error("empty-client inbound should still report routed=true; accounts list handles emptiness")
	}
}

// The default ssh reader: id+password+email+enable, dedup by email, and
// routed=false when nothing usable remains.
func TestDefaultSshAccounts(t *testing.T) {
	settings := `{"clients":[
		{"id":"u1","password":"p1","email":"a@x","enable":true},
		{"id":"u2","password":"p2","email":"b@x","enable":false},
		{"id":"","password":"p3","email":"c@x","enable":true},
		{"id":"u4","password":"p4","email":"a@x","enable":true}
	]}`
	accounts, routed := defaultSshAccounts(settings)
	if !routed {
		t.Fatal("routed = false, want true")
	}
	if len(accounts) != 1 || accounts[0].User != "a@x" {
		t.Errorf("accounts = %+v, want exactly a@x (disabled/credential-less dropped, deduped)", accounts)
	}

	if accounts, routed := defaultSshAccounts(`{"clients":[{"id":"u","password":"p","email":"e@x","enable":false}]}`); routed || accounts != nil {
		t.Errorf("all-disabled inbound: accounts=%v routed=%v, want nil/false", accounts, routed)
	}
}

// RelayAccountsFor dispatches, and a registered provider overrides the default.
func TestRelayAccountsForOverride(t *testing.T) {
	inbound := &model.Inbound{Id: 5, Protocol: defaults.ProtoSSH, Settings: `{"clients":[{"id":"u","password":"p","email":"e@x","enable":true}]}`}
	if accounts, routed := RelayAccountsFor("ssh", inbound); !routed || len(accounts) != 1 {
		t.Fatalf("default ssh read = %v/%v, want routed with one account", accounts, routed)
	}

	RegisterRelayAccounts(string(defaults.ProtoSSH), func(*model.Inbound) ([]SocksAccount, bool) {
		return []SocksAccount{{User: "override", Pass: "override"}}, true
	})
	defer RegisterRelayAccounts(string(defaults.ProtoSSH), nil)

	accounts, routed := RelayAccountsFor("ssh", inbound)
	if !routed || len(accounts) != 1 || accounts[0].User != "override" {
		t.Errorf("override read = %v/%v, want the registered provider's account", accounts, routed)
	}

	// Non-relay protocols have no reader at all.
	if accounts, routed := RelayAccountsFor("l2tp", inbound); routed || accounts != nil {
		t.Errorf("l2tp resolved as a relay: %v/%v", accounts, routed)
	}
}

// InjectPairedInbounds: one dokodemo per enabled tunnel inbound, one socks per
// routable relay, and NOTHING for the Xray-native protocols (they are the
// caller's job) or for disabled inbounds.
func TestInjectPairedInbounds(t *testing.T) {
	cfg := &xray.Config{InboundConfigs: []xray.InboundConfig{{Tag: "native", Protocol: "vless"}}}
	inbounds := []*model.Inbound{
		{Id: 1, Protocol: defaults.ProtoL2TP, Tag: "l2tp-a", Enable: true, Settings: `{"clients":[]}`},
		{Id: 2, Protocol: defaults.ProtoPPTP, Tag: "pptp-a", Enable: false},
		{Id: 3, Protocol: "vless", Tag: "native-2", Enable: true, Settings: `{"clients":[]}`},
		{
			Id: 4, Protocol: defaults.ProtoSSH, Tag: "ssh-a", Enable: true,
			Settings: `{"clients":[{"id":"u","password":"p","email":"e@x","enable":true}]}`,
		},
		{
			Id: 5, Protocol: defaults.ProtoMTProto, Tag: "mt-a", Enable: true,
			Settings: `{"clients":[{"email":"m@x","secret":"s","adtagEnable":true,"adtag":"7"}]}`,
		},
		{
			Id: 6, Protocol: defaults.ProtoMTProto, Tag: "mt-b", Enable: true,
			Settings: `{"clients":[{"email":"m@x","secret":"s"}]}`,
		},
	}
	InjectPairedInbounds(cfg, inbounds)

	var got []string
	for _, ib := range cfg.InboundConfigs {
		got = append(got, ib.Protocol+":"+ib.Tag+":"+strconv.Itoa(ib.Port-TproxyPortBase))
	}
	want := []string{
		"vless:native:-12300", // untouched pre-existing entry (port 0)
		"dokodemo-door:l2tp-a:1",
		"socks:ssh-a:4",
		"socks:mt-b:6",
	}
	if len(got) != len(want) {
		t.Fatalf("inbounds = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("inbounds[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// The predicates match vpn-ui's isVpnProtocol/isRelayProtocol exactly.
func TestProtocolPredicates(t *testing.T) {
	for _, p := range defaults.TunnelProtocols {
		if !IsVpnProtocol(model.Protocol(p)) {
			t.Errorf("IsVpnProtocol(%q) = false, want true", p)
		}
	}
	if IsVpnProtocol(defaults.ProtoMTProto) || IsVpnProtocol("vless") {
		t.Error("relays/native protocols must not read as VPN pool protocols")
	}
	if !IsRelayProtocol(defaults.ProtoMTProto) || !IsRelayProtocol(defaults.ProtoSSH) {
		t.Error("mtproto/ssh must read as relays")
	}
	if IsRelayProtocol(defaults.ProtoL2TP) {
		t.Error("l2tp must not read as a relay")
	}
}
