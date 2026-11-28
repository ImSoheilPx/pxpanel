// Operator routing-rule semantics over the VPN paired inbounds: an operator's
// panel rules (domain / ip-cidr / per-email) must reach the dokodemo and
// relay-socks tags untouched where Xray matches them itself, get translated
// where only a source match can carry them, and never displace the backstop.
// Exercises the translation over a SYNTHETIC inbound set (ssh/mtproto socks +
// l2tp dokodemo) built through InjectPairedInbounds, no database.
package xrayplane

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

// vpnTagConfig builds a config whose inbound set mirrors a small live panel:
// one native vless inbound (the caller's job, pre-inserted), one l2tp dokodemo
// pair, one ssh socks pair and one routable (non-adtag) mtproto socks pair —
// then appends the operator's rules as given.
func vpnTagConfig(t *testing.T, rules []map[string]any) *xray.Config {
	t.Helper()
	cfg := configWithRules(t, rules)
	cfg.InboundConfigs = []xray.InboundConfig{{Tag: "vless-native", Protocol: "vless"}}
	inbounds := []*model.Inbound{
		{Id: 1, Protocol: defaults.ProtoL2TP, Tag: "l2tp-a", Enable: true, Settings: `{"clients":[]}`},
		{
			Id: 2, Protocol: defaults.ProtoSSH, Tag: "ssh-a", Enable: true,
			Settings: `{"clients":[{"id":"u","password":"p","email":"ssh@x","enable":true}]}`,
		},
		{
			Id: 3, Protocol: defaults.ProtoMTProto, Tag: "mt-a", Enable: true,
			Settings: `{"clients":[{"email":"mt@x","secret":"s"}]}`,
		},
	}
	InjectPairedInbounds(cfg, inbounds)
	return cfg
}

// inboundTags returns the tags present in the config's inbound set.
func inboundTags(t *testing.T, cfg *xray.Config) []string {
	t.Helper()
	var tags []string
	for _, ib := range cfg.InboundConfigs {
		tags = append(tags, ib.Tag)
	}
	return tags
}

// assertOperatorRulesUntouched pins the translation's one permitted change:
// operator rules keep their content and relative order, and the only thing
// ever appended behind them is the backstop pair (valid-IP pass-through to the
// default outbound, then the /12 to the blackhole) — vpn-ui appended that
// backstop whenever the email map had any address and a blackhole outbound
// exists, regardless of which rules matched, so "untouched" means "the rules
// the operator wrote are still there, in order, unmodified".
func assertOperatorRulesUntouched(t *testing.T, before, after []map[string]any) {
	t.Helper()
	if len(after) < len(before) {
		t.Fatalf("rules shrank: %d -> %d", len(before), len(after))
	}
	for i, want := range before {
		wantJSON, _ := json.Marshal(want)
		gotJSON, _ := json.Marshal(after[i])
		if string(wantJSON) != string(gotJSON) {
			t.Fatalf("operator rule %d was modified:\nbefore %s\nafter  %s", i, wantJSON, gotJSON)
		}
	}
	trailing := after[len(before):]
	if len(trailing) > 2 {
		t.Fatalf("more than the backstop pair was appended: %+v", trailing)
	}
	if len(trailing) == 2 {
		if src, _ := trailing[0]["source"].([]any); trailing[0]["outboundTag"] != "proxy-all" || src == nil {
			t.Errorf("backstop entry 0 = %+v, want the valid-IP pass-through to the default outbound", trailing[0])
		}
		if src, _ := trailing[1]["source"].([]any); !reflect.DeepEqual(src, []any{VpnAddrSpace}) || trailing[1]["outboundTag"] != "block-vpn" {
			t.Errorf("backstop entry 1 = %+v, want %s to block-vpn", trailing[1], VpnAddrSpace)
		}
	}
}

// Destination rules (domain, ip-cidr) must pass through the translation
// UNTOUCHED: Xray matches them against the destination on EVERY inbound —
// the l2tp dokodemo pair (sniffed TLS SNI, or the raw IP the client sent),
// the ssh socks pair (the hostname the client sent in direct-tcpip, encoded
// ATYP=domain), and the native inbounds alike. Rewriting, reordering or
// dropping them is how "the rule only applies to vless" bugs are born.
func TestDestinationRulesPassThroughUntouchedOverVpnTags(t *testing.T) {
	before := []map[string]any{
		{"type": "field", "inboundTag": []any{"api"}, "outboundTag": "api"},
		{"type": "field", "domain": []any{"domain:warp.example", "geosite:netflix"}, "outboundTag": "warp"},
		{"type": "field", "ip": []any{"203.0.113.0/24", "geoip:ir"}, "outboundTag": "warp"},
	}
	cfg := vpnTagConfig(t, before)

	// The map/natives shapes the config build would produce: one pool account
	// with a tunnel IP, relays matching by socks username.
	translateRoutingRulesWith(cfg,
		map[string][]string{"pool@x": {"10.0.1.2"}},
		map[string]bool{})

	assertOperatorRulesUntouched(t, before, rulesOf(t, cfg))
}

// The per-email rule: the pool email becomes a source match on its tunnel IPs
// (a dokodemo inbound has no user to match), while the ssh/mtproto emails stay
// as user matches — the relays' accounts ride the socks username (Xray copies
// it to inbound.User.Email), so a user rule is exactly what routes them.
// Translating a relay email to a source match would produce a rule that never
// matches anything (a relay has no tunnel IP) and silently stop routing it.
func TestPerEmailRuleSplitsPoolFromRelayOverVpnTags(t *testing.T) {
	cfg := vpnTagConfig(t, []map[string]any{
		{"type": "field", "user": []any{"pool@x", "ssh@x", "mt@x"}, "outboundTag": "warp"},
	})
	if got := inboundTags(t, cfg); len(got) != 4 {
		t.Fatalf("inbound tags = %v, want the native + 3 paired inbounds", got)
	}

	translateRoutingRulesWith(cfg,
		map[string][]string{"pool@x": {"10.0.1.2"}},
		map[string]bool{})

	// Rule 0: the source rule for the pool account (other matchers preserved).
	source := routingRule(t, cfg, 0)
	if src, ok := source["source"].([]any); !ok || !reflect.DeepEqual(src, []any{"10.0.1.2"}) {
		t.Errorf("rule 0 source = %v, want [10.0.1.2]", source["source"])
	}
	if source["outboundTag"] != "warp" {
		t.Errorf("rule 0 outboundTag = %v, want warp", source["outboundTag"])
	}
	if _, has := source["user"]; has {
		t.Error("rule 0 kept a user match; the pool email must move to source matching")
	}

	// Rule 1: the user rule keeps the relay emails only.
	kept := routingRule(t, cfg, 1)
	if users, _ := kept["user"].([]any); !reflect.DeepEqual(users, []any{"ssh@x", "mt@x"}) {
		t.Errorf("rule 1 user = %v, want the ssh+mtproto emails kept as user matches", users)
	}
	if _, has := kept["source"]; has {
		t.Errorf("rule 1 gained a source match on a relay email: %+v (a relay has no tunnel IP; the rule would match nothing)", kept)
	}

	// Backstop appended behind every operator rule.
	if n := routingRuleCount(t, cfg); n != 4 {
		t.Fatalf("rules = %d, want 4 (source + user + the two backstop entries)", n)
	}
	pass := routingRule(t, cfg, 2)
	if src, _ := pass["source"].([]any); !reflect.DeepEqual(src, []any{"10.0.1.2"}) || pass["outboundTag"] != "proxy-all" {
		t.Errorf("backstop pass-through = %+v, want 10.0.1.2 to the default outbound", pass)
	}
	hole := routingRule(t, cfg, 3)
	if src, _ := hole["source"].([]any); !reflect.DeepEqual(src, []any{VpnAddrSpace}) || hole["outboundTag"] != "block-vpn" {
		t.Errorf("backstop blackhole = %+v, want %s to block-vpn", hole, VpnAddrSpace)
	}
}

// An inboundTag-restricted operator rule targeting a VPN tag must survive the
// translation untouched — that restriction is exactly how an operator routes
// one dokodemo/socks pair. The paired inbound carries inbound.Tag, so the
// restriction resolves against the injected config.
func TestInboundTagRuleForVpnTagSurvives(t *testing.T) {
	before := []map[string]any{{
		"type": "field", "inboundTag": []any{"ssh-a", "mt-a"},
		"domain": []any{"domain:warp.example"}, "outboundTag": "warp",
	}}
	cfg := vpnTagConfig(t, before)

	translateRoutingRulesWith(cfg, map[string][]string{"pool@x": {"10.0.1.2"}}, map[string]bool{})

	assertOperatorRulesUntouched(t, before, rulesOf(t, cfg))
}

// A user rule for a native-only email must keep its user match (the core
// terminates that traffic itself) while the backstop still lands behind it.
func TestNativeEmailStaysUserMatched(t *testing.T) {
	cfg := vpnTagConfig(t, []map[string]any{
		{"type": "field", "user": []any{"vless@x"}, "outboundTag": "warp"},
	})
	translateRoutingRulesWith(cfg,
		map[string][]string{"pool@x": {"10.0.1.2"}},
		map[string]bool{"vless@x": true}) // normalized native email

	got := routingRule(t, cfg, 0)
	if users, _ := got["user"].([]any); !reflect.DeepEqual(users, []any{"vless@x"}) {
		t.Errorf("user rule = %v, want vless@x kept (native traffic matches by user)", users)
	}
	if n := routingRuleCount(t, cfg); n != 3 {
		t.Fatalf("rules = %d, want 3 (user + the two backstop entries)", n)
	}
}

// rulesOf decodes the config's rules list (order preserved).
func rulesOf(t *testing.T, cfg *xray.Config) []map[string]any {
	t.Helper()
	var routing map[string]any
	if err := json.Unmarshal(cfg.RouterConfig, &routing); err != nil {
		t.Fatalf("routing decode: %v", err)
	}
	raw, _ := routing["rules"].([]any)
	rules := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		m, _ := r.(map[string]any)
		rules = append(rules, m)
	}
	return rules
}
