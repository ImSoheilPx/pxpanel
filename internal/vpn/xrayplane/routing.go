// Routing-rule translation and the email->tunnel-IP map, ported from vpn-ui
// web/service/xray.go (translateVpnRoutingRules, buildXrayNativeEmailSet,
// RemoveIndex) and web/service/radius.go (BuildVpnEmailToIPMap). The map needs
// only the vpnrange block math for the eight PPP-family protocols; OpenVPN's
// transport-aware reader is registered by its own wave.
package xrayplane

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/accounts"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/log"
	vpnrange "github.com/ImSoheilPx/pxpanel/internal/vpn/range"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

// VpnAddrSpace is the covering /12 (10.0.0.0-10.15.255.255) for the protocol
// /16s, carriers included — the same value the nftables package trusts and
// firewalld trusts as a source prefix. (vpn-ui web/service/nftables.go
// vpnAddrSpace; duplicated as a constant here rather than imported because the
// routing rules and the firewall must agree about it without one importing the
// other's package graph.)
const VpnAddrSpace = "10.0.0.0/12"

// RemoveIndex removes an element at the specified index from a slice.
// Returns a new slice with the element removed.
// (vpn-ui web/service/xray.go RemoveIndex.)
func RemoveIndex(s []any, index int) []any {
	return append(s[:index], s[index+1:]...)
}

// ---------------------------------------------------------------------------
// email -> tunnel-IP map (vpn-ui web/service/radius.go BuildVpnEmailToIPMap)
// ---------------------------------------------------------------------------

// OpenVPNAddressMapFn produces the OpenVPN part of the email->IP map: one
// deterministic CCD IP per enabled transport block (udp 10.2.x, tcp 10.3.x
// mirror), K device IPs per account when the User Limit says so. It needs the
// openvpn settings shape (udpEnabled/tcpEnabled/effectiveRanges/ovpnBlockFor),
// which belongs to the openvpn wave — register there with
// RegisterOpenVPNAddressMap.
type OpenVPNAddressMapFn func() map[string][]string

var (
	ovpnMapMu      sync.RWMutex
	ovpnAddressMap OpenVPNAddressMapFn
)

// RegisterOpenVPNAddressMap attaches the OpenVPN transport-aware reader.
// TODO(openvpn wave): call this from the openvpn service init.
func RegisterOpenVPNAddressMap(fn OpenVPNAddressMapFn) {
	ovpnMapMu.Lock()
	ovpnAddressMap = fn
	ovpnMapMu.Unlock()
}

// nextPow2 returns the smallest power of two >= n (>=1).
// (vpn-ui web/service/wgc.go nextPow2.)
func nextPow2(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// log2i returns floor(log2(n)) for n >= 1.
func log2i(n int) int {
	log2 := 0
	for n > 1 {
		n >>= 1
		log2++
	}
	return log2
}

// BuildVpnEmailToIPMap returns a map of email → deterministic tunnel IP(s) for all
// enabled VPN clients. Used by TranslateVpnRoutingRules to translate
// email-based routing rules into source-IP rules. Values are slices: an OpenVPN
// client maps to one IP per enabled transport, and under User Limit K>=2 every
// account maps to its K device IPs (times the enabled transports for OpenVPN).
func BuildVpnEmailToIPMap() map[string][]string {
	result := make(map[string][]string)
	db := vpn.DB()
	if db == nil {
		return result
	}

	// --- L2TP / PPTP / OpenConnect / SSTP / IKEv2 / WGC / AWG / GRE: single-network
	// block, one IP (or K device IPs) per account. ---
	var pppInbounds []*model.Inbound
	db.Where("protocol IN ? AND enable = ?", []string{"l2tp", "pptp", "openconnect", "sstp", "ikev2", "wg-c", "awg", "gre"}, true).Find(&pppInbounds)
	for _, inbound := range pppInbounds {
		for email, ips := range pppInboundEmailIPs(inbound.Protocol, inbound.Id, inbound.Settings) {
			result[email] = append(result[email], ips...)
		}
	}

	// --- OpenVPN: one deterministic CCD IP per enabled transport block. The
	// transport reader needs the openvpn settings shape (udp/tcp enabled, effective
	// ranges, per-transport block) owned by the openvpn wave; until it registers its
	// extension the OpenVPN family contributes nothing here.
	ovpnMapMu.RLock()
	fn := ovpnAddressMap
	ovpnMapMu.RUnlock()
	if fn != nil {
		for email, ips := range fn() {
			result[email] = append(result[email], ips...)
		}
	}

	return result
}

// pppInboundEmailIPs computes the email -> tunnel-IP entries for ONE PPP-family
// inbound from its stored settings JSON. Pure (no DB), so the address-plan
// composition is testable without a database; BuildVpnEmailToIPMap applies it to
// every enabled inbound of the family.
func pppInboundEmailIPs(protocol model.Protocol, inboundId int, settingsJSON string) map[string][]string {
	result := map[string][]string{}

	type clientEntry struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Slot  *int   `json:"slot"` // address-pool slot; nil = fall back to list index
	}
	type pppSettingsJSON struct {
		IpRanges  []string      `json:"ipRanges"`
		IpRange   string        `json:"ipRange"`
		UserLimit *int          `json:"userLimit"` // nil = absent (legacy => 1); 0 = no limit
		AuthMode  string        `json:"authMode"`  // ikev2 only: psk/eap-tls = one local-auth account
		Clients   []clientEntry `json:"clients"`
	}

	var settings pppSettingsJSON
	if err := json.Unmarshal([]byte(settingsJSON), &settings); err != nil {
		return result
	}
	ranges := settings.IpRanges
	if len(ranges) == 0 && settings.IpRange != "" {
		ranges = []string{settings.IpRange}
	}
	k := vpnrange.EffectiveUserLimit(settings.UserLimit)
	// K>=2: each account maps to its K device IPs, so one source rule (an
	// explicit IP list) covers every device. K==1 keeps the legacy single IP.
	subnets := vpnrange.PppSubnetsOrDefault(ranges, string(protocol), inboundId)
	for i, client := range settings.Clients {
		if client.Email == "" {
			continue
		}
		slot := vpnrange.SlotOr(client.Slot, i) // stored slot, not list position
		// ikev2 psk / eap-tls: one local-auth account whose devices lease from a
		// whole-block charon pool. Map it to the entire block CIDR so any pool
		// address routes through Xray instead of hitting the vpnAddrSpace
		// blackhole; the reconcile sweep enforces the real device count.
		if protocol == defaults.ProtoIKEv2 && (settings.AuthMode == "psk" || settings.AuthMode == "eap-tls") {
			if bn, prefix := vpnrange.VpnBlock(ranges, vpnrange.ProtocolBase(string(defaults.ProtoIKEv2)), inboundId); bn != nil {
				result[client.Email] = append(result[client.Email], fmt.Sprintf("%s/%d", bn.String(), prefix))
			}
			continue
		}
		// WireGuard (C) gateway model: the account owns ONE aligned block (a /29-style
		// CIDR); route its whole CIDR (matches wgcAccountBlock) so every IP the router
		// hands out behind the single link flows through Xray.
		if protocol == defaults.ProtoWGC || protocol == defaults.ProtoAWG || protocol == defaults.ProtoGRE {
			// WireGuard (C) / AmneziaWG size the account block with gateway semantics
			// (User Limit 0 = the full 64-device /26), which differs from the shared k above.
			wk := vpnrange.WgcEffectiveK(settings.UserLimit)
			if wk <= 1 {
				if ip := vpnrange.ComputeVpnClientIP(ranges, inboundId, slot, string(protocol)); ip != nil {
					result[client.Email] = append(result[client.Email], ip.String()+"/32")
				}
			} else {
				bs := nextPow2(wk)
				if subnet, hostBase, ok := vpnrange.VpnAccountBlock(subnets, slot, bs); ok {
					result[client.Email] = append(result[client.Email], fmt.Sprintf("%s.%d/%d", subnet, hostBase, 32-log2i(bs)))
				}
			}
			continue
		}
		if k <= 1 {
			if ip := vpnrange.ComputeVpnClientIP(ranges, inboundId, slot, string(protocol)); ip != nil {
				result[client.Email] = append(result[client.Email], ip.String())
			}
		} else {
			result[client.Email] = append(result[client.Email], vpnrange.VpnAccountDeviceIPs(subnets, slot, k)...)
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Routing-rule translation (vpn-ui web/service/xray.go)
// ---------------------------------------------------------------------------

// parseSettingsClients decodes an inbound settings JSON's clients[] array.
// (vpn-ui web/service/migrationaccounts.go parseSettingsClients; kept local so
// this package does not depend on the accounts service internals.)
func parseSettingsClients(settings string) ([]map[string]any, bool) {
	if settings == "" {
		return nil, false
	}
	var parsed struct {
		Clients []map[string]any `json:"clients"`
	}
	if err := json.Unmarshal([]byte(settings), &parsed); err != nil {
		return nil, false
	}
	if len(parsed.Clients) == 0 {
		return nil, false
	}
	return parsed.Clients, true
}

// NativeEmailSet returns the normalized emails that appear on an inbound
// Xray terminates ITSELF, and can therefore match a routing rule's "user" field.
//
// The predicate is the complement of what InjectPairedInbounds consumes: the nine pool
// VPN protocols (IsVpnProtocol) plus the relays (both mtproto planes and ssh), none of
// which hand Xray a user list to match on.
// (vpn-ui web/service/xray.go buildXrayNativeEmailSet.)
func NativeEmailSet() map[string]bool {
	out := map[string]bool{}
	var inbounds []*model.Inbound
	db := vpn.DB()
	if db == nil {
		return out
	}
	if err := db.Model(&model.Inbound{}).
		Select("protocol", "settings", "enable").Find(&inbounds).Error; err != nil {
		log.Warning("could not read inbounds while building the native-email set:", err)
		return out
	}
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		if IsVpnProtocol(inbound.Protocol) || IsRelayProtocol(inbound.Protocol) {
			continue
		}
		clients, ok := parseSettingsClients(inbound.Settings)
		if !ok {
			continue
		}
		for _, entry := range clients {
			email, _ := entry["email"].(string)
			if key := accounts.AccountKeyOf(email); key != "" {
				out[key] = true
			}
		}
	}
	return out
}

// TranslateVpnRoutingRules rewrites routing rules so that "user" (email) matches
// for VPN clients are translated to "source" (IP) matches.
//
// Emails absent from the map are left as "user" rules on purpose, and two very
// different protocol families rely on that: Xray-native ones (vless/vmess), which
// match the user natively, and mtproto, whose account arrives as the socks username
// (see MtprotoSocksConfig). So an operator writes the same
// user:[email] rule for every protocol and this decides the carrier. Do NOT add
// mtproto to BuildVpnEmailToIPMap to "complete" it: a relay has no per-client IP,
// so it would translate the rule into a source match on an IP that never exists
// and the rule would silently stop matching anything.
//
// MUST run AFTER InjectPairedInbounds and LAST in the config build: it also
// appends the blackhole backstop, which has to sit behind every operator rule.
// (vpn-ui web/service/xray.go (*XrayService).translateVpnRoutingRules.)
func TranslateVpnRoutingRules(cfg *xray.Config) {
	if len(cfg.RouterConfig) == 0 {
		return
	}
	translateRoutingRulesWith(cfg, BuildVpnEmailToIPMap(), NativeEmailSet())
}

// translateRoutingRulesWith is the pure half of TranslateVpnRoutingRules, taking
// the email->IP map and the native-email set as arguments so it can be tested
// without a database (vpn-ui's applySshOutboundsWith pattern).
func translateRoutingRulesWith(cfg *xray.Config, vpnMap map[string][]string, nativeEmails map[string]bool) {
	if len(cfg.RouterConfig) == 0 || len(vpnMap) == 0 {
		return
	}

	var routing map[string]any
	if err := json.Unmarshal(cfg.RouterConfig, &routing); err != nil {
		return
	}

	rulesRaw, ok := routing["rules"].([]any)
	if !ok || len(rulesRaw) == 0 {
		return
	}

	var newRules []any
	modified := false

	for _, ruleRaw := range rulesRaw {
		rule, ok := ruleRaw.(map[string]any)
		if !ok {
			newRules = append(newRules, ruleRaw)
			continue
		}

		usersRaw, ok := rule["user"].([]any)
		if !ok || len(usersRaw) == 0 {
			newRules = append(newRules, rule)
			continue
		}

		// Separate VPN emails from regular Xray emails.
		//
		// An account can be BOTH: one email on vless and on l2tp is exactly what
		// the accounts layer exists to allow. This used to be an either/or -- the
		// moment an email had any pool-protocol membership it was moved out of the
		// rule's "user" list entirely and replaced by a source-IP match -- so the
		// account's vless traffic stopped matching its own routing rule: the source
		// rule only covers tunnel addresses, and the native user match was gone.
		// Silently, with a valid config and a running core.
		//
		// So an email that Xray also authenticates natively stays in BOTH lists:
		// it gets the source rule for its tunnel addresses AND keeps the user rule
		// for the traffic the core terminates itself.
		var vpnIPs []any
		var regularEmails []any
		for _, u := range usersRaw {
			email, ok := u.(string)
			if !ok {
				regularEmails = append(regularEmails, u)
				continue
			}
			ips, found := vpnMap[email]
			if !found {
				regularEmails = append(regularEmails, u)
				continue
			}
			for _, ip := range ips {
				vpnIPs = append(vpnIPs, ip)
			}
			if nativeEmails[accounts.AccountKeyOf(email)] {
				regularEmails = append(regularEmails, u)
			}
		}

		if len(vpnIPs) == 0 {
			newRules = append(newRules, rule)
			continue
		}

		modified = true

		// Create source-based rule for VPN clients (copy all fields except "user")
		vpnRule := make(map[string]any)
		for k, v := range rule {
			if k != "user" {
				vpnRule[k] = v
			}
		}
		vpnRule["source"] = vpnIPs
		newRules = append(newRules, vpnRule)

		// Keep original rule with remaining non-VPN emails
		if len(regularEmails) > 0 {
			rule["user"] = regularEmails
			newRules = append(newRules, rule)
		}
	}

	// Backstop: block any VPN tunnel source that isn't a valid account device IP.
	// nftables TPROXYs the WHOLE client /24 into Xray, and with no matching rule a
	// packet falls through to Xray's default (first) outbound — so a device holding an
	// in-/24 but out-of-block IP (an over-limit device, a failed eviction, or a keyless
	// Access-Accept fallback) would otherwise reach the internet, making the User Limit
	// cap cosmetic. We list every legitimate device IP -> the default outbound, then
	// blackhole the rest of the VPN space. Appended last, so operator per-account rules
	// still take precedence for valid IPs; only unrecognized (over-limit / leaked)
	// sources hit the blackhole. Tags are taken from the config's own outbounds so the
	// default egress is preserved and the backstop is skipped when no blackhole exists.
	defaultTag, blockTag := "direct", ""
	var obs []map[string]any
	if json.Unmarshal(cfg.OutboundConfigs, &obs) == nil {
		for i, ob := range obs {
			t, _ := ob["tag"].(string)
			if i == 0 && t != "" {
				defaultTag = t
			}
			if p, _ := ob["protocol"].(string); p == "blackhole" && t != "" {
				blockTag = t
			}
		}
	}
	var validIPs []any
	seen := make(map[string]bool)
	for _, ips := range vpnMap {
		for _, ip := range ips {
			if ip != "" && !seen[ip] {
				seen[ip] = true
				validIPs = append(validIPs, ip)
			}
		}
	}
	if blockTag != "" && len(validIPs) > 0 {
		newRules = append(newRules,
			map[string]any{"type": "field", "source": validIPs, "outboundTag": defaultTag},
			map[string]any{"type": "field", "source": []any{VpnAddrSpace}, "outboundTag": blockTag},
		)
		modified = true
	}

	if !modified {
		return
	}

	routing["rules"] = newRules
	if data, err := json.Marshal(routing); err == nil {
		cfg.RouterConfig = data
	}
}
