// Package defaults holds the VPN-side protocol identities and the server-side
// settings defaults for the non-Xray protocols. Ported from vpn-ui
// web/service/protocoldefaults.go (+ sharedconfig.go's sharedL2tpIpsecPsk and
// ikev2.go's default MTU), adapted to the pxpanel import tree.
package defaults

import (
	"encoding/json"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/util/common"
	"github.com/ImSoheilPx/pxpanel/internal/util/random"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
)

// Protocol identities of the VPN-side protocol family (the vpn-ui lineage).
//
// The pxpanel model.Protocol constants (model.go) carry only the Xray-native
// set the core panel knows. These are the VPN additions; their STRING VALUES
// are the storage contract — they land in Inbound.Protocol rows and are parsed
// by every protocol service, so they must stay byte-identical to vpn-ui's even
// though the Go constant names differ (vpn-ui reused model.WGC/model.AWG, which
// in pxpanel's model package mean the Xray-native wireguard/amneziawg instead).
const (
	ProtoL2TP        model.Protocol = "l2tp"
	ProtoPPTP        model.Protocol = "pptp"
	ProtoOpenVPN     model.Protocol = "openvpn"
	ProtoOpenConnect model.Protocol = "openconnect"
	ProtoSSTP        model.Protocol = "sstp"
	ProtoIKEv2       model.Protocol = "ikev2"
	ProtoWGC         model.Protocol = "wg-c"
	ProtoAWG         model.Protocol = "awg"
	ProtoGRE         model.Protocol = "gre"
	ProtoMTProto     model.Protocol = "mtproto"
	// ProtoMTProtoC is the vpn-ui telemt MTProto plane (Sir-MmD telemt daemon,
	// one process per inbound, relay egress through a paired loopback socks).
	// It is a DISTINCT protocol string from ProtoMTProto because 3x-ui itself
	// has always owned the plain "mtproto" string with its own settings shape
	// (the mtg sidecar), and both planes must stay creatable side by side.
	ProtoMTProtoC model.Protocol = "mtproto-c"
	ProtoSSH      model.Protocol = "ssh"
	ProtoAnyTLS   model.Protocol = "anytls"
	ProtoNaive    model.Protocol = "naive"
	// ProtoHysteria2 is the literal import string some sources carry for Hysteria v2;
	// the panel stores both generations as "hysteria", so identity checks accept both.
	ProtoHysteria2 model.Protocol = "hysteria2"
)

// TunnelProtocols are the protocols with an address pool and nft accounting
// (the "VPN protocols" proper). Relay protocols (mtproto, ssh) and the
// Xray-native ones are NOT in this list. (A var: Go slices cannot be consts.)
var TunnelProtocols = []string{
	"l2tp", "pptp", "openvpn", "openconnect", "sstp",
	"ikev2", "wg-c", "awg", "gre",
}

// ikev2DefaultMtu is what an IKEv2 tunnel gets when the operator names no MTU.
// 1400 because a real-world IKEv2 client is behind a NAT and therefore carrying
// ESP inside UDP, which costs 73-100 bytes on a 1500 byte path.
const IKEv2DefaultMTU = 1400

// Server-side settings defaults and validation for the non-Xray protocols.
//
// Every one of those protocols has its inbound `settings` JSON built ENTIRELY in
// the browser, by the form classes (the vpn-ui lineage kept them in
// web/assets/js/model/inbound.js). The Go API used to take that blob verbatim:
// no defaults, no validation. A script calling the inbound add API therefore had
// to hand-reproduce the JS output field for field, and a key it guessed wrong was
// not an error, it was a daemon that came up with the wrong DNS / MTU / device
// cap, or an inbound whose settings the protocol's own Go struct could not even
// unmarshal.
//
// The tables below are a port of those JS classes: the same keys, the same
// defaults, read off each class's CONSTRUCTOR (which is what a NEW inbound
// starts from, i.e. what the panel's own Add form produces).
//
// The form classes are the spec. A key spelled differently here is silent
// breakage: the value lands in the stored JSON under a name nothing reads, the
// protocol's Go struct falls back to its zero value, and no error is raised
// anywhere.

// settingDefault is one settings key and the value a freshly created inbound of
// that protocol carries for it.
//
// mint, when set, produces the value per call instead of sharing one constant:
// the two IPsec pre-shared keys must not be identical across every inbound the
// panel ever creates, which is exactly what a package-level constant would give
// them.
type settingDefault struct {
	key  string
	val  any
	mint func() any
}

func def(key string, val any) settingDefault { return settingDefault{key: key, val: val} }

func gen(key string, mint func() any) settingDefault {
	return settingDefault{key: key, mint: mint}
}

func (d settingDefault) value() any {
	if d.mint != nil {
		return d.mint()
	}
	return d.val
}

// emptyList is the value of every array-valued default. A distinct []any{} per call so
// two inbounds can never end up sharing one backing slice through the marshaller.
func emptyList() any { return []any{} }

// noClients is the `clients` default. A fresh inbound gets NO accounts even
// though the JS constructors seed one: the browser can mint a credential
// locally, but an account created here would be one the caller never asked for
// and never sees the password of.
func noClients() any { return []any{} }

// protocolSettingDefaults returns the ordered settings defaults for a protocol, or nil
// for one that has none (every Xray-native protocol: the core owns those shapes and
// GenXrayInboundConfig passes them through untouched, so inventing keys for them here
// would only corrupt configs the core already understands).
//
// Order is the order of the matching JS toJson(), so this reads as a diff against the
// spec. It does not survive into the stored JSON (Go marshals map keys sorted, which is
// what AddInbound's own re-marshal already does to a UI-created inbound).
func protocolSettingDefaults(protocol model.Protocol) []settingDefault {
	switch protocol {
	case ProtoL2TP:
		// Inbound.L2tpSettings
		return []settingDefault{
			def("ipsecEnable", true),
			// RandomUtil.randomSeq(16) in the constructor. fromJson() passes an absent
			// psk straight through as undefined instead, so only a NEW inbound gets one.
			//
			// INHERITED, not minted, when an enabled l2tp inbound already has a key. A
			// fresh random key for a second inbound is not a risk of being rejected, it
			// is a certainty: the shared-daemon check refuses two different keys on
			// one IKE listen address, and a new inbound listens on all of them. The
			// operator was left hand-copying the first inbound's key out of the other
			// form. Minting only happens for the first l2tp inbound, or when the
			// existing ones have IPsec off. See SharedL2tpIpsecPsk.
			gen("ipsecPsk", func() any {
				if psk := SharedL2tpIpsecPsk(); psk != "" {
					return psk
				}
				return random.Seq(16)
			}),
			def("allowRaw", false),
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("dns1", "8.8.8.8"),
			def("dns2", "8.8.4.4"),
			def("mtu", 1400),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
			def("clients", noClients()),
			def("externalProxy", emptyList()),
		}

	case ProtoPPTP:
		// Inbound.PptpSettings. No IPsec pair: PPTP carries MPPE itself.
		return []settingDefault{
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("dns1", "8.8.8.8"),
			def("dns2", "8.8.4.4"),
			def("mtu", 1400),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
			def("clients", noClients()),
			def("externalProxy", emptyList()),
		}

	case ProtoOpenVPN:
		// Inbound.OpenvpnSettings
		return []settingDefault{
			def("udpEnable", true),
			def("tcpEnable", true),
			def("tcpPort", 1194),
			// The one field where the JS constructor (false: TCP and UDP share
			// inbound.Port) and fromJson (true: TCP gets its own tcpPort) disagree. The
			// constructor is what the Add form starts from, so it is what a caller who
			// omits the key gets, and it is also the reading that cannot collide with
			// another inbound already holding 1194.
			def("separatePorts", false),
			def("tlsUseFile", false),
			def("caCertFile", ""),
			def("serverCertFile", ""),
			def("serverKeyFile", ""),
			def("tlsCryptFile", ""),
			// On by default: it is what every existing inbound does, and the
			// self-signed generator mints the key anyway. Turning it off is the
			// opt-out for an operator who does not want tls-crypt at all.
			def("tlsCryptEnable", true),
			// The .ovpn profile name (setenv FRIENDLY_NAME). Empty = emit nothing.
			def("friendlyName", ""),
			def("dns1", "8.8.8.8"),
			def("dns2", "8.8.4.4"),
			def("mtu", 1500),
			// No cert is minted here. Generating one is client-side only (the JS forge
			// build), and the inbound validator already refuses an OpenVPN inbound with
			// no caCert/serverCert, so an API caller must still supply or generate a
			// certificate. Defaulting these to "" only makes the omission explicit.
			def("caCert", ""),
			def("caKey", ""),
			def("serverCert", ""),
			def("serverKey", ""),
			def("tlsCrypt", ""),
			def("clients", noClients()),
			def("externalProxy", emptyList()),
			def("cipherMode", "all"),
			// Inbound.OpenvpnSettings.CIPHER_MODES.all, in its preference order: that
			// order is written straight into the `data-ciphers` directive.
			def("ciphers", []string{
				"AES-256-GCM",
				"AES-128-GCM",
				"CHACHA20-POLY1305",
				"AES-256-CBC",
				"AES-192-CBC",
				"AES-128-CBC",
				"BF-CBC",
				"DES-EDE3-CBC",
			}),
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
		}

	case ProtoOpenConnect:
		// Inbound.OcservSettings
		return []settingDefault{
			def("dns1", "8.8.8.8"),
			def("dns2", "8.8.4.4"),
			def("mtu", 1420),
			def("tlsUseFile", false),
			def("certificateFile", ""),
			def("keyFile", ""),
			def("certificate", ""),
			def("key", ""),
			def("caCert", ""),
			def("clients", noClients()),
			def("externalProxy", emptyList()),
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
		}

	case ProtoSSTP:
		// Inbound.SstpSettings. Field for field identical to OcservSettings apart from
		// the MTU below; kept spelled out rather than shared so a future divergence in
		// either one cannot silently rewrite the other's stored JSON.
		return []settingDefault{
			def("dns1", "8.8.8.8"),
			def("dns2", "8.8.4.4"),
			// 1400, and NOT OpenConnect's 1420. SSTP is PPP inside a 4-byte SSTP header
			// inside TLS inside TCP, so a 1500 byte path pays 20 (IP) + 20 (TCP) + 5 (TLS
			// record) + 16 (IV) + 32 (MAC) + 4 (SSTP) + 4 (PPP) and lands just under 1400.
			// OpenConnect's 1420 is a DTLS/UDP number and does not transfer.
			def("mtu", 1400),
			def("tlsUseFile", false),
			def("certificateFile", ""),
			def("keyFile", ""),
			def("certificate", ""),
			def("key", ""),
			def("caCert", ""),
			def("clients", noClients()),
			def("externalProxy", emptyList()),
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
		}

	case ProtoIKEv2:
		// Inbound.Ikev2Settings
		return []settingDefault{
			def("dns1", "8.8.8.8"),
			def("dns2", "8.8.4.4"),
			// 1400 (IKEv2DefaultMTU). Enforced as a TCP MSS clamp, not written into a
			// daemon config — see the ikev2 wave's settings struct for why that is the
			// only option.
			def("mtu", IKEv2DefaultMTU),
			def("authMode", "eap-mschapv2"),
			def("psk", ""),
			// Empty means "use the panel-access host / detected server IP", which is
			// what the ikev2 settings document. Not defaulted to anything guessable:
			// the value has to match the server cert's SAN or every client rejects it.
			def("serverAddr", ""),
			def("nattPort", 4500),
			def("tlsUseFile", false),
			def("certificateFile", ""),
			def("keyFile", ""),
			def("certificate", ""),
			def("key", ""),
			def("caCert", ""),
			def("clients", noClients()),
			def("externalProxy", emptyList()),
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
		}

	case ProtoWGC:
		// Inbound.WgcSettings. Note the DNS pair differs from the PPP family (1.1.1.1
		// rather than 8.8.8.8); it is written into the generated client config.
		return []settingDefault{
			def("dns1", "1.1.1.1"),
			def("dns2", "1.0.0.1"),
			def("mtu", 1420),
			// Left empty on purpose: the wgc reconciler mints the server keypair
			// (and every per-device keypair) after the inbound is stored. A key minted
			// here would be overwritten by it anyway.
			def("serverPrivKey", ""),
			def("serverPubKey", ""),
			def("pskEnable", false),
			def("clients", noClients()),
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
			def("externalProxy", emptyList()),
		}

	case ProtoAWG:
		// Inbound.AwgSettings: WgcSettings plus the AWG 1.0 obfuscation parameters.
		// Jc/Jmin/Jmax/S1/S2 are the AmneziaWG defaults; the magic headers H1-H4 are
		// minted by the awg service (like serverPubKey) and start empty.
		return []settingDefault{
			def("dns1", "1.1.1.1"),
			def("dns2", "1.0.0.1"),
			def("mtu", 1420),
			def("jc", 4),
			def("jmin", 8),
			def("jmax", 80),
			def("s1", 77),
			def("s2", 90),
			def("h1", ""),
			def("h2", ""),
			def("h3", ""),
			def("h4", ""),
			def("serverPrivKey", ""),
			def("serverPubKey", ""),
			def("pskEnable", false),
			def("clients", noClients()),
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
			def("externalProxy", emptyList()),
		}

	case ProtoGRE:
		// Inbound.GreSettings
		return []settingDefault{
			// 0 = let the kernel choose. The right value differs per encapsulation
			// (1476 raw, 1464 under FOU) and the kernel already knows which, so any
			// number pinned here would be wrong for the other mode.
			def("mtu", 0),
			def("ttl", 64),
			def("ipsecEnable", false),
			// RandomUtil.randomSeq(24) in the constructor (fromJson defaults it to "").
			// Minted even with ipsecEnable off, exactly as the form does, so flipping
			// the switch later does not require also inventing a secret.
			gen("ipsecPsk", func() any { return random.Seq(24) }),
			def("allowRaw", true),
			def("fouEnable", false),
			def("fouPort", 15547),
			def("clients", noClients()),
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
		}

	case ProtoMTProto:
		// Inbound.MtprotoSettings. The proxy's policy is the INBOUND's: telemt applies
		// the FakeTLS domain process-wide, and its mode map has to be spelled out per
		// account or a missing entry reads as "no restriction". The secret, the link
		// endpoints and the ad tag stay per-account, so none of them is seeded here.
		//
		// All three modes on and userLimit 10 (ten devices per account) are the values
		// the JS constructor uses, so an inbound created through the API matches one
		// created in the form. 0 stays settable and does NOT mean unlimited: the
		// effective user-limit resolver reads it as the bounded 16-device block, which
		// is why it is not the default any more.
		return []settingDefault{
			def("modeClassic", true),
			def("modeSecure", true),
			def("modeTls", true),
			def("tlsDomain", "www.google.com"),
			def("userLimit", 10),
			def("clients", noClients()),
			// The inbound-wide link endpoints, overridden per account by the client's
			// own externalProxy.
			def("externalProxy", emptyList()),
		}

	case ProtoMTProtoC:
		// The vpn-ui telemt plane under its own protocol string. Same settings
		// shape and defaults as the telemt case above — the ONLY difference
		// between the two planes is the protocol string the row carries (and
		// therefore which service wave claims it), never the payload.
		return []settingDefault{
			def("modeClassic", true),
			def("modeSecure", true),
			def("modeTls", true),
			def("tlsDomain", "www.google.com"),
			def("userLimit", 10),
			def("clients", noClients()),
			def("externalProxy", emptyList()),
		}

	case ProtoSSH:
		// Inbound.SshSettings. userLimit 10 = ten concurrent devices, which is what
		// the constructor (and therefore the Add form) uses. fromJson resolves an
		// ABSENT value to 1 instead; a caller who omits the key here is creating a
		// NEW inbound, so the constructor's 10 is the right reading. 0 is still
		// settable and SSH is the one protocol where it really does mean no cap at all.
		return []settingDefault{
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
			def("externalProxy", emptyList()),
			def("clients", noClients()),
			// Minted by the ssh service on first use and kept stable so a client's
			// host-key pin holds across restarts. Never set from outside.
			def("hostKey", ""),
		}

	case ProtoAnyTLS:
		// Inbound.AnytlsSettings
		return []settingDefault{
			def("clients", noClients()),
			// Inbound.AnytlsSettings.DEFAULT_PADDING_SCHEME: upstream AnyTLS's own
			// scheme, spelled out rather than left empty so what the server will
			// actually do is visible and editable. The scheme is SERVER-AUTHORITATIVE
			// (handed to the client in the session's settings frame), so changing it
			// never requires reconfiguring a client.
			def("paddingScheme", []string{
				"stop=8",
				"0=30-30",
				"1=100-400",
				"2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
				"3=9-9,500-1000",
				"4=500-1000",
				"5=500-1000",
				"6=500-1000",
				"7=500-1000",
			}),
		}

	case model.TUIC:
		// Inbound.TuicSettings. TUIC predates the vpn-ui split in 3x-ui itself, so the
		// pxpanel model constant carries the same value; it is listed here because the
		// vpn-ui stack gave it a server-side settings shape.
		return []settingDefault{
			def("clients", noClients()),
			def("congestionControl", "cubic"),
			def("authTimeout", 3),
			def("zeroRttHandshake", false),
			def("heartbeat", 10),
			def("udpTimeout", 60),
		}

	case ProtoNaive:
		// Inbound.NaiveSettings. `network` is the SINGLE SOURCE OF TRUTH for which
		// wires the listener owns; the naive wave's normalizer forces the transport
		// from here onto the stream, OVERRIDING streamSettings.network.
		return []settingDefault{
			def("clients", noClients()),
			def("network", "tcp"),
			// All four keys are kept even though each of file/url/string belongs to
			// exactly one type, which is what lets the form switch type back and forth
			// without losing what was typed under the other one.
			def("masquerade", map[string]any{
				"type":   "404",
				"file":   "",
				"url":    "",
				"string": "",
			}),
		}
	}
	return nil
}

// DefaultSettingsFor returns the settings JSON a freshly created inbound of a protocol
// should carry, matching what the panel's Add form produces minus the one account its
// JS constructor seeds (see noClients).
//
// Errors for a protocol with no server-side shape rather than returning "{}": an empty
// object is a plausible-looking answer that would strip an Xray-native inbound of
// everything the core needs.
func DefaultSettingsFor(protocol model.Protocol) (string, error) {
	defaults := protocolSettingDefaults(protocol)
	if len(defaults) == 0 {
		return "", common.NewErrorf("no server-side settings defaults for protocol %q", protocol)
	}
	root := make(map[string]any, len(defaults))
	for _, d := range defaults {
		root[d.key] = d.value()
	}
	bs, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", common.NewErrorf("building default %s settings: %v", protocol, err)
	}
	return string(bs), nil
}

// FillSettingsDefaults completes whatever the caller posted, adding every key of the
// protocol's shape that is missing and touching nothing that is present.
//
// The no-op case is load-bearing. Every request the panel's own UI makes already
// carries the full shape, and those must keep storing the SAME BYTES they do today, or
// this turns into a rewrite of every inbound anyone saves. So when no key was missing
// the input string is returned verbatim rather than re-marshalled: re-encoding would
// reorder keys and renumber floats even though nothing changed.
//
// Values already present are copied as raw JSON, never decoded and re-encoded, so a
// large integer (an expiryTime in milliseconds, a totalGB in bytes) cannot lose
// precision on the way through.
//
// A protocol with no server-side shape is passed through untouched.
func FillSettingsDefaults(protocol model.Protocol, posted string) (string, error) {
	defaults := protocolSettingDefaults(protocol)
	if len(defaults) == 0 {
		return posted, nil
	}
	root, err := settingsRaw(posted)
	if err != nil {
		return "", err
	}
	added := false
	for _, d := range defaults {
		if _, ok := root[d.key]; ok {
			continue
		}
		bs, err := json.Marshal(d.value())
		if err != nil {
			return "", common.NewErrorf("building the default for %q: %v", d.key, err)
		}
		root[d.key] = bs
		added = true
	}
	if !added {
		return posted, nil
	}
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", common.NewErrorf("filling %s settings defaults: %v", protocol, err)
	}
	return string(out), nil
}

// settingsRaw parses a settings blob into its top-level keys, keeping each value as the
// exact bytes the caller sent.
//
// An empty blob (and a literal null, which is what an absent field marshals to) is an
// empty object rather than an error: creating an inbound with no settings at all is the
// minimal API body this whole file exists to support.
func settingsRaw(settings string) (map[string]json.RawMessage, error) {
	trimmed := strings.TrimSpace(settings)
	if trimmed == "" || trimmed == "null" {
		return map[string]json.RawMessage{}, nil
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &root); err != nil {
		return nil, common.NewErrorf("inbound settings must be a JSON object: %v", err)
	}
	if root == nil {
		return map[string]json.RawMessage{}, nil
	}
	return root, nil
}

// NormalizeInboundSettings fills a new inbound's missing settings keys and then
// validates the result. The ADD path's single entry point into this file.
//
// Order matters: validation runs on the FILLED blob, so a caller who omitted a field is
// judged on the default that will actually be stored, not on its absence.
func NormalizeInboundSettings(inbound *model.Inbound) error {
	if inbound == nil {
		return nil
	}
	// MTProto only, and BEFORE the defaults on purpose: a body written against the old
	// field names carries its connection modes, FakeTLS domain and device cap on its
	// CLIENTS, and filling the inbound-level defaults over that would both lose them and
	// make the blob look already-migrated to the startup lift.
	if MtprotoSettingsLifter != nil {
		inbound.Settings = MtprotoSettingsLifter(inbound.Protocol, inbound.Settings)
	}

	filled, err := FillSettingsDefaults(inbound.Protocol, inbound.Settings)
	if err != nil {
		return err
	}
	inbound.Settings = filled
	// A nil hook is "no server-side validation yet" (the controllers wave wires
	// it), not a crash: calling a nil func var here took the whole inbound ADD
	// path down with a nil-pointer panic in every binary that had not linked a
	// registering package. Defaults are still filled above, so the caller stores
	// the same complete shape either way.
	if ValidateSettings == nil {
		return nil
	}
	return ValidateSettings(inbound.Protocol, inbound.Settings)
}

// MtprotoSettingsLifter rewrites a PRE-MOVE mtproto settings blob (policy on the
// clients) into the current inbound-level shape, before defaults are filled.
//
// The implementation (vpn-ui web/service/mtproto.go's liftMtprotoSettingsBlob and
// its resolveMtprotoPolicy / deriveMtprotoPolicy machinery) lives in the mtproto
// package — it needs vpnrange's effective-user-limit math, and vpnrange imports
// this package, so defaults cannot host it without an import cycle. The mtproto
// package registers it from init(), exactly like the validator hook below.
//
// A nil lifter is the pass-through the foundation wave shipped: pre-move mtproto
// bodies are simply not lifted (only reachable in builds that do not import the
// mtproto package at all).
var MtprotoSettingsLifter func(protocol model.Protocol, settings string) string

// ValidateSettings is the per-protocol settings validator hook, called at the end of
// NormalizeInboundSettings.
//
// TODO(protocol waves): vpn-ui carried the full validator table
// (web/service/protocolvalidate.go, ~760 LOC: checkClients, per-protocol shapes).
// Each protocol wave registers its validator here on init:
//
//	defaults.ValidateSettings = mypackage.ValidateProtocolSettings
//
// A nil hook means "no server-side validation yet" — defaults are still filled, so
// daemons come up with sane shapes; only malformed caller-supplied keys pass unchecked.
var ValidateSettings func(protocol model.Protocol, settings string) error

// SharedL2tpIpsecPsk returns the IPsec pre-shared key an enabled L2TP inbound already
// uses, or "" when there is none (no l2tp inbound yet, or no DB).
//
// This exists because minting a random key for a second L2TP inbound is a GUARANTEED
// rejection, not a risk of one: the save-time check refuses two different keys on
// one IKE listen address, and a new inbound's listen address is blank (= every address)
// by default. Inheriting is therefore the only default that can be saved, and it is also
// the honest one — until the operator gives the inbound its own address, that IS the key
// their clients will authenticate with.
//
// The lowest id wins, matching the inbound the generators already treat as the owner of
// every other shared L2TP value. (vpn-ui sharedconfig.go:sharedL2tpIpsecPsk, with
// enabledInboundsOfProtocol folded in.)
func SharedL2tpIpsecPsk() string {
	db := vpn.DB()
	if db == nil {
		return ""
	}
	var inbounds []*model.Inbound
	if err := db.Model(&model.Inbound{}).
		Where("protocol = ? AND enable = ?", string(ProtoL2TP), true).
		Order("id ASC").Find(&inbounds).Error; err != nil {
		return ""
	}
	for _, inbound := range inbounds {
		var theirs struct {
			IpsecEnable bool   `json:"ipsecEnable"`
			IpsecPsk    string `json:"ipsecPsk"`
		}
		if json.Unmarshal([]byte(inbound.Settings), &theirs) != nil {
			continue
		}
		if theirs.IpsecEnable && strings.TrimSpace(theirs.IpsecPsk) != "" {
			return theirs.IpsecPsk
		}
	}
	return ""
}
