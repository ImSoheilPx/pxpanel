package l2tp

// The L2TP/IPsec renderers, verbatim from vpn-ui web/service/l2tp.go (they sat
// in the same file below the service). Two backends, chosen by the callers in
// l2tp.go: the shared charon's swanctl conf (bundled strongSwan path) and the
// host/bundled libreswan's ipsec.conf + ipsec.secrets (fallback).
//
// Free-standing helpers now come from the foundation: libreswanVersion →
// pkgmgr.LibreswanVersion, usingBundledIpsec/bundledIpsecUpdown →
// internal/vpn/ipsec.

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ipsec"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/pkgmgr"
)

// ipsecConnName is the panel-wide libreswan connection name (vpn-ui
// ipsec_bundle.go const; the ipsec package keeps its own private copy for the
// bundled-pluto conn loading fallback).
const ipsecConnName = "l2tp-psk"

// PER-INBOUND IPsec PRE-SHARED KEYS.
//
// Both IPsec backends below can serve one key per inbound, but only under a condition the
// protocol imposes and no configuration setting can lift.
//
// L2TP/IPsec is IKEv1 Main Mode with a pre-shared key. SKEYID = prf(PSK, Ni|Nr) is
// computed at messages 3/4, and the initiator's ID payload does not arrive until message
// 5 — already encrypted under keys derived from the very key the responder is trying to
// choose. The responder therefore has to pick the key knowing nothing but the IP address
// pair, and the peer is a road warrior whose address is unknown. So the ONLY thing that
// can select between two of our keys is OUR OWN address: the one the packet arrived on.
//
// Hence: distinct, concrete listen addresses, or one shared key. There is no strongSwan
// or libreswan option that changes this. (GRE gets away with per-tunnel keys because its
// connections are `version = 0` and negotiate IKEv2 in practice, where the identity is
// available in time to select the secret.)
//
// WHAT A PER-INBOUND KEY DOES AND DOES NOT SEPARATE. It authenticates the IPsec layer per
// listen address, and that is all. Everything above it is still protocol-wide: one xl2tpd
// with one [global] on port 1701, one /etc/ppp/options.xl2tpd, and a RADIUS lookup that
// resolves an account by username across every enabled l2tp inbound. A client that holds
// inbound B's key but authenticates as an inbound-A account still lands in inbound A's IP
// pool with inbound A's routing. The key is a door, not a partition.

// l2tpIpsecPeer is one L2TP inbound that terminates IKE: its key, and the address it
// answers on ("" when it answers on all of them).
type l2tpIpsecPeer struct {
	inbound *model.Inbound
	psk     string
	listen  string
}

// l2tpIpsecPeers returns the inbounds that want IPsec and have a key to do it with, in
// the order they were given.
//
// requireEnable is not a detail to tidy away: the swanctl generator has always skipped
// disabled inbounds and the libreswan one has always ignored the flag, and both of those
// choices are load-bearing for the panel-wide output they produce today.
func (s *L2tpService) l2tpIpsecPeers(inbounds []*model.Inbound, requireEnable bool) []l2tpIpsecPeer {
	var out []l2tpIpsecPeer
	for _, inbound := range inbounds {
		if requireEnable && !inbound.Enable {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil || !settings.IpsecEnable || settings.IpsecPsk == "" {
			continue
		}
		out = append(out, l2tpIpsecPeer{
			inbound: inbound,
			psk:     settings.IpsecPsk,
			listen:  strings.TrimSpace(inbound.Listen),
		})
	}
	return out
}

// l2tpPerListenPeers returns the peers when each can own its key, and nil when they
// cannot — which is the default and stays the default.
//
// Every condition here is a reason the addresses could not tell two keys apart:
//
//   - fewer than two peers: there is nothing to tell apart, and emitting the per-inbound
//     shape for a lone inbound would rewrite a file on every existing install for no gain.
//   - a wildcard listen: that inbound answers on every address, including the others'.
//   - a listen that is not an IP literal: a hostname becomes an FQDN identity in IKEv1,
//     which never matches the address-derived identity the key lookup uses.
//   - two peers on the same address: the ambiguity this whole mechanism exists to avoid.
func l2tpPerListenPeers(peers []l2tpIpsecPeer) []l2tpIpsecPeer {
	if len(peers) < 2 {
		return nil
	}
	seen := make(map[string]bool, len(peers))
	for _, peer := range peers {
		if listenIsWildcard(peer.listen) || net.ParseIP(peer.listen) == nil || seen[peer.listen] {
			return nil
		}
		seen[peer.listen] = true
	}
	return peers
}

// listenIsWildcard reports whether listen covers EVERY local address (vpn-ui
// web/service/inboundport.go listenIsWildcard — the inbound-save half lives with the
// inbound wave; this package needs only the predicate).
func listenIsWildcard(listen string) bool {
	switch strings.TrimSpace(listen) {
	case "", "0.0.0.0", "::", "::0":
		return true
	}
	return false
}

// GenerateIPsecConfig writes /etc/ipsec.conf and /etc/ipsec.secrets for L2TP/IPsec.
// Uses Libreswan format which provides better compatibility across Windows, iOS, and Linux.
//
// One `conn l2tp-psk` on %defaultroute with a wildcard secret, or one `conn l2tp-psk-<id>`
// per inbound pinned to its own left= address with an address-scoped secret. See the
// per-inbound PSK note above for when the second shape is possible.
func (s *L2tpService) GenerateIPsecConfig(inbounds []*model.Inbound) error {
	// The panel-wide fallback reads every inbound, enabled or not, which is what this
	// generator has always done; the per-inbound shape only ever serves enabled ones.
	all := s.l2tpIpsecPeers(inbounds, false)
	perListen := l2tpPerListenPeers(s.l2tpIpsecPeers(inbounds, true))

	if len(all) == 0 {
		return nil
	}

	// The host libreswan's own two files. ipsec.secrets is the painful one: it holds
	// every PSK the operator configured, and we replace it with a single line, so
	// before this recorded a backup an install silently destroyed their IPsec
	// credentials with no way back. See ownership.go.
	manifest.PrepareHostFile("/etc/ipsec.conf", "l2tp")
	if err := s.writeFile("/etc/ipsec.conf",
		buildIpsecConf(detectLibreswanFeatures(), ipsecConnsFor(all, perListen))); err != nil {
		return err
	}

	// Write /etc/ipsec.secrets (mode 0600 for PSK confidentiality)
	manifest.PrepareHostFile("/etc/ipsec.secrets", "l2tp")
	if err := s.writeFileMode("/etc/ipsec.secrets", buildIpsecSecrets(all, perListen), 0o600); err != nil {
		return err
	}

	// Clean up old StrongSwan swanctl config if present, per-inbound files included:
	// pluto is serving these connections now, and a leftover charon conn would answer
	// on the same addresses with a key of its own.
	os.Remove(ipsec.SwanctlConfDir() + "/l2tp.conf")
	l2tpPruneSwanctlConns(nil)

	return nil
}

// ipsecConn is one `conn` stanza: its name and the local address it terminates on.
type ipsecConn struct {
	name string
	left string
}

// ipsecConnsFor maps the peers onto the connections to write: the panel-wide one on
// %defaultroute, or one per inbound pinned to its own address.
func ipsecConnsFor(all, perListen []l2tpIpsecPeer) []ipsecConn {
	if len(perListen) == 0 {
		return []ipsecConn{{name: ipsecConnName, left: "%defaultroute"}}
	}
	out := make([]ipsecConn, 0, len(perListen))
	for _, peer := range perListen {
		out = append(out, ipsecConn{name: fmt.Sprintf("%s-%d", ipsecConnName, peer.inbound.Id), left: peer.listen})
	}
	return out
}

// buildIpsecSecrets renders /etc/ipsec.secrets.
//
// The panel-wide form is the bare wildcard `: PSK "..."`, which libreswan offers to every
// exchange. The per-inbound form names the pair the key belongs to — our address and any
// peer — which is the finest scoping IKEv1 Main Mode allows, since our address is the only
// thing known when the key is chosen.
func buildIpsecSecrets(all, perListen []l2tpIpsecPeer) string {
	escape := func(psk string) string {
		esc := strings.ReplaceAll(psk, `\`, `\\`)
		return strings.ReplaceAll(esc, `"`, `\"`)
	}
	if len(perListen) == 0 {
		if len(all) == 0 {
			return ""
		}
		return fmt.Sprintf(": PSK \"%s\"\n", escape(all[0].psk))
	}
	var b strings.Builder
	for _, peer := range perListen {
		fmt.Fprintf(&b, "%s %%any : PSK \"%s\"\n", peer.listen, escape(peer.psk))
	}
	return b.String()
}

// libreswanFeatures is what the INSTALLED libreswan understands. Detected once and passed
// in rather than probed inside the renderer, so the rendered text is a pure function of
// the inbounds plus this struct (and so a test can pin the bytes without a libreswan).
type libreswanFeatures struct {
	ikev1Policy   bool
	keyexchangeV1 bool
	modp1024      bool
	// leftupdown is the absolute updown command for the bundled pluto, "" for a host
	// libreswan that finds `ipsec` on its PATH.
	leftupdown string
}

// detectLibreswanFeatures probes the installed libreswan.
//
// Libreswan's L2TP/IPsec keywords are NOT portable across major versions, and getting
// them wrong is fatal in different ways on different distros — which is why "stuck on
// stopped" only showed up on some of them. Emit version-appropriate keywords (validated
// on 3.32, 4.3, 4.14 and 5.2):
//
//	ikev1-policy: `config setup` keyword added in 4.2. From 5.0 (and Debian/
//	RHEL back-patches) IKEv1 is dropped by default, so 4.2+ REQUIRES
//	ikev1-policy=accept or the L2TP conn fails to load ("global ikev1-policy
//	does not allow IKEv1 connections"). But on <4.2 the keyword is UNKNOWN, and
//	an unknown `config setup` keyword makes pluto reject the WHOLE config — the
//	service then won't start and neither a restart nor a reboot fixes it. So
//	emit it only on 4.2+ (pre-4.2 accepts IKEv1 by default anyway).
//
//	keyexchange: the explicit value `ikev1` only exists in 5.x; 3.x and 4.x
//	reject it ("invalid value"). `keyexchange=ike` + `ikev2=no` selects IKEv1
//	and parses on every version, so it's the portable form for <5.0.
func detectLibreswanFeatures() libreswanFeatures {
	lsMajor, lsMinor, lsOK := pkgmgr.LibreswanVersion()
	feat := libreswanFeatures{
		ikev1Policy:   lsOK && (lsMajor > 4 || (lsMajor == 4 && lsMinor >= 2)),
		keyexchangeV1: lsOK && lsMajor >= 5,
		modp1024:      ipsecSupportsModp1024(),
	}
	// The bundled pluto can't find `ipsec` on its PATH, so the default
	// `leftupdown=ipsec _updown` fails and the IPsec SA never installs (breaking
	// real L2TP/IPsec, esp. a 2nd concurrent client). Point it at the absolute
	// bundle path. Host libreswan has `ipsec` on PATH, so it keeps the default.
	if ipsec.UsingBundledIpsec() {
		feat.leftupdown = ipsec.BundledIpsecUpdown()
	}
	return feat
}

// buildIpsecConf renders /etc/ipsec.conf: one `config setup` block and one stanza per
// connection. A single conn on %defaultroute is the panel-wide shape and must stay byte
// for byte what it has always been.
func buildIpsecConf(feat libreswanFeatures, conns []ipsecConn) string {
	var b strings.Builder
	b.WriteString("# Auto-generated by pxpanel L2TP service — do not edit\n")
	b.WriteString("config setup\n")
	b.WriteString("    uniqueids=no\n")
	b.WriteString("    logfile=/var/log/pluto.log\n")
	if feat.ikev1Policy {
		b.WriteString("    ikev1-policy=accept\n")
	}
	for _, conn := range conns {
		b.WriteString("\n")
		b.WriteString("conn " + conn.name + "\n")
		b.WriteString("    auto=add\n")
		if feat.leftupdown != "" {
			fmt.Fprintf(&b, "    leftupdown=%q\n", feat.leftupdown)
		}
		b.WriteString("    leftprotoport=17/1701\n")
		b.WriteString("    rightprotoport=17/%any\n")
		b.WriteString("    type=transport\n")
		b.WriteString("    authby=secret\n")
		b.WriteString("    pfs=no\n")
		b.WriteString("    rekey=no\n")
		b.WriteString("    dpddelay=40\n")
		b.WriteString("    dpdtimeout=130\n")
		if feat.keyexchangeV1 {
			b.WriteString("    keyexchange=ikev1\n")
		} else {
			b.WriteString("    keyexchange=ike\n")
			b.WriteString("    ikev2=no\n")
		}
		// IKE (phase 1) proposals — widest client compatibility. modp2048/modp1536
		// and the ECP groups (dh19/dh20) are in every Libreswan; modp1024 (DH2) is
		// only present in an ALL_ALGS=true build. Libreswan rejects the WHOLE
		// connection if the proposal names a group it doesn't support, so modp1024
		// is appended only when the installed Libreswan actually has it — otherwise
		// stock/distro Libreswan (which the setup installs) fails to load the conn.
		ike := "aes256-sha2;modp2048,aes128-sha2;modp2048,aes256-sha1;modp2048,aes128-sha1;modp2048,3des-sha1;modp2048," +
			"aes256-sha2;modp1536,aes128-sha2;modp1536,aes256-sha1;modp1536,aes128-sha1;modp1536,3des-sha1;modp1536,3des-md5;modp1536," +
			"aes256-sha2;dh20,aes256-sha2;dh19,aes128-sha2;dh19"
		if feat.modp1024 {
			ike += ",aes256-sha2;modp1024,aes128-sha2;modp1024,aes256-sha1;modp1024,aes128-sha1;modp1024,3des-sha1;modp1024,3des-md5;modp1024"
		}
		b.WriteString("    ike=" + ike + "\n")
		// ESP (Phase 2) proposals: SHA2 + SHA1 + MD5 for widest compatibility
		b.WriteString("    phase2alg=aes256-sha2,aes128-sha2,aes256-sha1,aes128-sha1,3des-sha1,aes256-md5,aes128-md5,3des-md5\n")
		b.WriteString("    left=" + conn.left + "\n")
		b.WriteString("    right=%any\n")
	}
	return b.String()
}

// ipsecSupportsModp1024 reports whether the installed Libreswan supports the
// MODP1024 (DH2) group. Distro/stock Libreswan omits it (it's cryptographically
// weak — only a build with ALL_ALGS=true has it), and naming an unsupported
// group in a proposal makes Libreswan reject the whole connection. The selftest
// aborts (and thus reports "not supported") if the NSS DB isn't initialized,
// which safely errs toward dropping modp1024.
func ipsecSupportsModp1024() bool {
	// The bundled libreswan is built USE_DH2=true, so MODP1024 is always present —
	// and asserting it here avoids running pluto --selftest before its NSS db is
	// initialized (which would abort and wrongly report "no MODP1024").
	if ipsec.UsingBundledIpsec() {
		return true
	}
	out, _ := exec.CommandContext(context.Background(), "ipsec", "pluto", "--selftest").CombinedOutput()
	return strings.Contains(strings.ToUpper(string(out)), "MODP1024")
}

// l2tpSwanctlConn renders one IKEv1 transport-mode PSK connection.
//
// localAddr == "" is the panel-wide form: no local_addrs (charon answers on every
// address) and an owner-less secret (charon offers the key to every peer). It must stay
// byte for byte what the panel wrote before per-inbound keys existed, because every
// existing install regenerates this file on the next restart.
//
// A localAddr pins the connection to one address and scopes the secret to it. In IKEv1
// Main Mode the identities ARE the IP addresses at the point the key is looked up — the
// ID payload does not arrive until message 5, encrypted under keys already derived from
// the key being looked up — so id_local is the owner that matches, and it is the only
// owner that can distinguish two of these connections. id_any = %any is the other half of
// the pair strongSwan requires: a secret that names owners must match BOTH ends, so
// without it this key would never be selected at all (see greipsec.go, which learned that
// the hard way).
func l2tpSwanctlConn(connName, secretName, psk, localAddr string) string {
	esc := strings.ReplaceAll(psk, `\`, `\\`)
	esc = strings.ReplaceAll(esc, `"`, `\"`)

	var b strings.Builder
	b.WriteString("# Auto-generated by pxpanel L2TP service (IKEv1 transport on shared charon) - do not edit\n")
	b.WriteString("connections {\n")
	fmt.Fprintf(&b, "    %s {\n", connName)
	if localAddr != "" {
		fmt.Fprintf(&b, "        local_addrs = %s\n", localAddr)
	}
	b.WriteString("        version = 1\n")
	b.WriteString("        aggressive = no\n")
	b.WriteString("        mobike = no\n")
	b.WriteString("        rekey_time = 3h\n")
	b.WriteString("        reauth_time = 0s\n")
	b.WriteString("        dpd_delay = 30s\n")
	b.WriteString("        fragmentation = yes\n")
	b.WriteString("        proposals = aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048,3des-sha1-modp2048,aes256-sha1-modp1536,3des-sha1-modp1536,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024,default\n")
	b.WriteString("        local {\n            auth = psk\n        }\n")
	b.WriteString("        remote {\n            auth = psk\n        }\n")
	b.WriteString("        children {\n")
	b.WriteString("            l2tp {\n")
	b.WriteString("                mode = transport\n")
	// swanctl traffic-selector syntax (NOT stroke): port must be numeric (no `l2tp`
	// service name) and "any remote port" is an OMITTED port, not `%any` (swanctl rejects
	// `%any` with "invalid value for: remote_ts"). We are the LNS: local = our L2TP port
	// 1701, remote = the client's any UDP port.
	b.WriteString("                local_ts = dynamic[udp/1701]\n")
	b.WriteString("                remote_ts = dynamic[udp]\n")
	b.WriteString("                esp_proposals = aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1,3des-sha1,default\n")
	b.WriteString("                rekey_time = 1h\n")
	b.WriteString("                dpd_action = clear\n")
	b.WriteString("            }\n")
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	b.WriteString("secrets {\n")
	fmt.Fprintf(&b, "    %s {\n", secretName)
	if localAddr != "" {
		fmt.Fprintf(&b, "        id_local = %s\n", localAddr)
		b.WriteString("        id_any = %any\n")
	}
	fmt.Fprintf(&b, "        secret = \"%s\"\n", esc)
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return b.String()
}
