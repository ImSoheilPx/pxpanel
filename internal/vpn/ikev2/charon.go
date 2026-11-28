// The bundled strongSwan charon is a SINGLE shared daemon (procMgr key ikev2ProcName)
// that serves BOTH IKEv2 (per-inbound conf.d/ikev2-<id>.conf) and, since the IPsec layer
// was unified in vpn-ui, L2TP/IPsec IKEv1 transport (conf.d/l2tp.conf). It owns UDP
// 500/4500 for both, which removes the old charon-vs-pluto (libreswan) port collision.
// This file holds the charon lifecycle both the ikev2 and l2tp services drive;
// swanctl.conf's `include conf.d/*.conf` loads every connection with one
// `swanctl --load-all`.
//
// PORT: vpn-ui web/service/charon.go (the l2tp and gre services call syncCharon through
// their own waves' packages; the L2TP/GRE waves should reach THIS package's SyncCharon —
// or a promoted internal/vpn/ipsec shared package — rather than re-porting the
// lifecycle a second time, because two copies would fight over the one daemon that owns
// UDP 500/4500 and /etc/swanctl).
//
// PORT ADAPTATIONS vs vpn-ui charon.go:
//   - database.GetDB() → vpn.DB().
//   - SettingService.GetRadiusSecret → vpn.RadiusSecret().
//   - procMgr → procmgr.GetProcManager().
//   - backend.StrongswanBundleReady/ExtractStrongswanBundle/LinkStrongswanIpsecDir →
//     the procmgr.Bundles() BundleProvider seam (no-bundle default: no-op, distro path).
//   - backend.StrongswanDefaultConfDir → strongswanDefaultConfDir() (ikev2.go), with a
//     distro /etc/strongswan.d fallback when no bundle is installed.
//   - ownPrepareHostFile → manifest.PrepareHostFile.
//   - applyCoreConfigOverride → coreconfig.ApplyCoreConfigOverride.
//   - vpnOutboundNeedsCharon (VpnOutboundService.listRaw, the vpnout wave's service) →
//     the vpnOutboundNeedsCharonHook var (SetVpnOutboundNeedHook); until the vpnout wave
//     registers it, the hook reports false — an IKEv2 INBOUND-only host behaves
//     identically to vpn-ui; a host that dials OUT over IKEv2 without any IPsec inbound
//     needs the hook wired to keep charon up (see charonNeeded).
//   - greInboundHasIpsec (vpn-ui web/service/greipsec.go) is ported here as a pure
//     settings decode — the GRE wave's package does not exist yet, and the shared
//     daemon's need-check cannot be split across packages that don't exist.
package ikev2

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/coreconfig"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/log"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"
)

// charonBin / swanctlBin resolve the bundled launchers (or a host binary from PATH).
func charonBin() string {
	if p := procmgr.Bundles().StrongswanBinPath("charon"); p != "" {
		return p
	}
	return "charon"
}

func swanctlBin() string {
	if p := procmgr.Bundles().StrongswanBinPath("swanctl"); p != "" {
		return p
	}
	return "swanctl"
}

// vpnOutboundNeedsCharonHook reports whether any enabled CLIENT-side tunnel rides this
// daemon (vpn-ui charon.go:vpnOutboundNeedsCharon read VpnOutboundService.listRaw).
//
// The outbound clause is not symmetry for its own sake. syncCharon runs from every
// inbound save, and this daemon is shared: on a box that dials out over IKEv2 but
// serves no IPsec inbound of its own, counting inbounds alone answers "not needed"
// and stops charon out from under a live outbound. The tunnel then drops on an
// unrelated edit to some other protocol's inbound, which is about as far from the
// apparent cause as a failure gets.
//
// PORT SEAM (vpnout wave): the vpnout driver set is not ported yet, so the check is a
// hook — SetVpnOutboundNeedHook at wire-up with a closure over the vpnout tunnel list
// (vpn-ui read the RAW list, not the masked view, because the L2TP PSK below is exactly
// such a secret). Default false = "no outbounds exist", which is literally true until
// that wave lands.
var vpnOutboundNeedsCharonHook func() bool

// SetVpnOutboundNeedHook installs the client-tunnel clause of charonNeeded. See the
// var's doc. Call once at server wire-up; safe to call again (last wins).
func SetVpnOutboundNeedHook(f func() bool) { vpnOutboundNeedsCharonHook = f }

func vpnOutboundNeedsCharon() bool {
	if vpnOutboundNeedsCharonHook == nil {
		return false
	}
	return vpnOutboundNeedsCharonHook()
}

// charonNeeded reports whether the shared charon should be running: true when any
// enabled IKEv2 inbound exists, or any enabled L2TP inbound has IPsec enabled, or any
// enabled GRE inbound has IPsec enabled (GRE-over-IPsec is ESP transport on this same
// daemon), or any enabled client-side OUTBOUND needs it (the hook above).
func charonNeeded() bool {
	db := vpn.DB()
	if db == nil {
		return false
	}
	if vpnOutboundNeedsCharon() {
		return true
	}
	var ikev2Count int64
	db.Model(&model.Inbound{}).Where("protocol = ? AND enable = ?", "ikev2", true).Count(&ikev2Count)
	if ikev2Count > 0 {
		return true
	}
	var l2tps []*model.Inbound
	db.Model(&model.Inbound{}).Where("protocol = ? AND enable = ?", "l2tp", true).Find(&l2tps)
	for _, ib := range l2tps {
		if l2tpInboundHasIpsec(ib) {
			return true
		}
	}
	var gres []*model.Inbound
	db.Model(&model.Inbound{}).Where("protocol = ? AND enable = ?", "gre", true).Find(&gres)
	for _, ib := range gres {
		if greInboundHasIpsec(ib) {
			return true
		}
	}
	return false
}

// l2tpInboundHasIpsec reports whether an l2tp inbound has IPsec enabled (ipsecEnable
// defaults to true when the key is absent, matching the l2tp settings model).
// PORT NOTE: vpn-ui defined this in charon.go (same file); it is a pure settings
// decode, so it ports here unchanged — the l2tp wave need not re-export it.
func l2tpInboundHasIpsec(inbound *model.Inbound) bool {
	if inbound == nil {
		return false
	}
	var st struct {
		IpsecEnable *bool `json:"ipsecEnable"`
	}
	_ = json.Unmarshal([]byte(inbound.Settings), &st)
	return st.IpsecEnable == nil || *st.IpsecEnable
}

// greInboundHasIpsec reports whether a GRE inbound rides the shared charon (GRE-over-
// IPsec is ESP transport on it). PORT NOTE: vpn-ui defined this in
// web/service/greipsec.go; it is ported HERE because charonNeeded cannot reach across
// to a GRE package that has not landed, and the decode is pure settings reading.
// The GRE wave should switch to this package's SyncCharon instead of duplicating.
func greInboundHasIpsec(inbound *model.Inbound) bool {
	if inbound == nil {
		return false
	}
	var st struct {
		IpsecEnable bool   `json:"ipsecEnable"`
		IpsecPsk    string `json:"ipsecPsk"`
	}
	if err := json.Unmarshal([]byte(inbound.Settings), &st); err != nil {
		return false
	}
	return st.IpsecEnable && strings.TrimSpace(st.IpsecPsk) != ""
}

// charonDNS returns the DNS servers to advertise (IKEv2 pools use them; L2TP gets DNS
// from PPP, so this only matters for ikev2). Falls back to public resolvers.
func charonDNS() (string, string) {
	dns1, dns2 := "8.8.8.8", "8.8.4.4"
	db := vpn.DB()
	if db == nil {
		return dns1, dns2
	}
	var ikev2s []*model.Inbound
	db.Model(&model.Inbound{}).Where("protocol = ? AND enable = ?", "ikev2", true).Find(&ikev2s)
	for _, ib := range ikev2s {
		var st struct {
			Dns1 string `json:"dns1"`
			Dns2 string `json:"dns2"`
		}
		if json.Unmarshal([]byte(ib.Settings), &st) == nil {
			if st.Dns1 != "" {
				dns1 = st.Dns1
			}
			if st.Dns2 != "" {
				dns2 = st.Dns2
			}
			break
		}
	}
	return dns1, dns2
}

// writeCharonConf writes /etc/strongswan.conf (shared charon config incl. the eap-radius
// plugin for IKEv2 EAP-MSCHAPv2, harmless to L2TP) + /etc/swanctl/swanctl.conf (which
// includes every conf.d/*.conf: ikev2-<id>.conf and l2tp.conf). Written whenever charon
// is needed by either protocol, so an L2TP-only box also gets a valid config to boot on.
func writeCharonConf() error {
	body, err := buildCharonConf()
	if err != nil {
		return err
	}
	_ = os.MkdirAll(ikev2ConfigRoot, 0o755)

	// Both of these belong to a host strongSwan when there is one, and both are
	// replaced outright: strongswan.conf with our whole render, swanctl.conf with a
	// single `include conf.d/*.conf` line that drops every connection the operator
	// had defined in it. Backed up on the first overwrite so uninstall can restore
	// them; see the ownership manifest (manifest.PrepareHostFile).
	manifest.PrepareHostFile("/etc/strongswan.conf", "ikev2")
	if err := os.WriteFile("/etc/strongswan.conf",
		[]byte(coreconfig.ApplyCoreConfigOverride("ipsec", 0, "strongswan.conf", body)), 0o600); err != nil {
		return fmt.Errorf("write /etc/strongswan.conf: %w", err)
	}

	// swanctl.conf just pulls in the per-protocol connection files, so it carries no
	// operator-visible settings of its own and is not offered in the config editor.
	_ = os.MkdirAll(swanctlConfDir, 0o755)
	_ = os.MkdirAll(swanctlX509, 0o755)
	_ = os.MkdirAll(swanctlX509CA, 0o755)
	_ = os.MkdirAll(swanctlPrivate, 0o700)
	manifest.PrepareHostFile(swanctlDir+"/swanctl.conf", "ikev2")
	return os.WriteFile(swanctlDir+"/swanctl.conf", []byte("include conf.d/*.conf\n"), 0o600)
}

// buildCharonConf renders the strongswan.conf body. Split from the write so the config
// editor can show the operator the GENERATED text they are diverging from; the file on
// disk already has their override merged in.
func buildCharonConf() (string, error) {
	dns1, dns2 := charonDNS()
	radiusSecret, _ := vpn.RadiusSecret()

	var b strings.Builder
	b.WriteString("# Auto-generated by pxpanel (shared charon) - do not edit\n")
	b.WriteString("charon {\n")
	b.WriteString("    load_modular = yes\n")
	// `never` (not `no`): ignore INITIAL_CONTACT so multiple devices per account coexist;
	// the panel RADIUS governs the K limit for IKEv2.
	b.WriteString("    uniqueids = never\n")
	// Stay root: the bundled charon (Alpine build) would setuid to a nonexistent `ipsec`
	// user and abort. The panel runs as root and needs CAP_NET_ADMIN for XFRM anyway.
	b.WriteString("    user = root\n")
	b.WriteString("    group = root\n")
	// We own routing via nftables TPROXY; charon must NOT install a 0.0.0.0/0 route. This
	// only suppresses route installation, not the transport/tunnel XFRM policies.
	b.WriteString("    install_routes = no\n")
	b.WriteString("    filelog {\n")
	b.WriteString("        stderr {\n")
	b.WriteString("            default = 1\n")
	b.WriteString("            ike_name = yes\n")
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("    plugins {\n")
	fmt.Fprintf(&b, "        include %s/charon/*.conf\n", strongswanDefaultConfDir())
	b.WriteString("        eap-radius {\n")
	b.WriteString("            accounting = yes\n")
	b.WriteString("            accounting_interval = 300\n")
	b.WriteString("            servers {\n")
	b.WriteString("                pxpanel {\n")
	b.WriteString("                    address = 127.0.0.1\n")
	fmt.Fprintf(&b, "                    secret = %s\n", radiusSecret)
	b.WriteString("                    auth_port = 1812\n")
	b.WriteString("                    acct_port = 1813\n")
	b.WriteString("                    nas_identifier = ikev2\n")
	b.WriteString("                }\n")
	b.WriteString("            }\n")
	b.WriteString("        }\n")
	b.WriteString("        attr {\n")
	fmt.Fprintf(&b, "            dns = %s, %s\n", dns1, dns2)
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return b.String(), nil
}

// ensureCharonRunning extracts/links the strongswan bundle and starts the shared charon
// (procMgr key ikev2ProcName) if it isn't already up, waiting for its vici socket.
// Idempotent; never drops live SAs when charon is already running.
func ensureCharonRunning() error {
	// Extract the bundle only if absent: re-extracting under a running charon overwrites
	// mmap'd .so files and SEGFAULTs it. The symlink is idempotent + always ensured.
	// PORT: both go through the BundleProvider seam (vpn-ui read backend/ directly);
	// the no-bundle default no-ops both, leaving a distro strongSwan in place.
	bundles := procmgr.Bundles()
	if !bundles.StrongswanBundleReady() {
		if err := bundles.ExtractStrongswanBundle(); err != nil {
			log.Warning("charon: extract strongswan bundle:", err)
		}
	}
	if err := bundles.LinkStrongswanIpsecDir(); err != nil {
		log.Warning("charon: link strongswan ipsec dir:", err)
	}
	if !procmgr.GetProcManager().IsRunning(ikev2ProcName) {
		_ = os.MkdirAll("/var/run", 0o755)
		if err := procmgr.GetProcManager().Start(ikev2ProcName, charonBin(), nil, nil, ikev2ConfigRoot); err != nil {
			return fmt.Errorf("start charon: %w", err)
		}
		if !waitForPath(viciSocket, 10*time.Second) {
			log.Warning("charon: vici socket never appeared at", viciSocket)
		}
	}
	return nil
}

// waitForPath polls until path exists or timeout elapses. PORT NOTE: vpn-ui defined
// this in web/service/ipsec_bundle.go (the ipsec wave's file); it is duplicated here
// because ensureCharonRunning needs it and that file is out of this wave's scope.
func waitForPath(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// reloadCharon (re)loads all swanctl conf.d connections/creds/pools into the running
// charon without dropping live SAs.
func reloadCharon() error {
	// Right after charon starts, its vici socket file can exist before charon actually
	// accepts connections (plugins still initializing), so a single --load-all can fail
	// with "Connection refused". On an ikev2+l2tp box the other protocol's later syncCharon
	// covers this, but an l2tp-only (or ikev2-only) box gets one shot, so retry briefly on
	// a vici connection error. A genuine config error (not a connect failure) breaks early.
	var out []byte
	var err error
	for attempt := 0; attempt < 6; attempt++ {
		out, err = exec.CommandContext(context.Background(), swanctlBin(), "--load-all").CombinedOutput()
		if err == nil {
			return nil
		}
		s := string(out)
		if !strings.Contains(s, "Connection refused") && !strings.Contains(s, "connecting to") {
			break
		}
		time.Sleep(time.Second)
	}
	log.Warning("charon: swanctl --load-all:", err, strings.TrimSpace(string(out)))
	return nil
}

// stopCharon stops the shared charon process.
func stopCharon() error {
	return procmgr.GetProcManager().Stop(ikev2ProcName)
}

// syncCharon is the shared entrypoint both the ikev2 and l2tp services call after
// writing their own conf.d files. It starts (or stops) the one charon based on whether
// either protocol still needs it, and reloads all connections. Because it is keyed on the
// shared ikev2ProcName, ikev2 and l2tp cooperate: whichever runs last leaves charon in the
// right state, and `swanctl --load-all` merges both sets of conf.d files.
func syncCharon() error {
	if !charonNeeded() {
		return stopCharon()
	}
	if err := writeCharonConf(); err != nil {
		return err
	}
	if err := ensureCharonRunning(); err != nil {
		return err
	}
	return reloadCharon()
}

// SyncCharon is the exported form of syncCharon for the sibling protocol services that
// share this daemon (vpn-ui: the l2tp and gre services called the package-private
// syncCharon directly). The L2TP/IPsec and GRE waves should call THIS (or promote this
// file into the shared ipsec package) — running two charon lifecycles against the one
// daemon that owns UDP 500/4500 and /etc/swanctl would fight.
func SyncCharon() error { return syncCharon() }

// CharonNeeded is the exported form of charonNeeded, for the same callers (vpn-ui
// coreconfig.go:ipsecConfigTargets asked it whether the shared daemon config exists).
func CharonNeeded() bool { return charonNeeded() }
