package ipsec

// The bundled strongSwan charon is a SINGLE shared daemon (procMgr key
// ikev2ProcName) that serves BOTH IKEv2 (per-inbound conf.d/ikev2-<id>.conf,
// ikev2 wave) and, since we unified the IPsec layer, L2TP/IPsec IKEv1 transport
// (conf.d/l2tp.conf, written by the l2tp package). It owns UDP 500/4500 for
// both, which removes the old charon-vs-pluto (libreswan) port collision. This
// file holds the charon lifecycle both the ikev2 and l2tp services drive;
// swanctl.conf's `include conf.d/*.conf` loads every connection with one
// `swanctl --load-all`.
//
// (vpn-ui web/service/charon.go, verbatim; cross-package reaches go through the
// seams listed in the package comment.)

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/configedit"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/log"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"
)

// charonNeeders are the extra "does anything still need charon" clauses from
// the protocol waves this package does not import (vpn-ui read them straight
// from the ikev2/gre/vpnout services). Each returns true when its caller's
// state still needs the shared daemon.
//
// TODO(ikev2 wave): the plain inbound COUNT for ikev2 below already covers
// serving charon for IKEv2; register nothing extra unless the wave adds
// non-inbound consumers.
var (
	neederMu     sync.RWMutex
	charonNeeder []func() bool
)

// RegisterCharonNeeder attaches one protocol wave's need clause. Call from
// init(); the wave keeps its settings parsing in its own package.
func RegisterCharonNeeder(f func() bool) {
	neederMu.Lock()
	defer neederMu.Unlock()
	charonNeeder = append(charonNeeder, f)
}

func runNeeders() bool {
	neederMu.RLock()
	fs := append([]func() bool{}, charonNeeder...)
	neederMu.RUnlock()
	for _, f := range fs {
		if f() {
			return true
		}
	}
	return false
}

// vpnOutboundNeedsCharon reports whether any enabled client tunnel rides this
// daemon: an IKEv2 outbound always does, an L2TP one does when it carries a PSK
// (which is how the L2TP/IPsec transport leg is configured on both sides), and
// a GRE one does when it is wrapped in IPsec.
//
// Every kind whose settings decide it reads ONE field, matched against the
// driver's own json tag. Keep this switch in step with the drivers: a kind that
// rides charon and is missing here fails silently, as a tunnel that dies on an
// unrelated inbound save rather than as anything pointing at this function.
//
// Read off the stored tunnel list rather than asked of the drivers, because the
// answer is needed while deciding whether to STOP charon, which is exactly when
// a driver may already have been torn down and would report nothing.
//
// PORT: vpn-ui read VpnOutboundService.listRaw() here. The vpnout family is its
// own wave; until it registers, "no outbound needs charon" — on a box that
// serves no IPsec inbound either, syncCharon then stops the daemon, which is
// correct for today's feature set.
//
// TODO(vpnout wave): register a needer that lists the stored tunnels (listRaw —
// the UNMASKED view: the psk below is a driver-declared secret, and reading it
// through the masked view would find nothing, answer "no IPsec outbound", and
// stop charon under a live tunnel) and checks Kind VpnOutIKEv2 / VpnOutL2TP
// (settings ipsecPsk != "") / VpnOutGre (settings ipsecEnable).
func vpnOutboundNeedsCharon() bool {
	return false
}

// charonNeeded reports whether the shared charon should be running: true when any
// enabled IKEv2 inbound exists, or any enabled L2TP inbound has IPsec enabled, or any
// enabled GRE inbound has IPsec enabled (GRE-over-IPsec is ESP transport on this same
// daemon), or any enabled client-side OUTBOUND needs it.
//
// The outbound clause is not symmetry for its own sake. syncCharon runs from every
// inbound save, and this daemon is shared: on a box that dials out over IKEv2 but
// serves no IPsec inbound of its own, counting inbounds alone answers "not needed"
// and stops charon out from under a live outbound. The tunnel then drops on an
// unrelated edit to some other protocol's inbound, which is about as far from the
// apparent cause as a failure gets.
func charonNeeded() bool {
	db := vpn.DB()
	if db == nil {
		return false
	}
	if vpnOutboundNeedsCharon() || runNeeders() {
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
	return false
}

// l2tpInboundHasIpsec reports whether an l2tp inbound has IPsec enabled (ipsecEnable
// defaults to true when the key is absent, matching the l2tp settings model).
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
	// them; see ownership.go.
	manifest.PrepareHostFile("/etc/strongswan.conf", "ikev2")
	if err := os.WriteFile("/etc/strongswan.conf",
		[]byte(configedit.ApplyOverride("ipsec", 0, "strongswan.conf", body)), 0o600); err != nil {
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
	fmt.Fprintf(&b, "        include %s/charon/*.conf\n", procmgr.Bundles().StrongswanDefaultConfDir())
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
	b := procmgr.Bundles()
	if !b.StrongswanBundleReady() {
		if err := b.ExtractStrongswanBundle(); err != nil {
			log.Warning("charon: extract strongswan bundle:", err)
		}
	}
	if err := b.LinkStrongswanIpsecDir(); err != nil {
		log.Warning("charon: link strongswan ipsec dir:", err)
	}
	if !procmgr.GetProcManager().IsRunning(ikev2ProcName) {
		_ = os.MkdirAll("/var/run", 0o755)
		if err := procmgr.GetProcManager().Start(ikev2ProcName, charonBin(), nil, nil, ikev2ConfigRoot); err != nil {
			return fmt.Errorf("start charon: %w", err)
		}
		if !WaitForPath(viciSocket, 10*time.Second) {
			log.Warning("charon: vici socket never appeared at", viciSocket)
		}
	}
	return nil
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

// StopCharon stops the shared charon process.
func StopCharon() error {
	return procmgr.GetProcManager().Stop(ikev2ProcName)
}

// SyncCharon is the shared entrypoint both the ikev2 and l2tp services call after
// writing their own conf.d files. It starts (or stops) the one charon based on whether
// either protocol still needs it, and reloads all connections. Because it is keyed on the
// shared ikev2ProcName, ikev2 and l2tp cooperate: whichever runs last leaves charon in the
// right state, and `swanctl --load-all` merges both sets of conf.d files.
func SyncCharon() error {
	if !charonNeeded() {
		return StopCharon()
	}
	if err := writeCharonConf(); err != nil {
		return err
	}
	if err := ensureCharonRunning(); err != nil {
		return err
	}
	return reloadCharon()
}
