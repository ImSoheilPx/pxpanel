package vpnout

// The shared charon three-step the client drivers run directly:
// writeCharonConf -> ensureCharonRunning -> reloadCharon.
//
// vpn-ui's vpnout_gre.go / vpnout_ikev2.go called these on the one `service`
// package. In the target the inbound copies live unexported in
// internal/vpn/ikev2 (and internal/vpn/ipsec), neither of which this wave may
// edit, so the drivers carry the identical functions here over the same
// exported seams (procmgr, manifest, coreconfig, vpn.RadiusSecret). Everything
// is keyed on the SAME proc name ("ikev2"), config root and swanctl paths as
// the inbound copies, so there is still exactly one charon on the box and
// whichever side syncs last leaves it right.
//
// TODO(ipsec promotion wave): ipsec/charon.go and ikev2/charon.go already
// duplicate this lifecycle; fold all three copies (incl. this one) into the
// shared ipsec package and re-point these helpers at its exported form.

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
	vpnlog "github.com/ImSoheilPx/pxpanel/internal/vpn/log"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"
)

// Path + identity constants, identical to ikev2/charon.go and ipsec/paths.go.
const (
	// vpnOutIkev2ProcName is the single shared charon process key in the
	// process manager. ikev2, l2tp, gre and this package's outbounds
	// cooperate through it.
	vpnOutIkev2ProcName = "ikev2"
	// vpnOutIkev2ConfigRoot holds the generated strongswan.conf.
	vpnOutIkev2ConfigRoot = "/etc/pxpanel-ikev2"
	// swanctlDir is charon's compiled-in swanctl config dir (Alpine layout).
	swanctlDir     = "/etc/swanctl"
	swanctlConfDir = swanctlDir + "/conf.d"
	swanctlX509    = swanctlDir + "/x509"
	swanctlX509CA  = swanctlDir + "/x509ca"
	swanctlPrivate = swanctlDir + "/private"
	// viciSocket is charon's control socket swanctl connects to.
	viciSocket = "/var/run/charon.vici"
)

// swanctlBin resolves the bundled launcher (or a host binary from PATH).
func swanctlBin() string {
	if p := procmgr.Bundles().StrongswanBinPath("swanctl"); p != "" {
		return p
	}
	return "swanctl"
}

// strongswanDefaultConfDir resolves the plugin-defaults include dir the generated
// strongswan.conf's `include <dir>/charon/*.conf` line names.
func strongswanDefaultConfDir() string {
	if dir := procmgr.Bundles().StrongswanDefaultConfDir(); dir != "" {
		return dir
	}
	return "/etc/strongswan.d"
}

// charonBin resolves the bundled launcher (or a host binary from PATH).
func charonBin() string {
	if p := procmgr.Bundles().StrongswanBinPath("charon"); p != "" {
		return p
	}
	return "charon"
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
// includes every conf.d/*.conf: ikev2-<id>.conf, l2tp.conf, greout-*.conf, ikev2out-*.conf).
// Written whenever charon is needed by any protocol, so an inbound-only box also gets a
// valid config to boot on.
func writeCharonConf() error {
	body, err := buildVpnOutCharonConf()
	if err != nil {
		return err
	}
	_ = os.MkdirAll(vpnOutIkev2ConfigRoot, 0o755)

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

// buildVpnOutCharonConf renders the strongswan.conf body. Split from the write so the
// config editor can show the operator the GENERATED text they are diverging from; the file
// on disk already has their override merged in. (ikev2/charon.go buildCharonConf.)
func buildVpnOutCharonConf() (string, error) {
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
// (procMgr key ikev2) if it isn't already up, waiting for its vici socket.
// Idempotent; never drops live SAs when charon is already running.
func ensureCharonRunning() error {
	// Extract the bundle only if absent: re-extracting under a running charon overwrites
	// mmap'd .so files and SEGFAULTs it. The symlink is idempotent + always ensured.
	// Both go through the BundleProvider seam (vpn-ui read backend/ directly);
	// the no-bundle default no-ops both, leaving a distro strongSwan in place.
	bundles := procmgr.Bundles()
	if !bundles.StrongswanBundleReady() {
		if err := bundles.ExtractStrongswanBundle(); err != nil {
			vpnlog.Warning("charon: extract strongswan bundle:", err)
		}
	}
	if err := bundles.LinkStrongswanIpsecDir(); err != nil {
		vpnlog.Warning("charon: link strongswan ipsec dir:", err)
	}
	if !procmgr.GetProcManager().IsRunning(vpnOutIkev2ProcName) {
		_ = os.MkdirAll("/var/run", 0o755)
		if err := procmgr.GetProcManager().Start(vpnOutIkev2ProcName, charonBin(), nil, nil, vpnOutIkev2ConfigRoot); err != nil {
			return fmt.Errorf("start charon: %w", err)
		}
		if !vpnOutWaitForPath(viciSocket, 10*time.Second) {
			vpnlog.Warning("charon: vici socket never appeared at", viciSocket)
		}
	}
	return nil
}

// vpnOutWaitForPath polls until path exists or timeout elapses (ikev2/charon.go waitForPath).
func vpnOutWaitForPath(path string, timeout time.Duration) bool {
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
	vpnlog.Warning("charon: swanctl --load-all:", err, strings.TrimSpace(string(out)))
	return nil
}
