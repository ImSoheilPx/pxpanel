package ipsec

// The bundled libreswan (pluto) path: the panel runs its OWN relocatable
// libreswan as a supervised child process instead of the host's ipsec.service,
// whenever a relocatable libreswan bundle is embedded for this architecture.
// That bundle is built with USE_DH2=true (vpn-ui build/backend/libreswan-bundle.sh),
// so it offers the MODP1024 (DH2) group that legacy L2TP/IPsec clients —
// Windows 7, old MikroTik — need in IKEv1, and which no distro libreswan
// package ships.
//
// When no bundle is embedded (e.g. arm64), UsingBundledIpsec() is false and
// every ipsec helper in pkgmgr / the l2tp service / the core wave falls back to
// the host package + systemd path exactly as before — byte-for-byte unchanged.
//
// (vpn-ui web/service/ipsec_bundle.go, verbatim; the backend.* embed reads go
// through procmgr.Bundles() — see the package comment.)

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/vpn/log"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/pkgmgr"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"
)

// UsingBundledIpsec reports whether the panel should run its own bundled
// libreswan rather than the host ipsec.service — true whenever a bundle is
// embedded for this arch. Extraction to disk is ensured lazily by
// ipsecCmd()/StartBundledPluto().
func UsingBundledIpsec() bool {
	return procmgr.Bundles().UsingBundledIpsec()
}

// bundledIpsecPath is the bundled `ipsec` launcher (vpn-ui backend.IpsecBundled:
// LibreswanBundleRoot + "/sbin/ipsec"), "" when no bundle layer provides one.
func bundledIpsecPath() string {
	if p := procmgr.Bundles().IpsecBundledPath(); p != "" {
		return p
	}
	if root := procmgr.Bundles().LibreswanBundleRoot(); root != "" {
		return root + "/sbin/ipsec"
	}
	return ""
}

// bundledPlutoPath is the bundled pluto daemon (vpn-ui backend.PlutoBundled).
func bundledPlutoPath() string {
	if p := procmgr.Bundles().PlutoBundledPath(); p != "" {
		return p
	}
	if root := procmgr.Bundles().LibreswanBundleRoot(); root != "" {
		return root + "/sbin/pluto"
	}
	return ""
}

// libreswanNssDir is the NSS database directory the bundled pluto uses (vpn-ui
// backend.LibreswanNssDir — the libreswan default "/etc/ipsec.d", so generated
// ipsec.conf/ipsec.secrets paths are unchanged).
func libreswanNssDir() string {
	if d := procmgr.Bundles().LibreswanNssDir(); d != "" {
		return d
	}
	return "/etc/ipsec.d"
}

// EnsureIpsecExtracted unpacks the libreswan bundle to its fixed path if it
// isn't already on disk. Idempotent and cheap after the first call.
func EnsureIpsecExtracted() error {
	if !UsingBundledIpsec() || procmgr.Bundles().LibreswanBundleReady() {
		return nil
	}
	return procmgr.Bundles().ExtractLibreswanBundle()
}

// BundledIpsecUpdown is the leftupdown command for the bundled pluto: the
// ABSOLUTE path to the bundle's `ipsec` wrapper plus the `_updown` subcommand.
// pluto runs its updown script on every SA up/down; the libreswan default
// `ipsec _updown` relies on `ipsec` being on PATH, but the bundle lives under
// /usr/libexec (NOT on the pluto child's PATH) — so the default fails with
// "ipsec: not found" (status 127), which aborts the XFRM policy install and the
// IPsec SA never comes up. L2TP then only limps along on its raw fallback, and
// a 2nd concurrent client fails outright. Pointing leftupdown at the absolute
// path (the wrapper fixes PATH/IPSEC_EXECDIR for everything it then runs)
// resolves it.
func BundledIpsecUpdown() string {
	return procmgr.Bundles().LibreswanBundleRoot() + "/sbin/ipsec _updown"
}

// EnsureIpsecNssDir makes sure the NSS database directory exists before
// `ipsec checknss` runs. The bundled checknss initializes the db files but does
// NOT create their parent dir — host libreswan ships /etc/ipsec.d via its
// package, but our bundle installs nothing under /etc. Without this, checknss
// fails with "destination directory /etc/ipsec.d is missing" and pluto then
// crash-loops every 5s on SEC_ERROR_BAD_DATABASE (NSS init against a missing
// dir).
func EnsureIpsecNssDir() {
	_ = os.MkdirAll(libreswanNssDir(), 0o700)
}

// EnsureBundledLibreswan is the provisioning step for the bundled IPsec: extract
// the tree and initialize its NSS database. It does NOT start pluto — that
// happens when L2TP actually loads a connection (RestartServices), which needs
// the generated /etc/ipsec.conf to exist first.
func EnsureBundledLibreswan() pkgmgr.ProvisionStep {
	if err := EnsureIpsecExtracted(); err != nil {
		return pkgmgr.ProvisionStep{
			Name: "libreswan (bundled IPsec)",
			OK:   false,
			Msg:  "failed to extract the bundled libreswan: " + err.Error(),
		}
	}
	EnsureIpsecNssDir()
	var logb strings.Builder
	out, err := exec.CommandContext(context.Background(), bundledIpsecPath(), "checknss").CombinedOutput()
	logb.WriteString(string(out))
	if err != nil {
		return pkgmgr.ProvisionStep{
			Name: "libreswan (bundled IPsec)", OK: true, Warn: true,
			Msg: "bundled libreswan extracted; NSS init reported: " + err.Error(), Log: logb.String(),
		}
	}
	ver := ""
	if maj, min, ok := pkgmgr.LibreswanVersion(); ok {
		ver = fmt.Sprintf(" %d.%d", maj, min)
	}
	return pkgmgr.ProvisionStep{
		Name: "libreswan (bundled IPsec)", OK: true,
		Msg: "bundled libreswan" + ver + " ready — ALL_ALGS build (MODP1024 for legacy L2TP clients)",
		Log: logb.String(),
	}
}

// StartBundledPluto (re)launches the bundled pluto as a panel-managed child and
// loads the L2TP connection into it. Safe to call repeatedly: procMgr.Start
// supersedes any running instance, and the conn is re-added every time so a
// regenerated /etc/ipsec.conf is picked up. Requires /etc/ipsec.conf to exist
// (written by l2tp.GenerateIPsecConfig) — the caller writes it first.
func StartBundledPluto() error {
	if err := EnsureIpsecExtracted(); err != nil {
		return err
	}
	// NSS database: the bundled `ipsec checknss` creates the db files under the
	// wrapper's IPSEC_NSSDIR (/etc/ipsec.d) using the bundled certutil — but not
	// the dir itself, so make sure it exists first (else pluto crash-loops on a
	// bad db).
	EnsureIpsecNssDir()
	if out, err := exec.CommandContext(context.Background(), bundledIpsecPath(), "checknss").CombinedOutput(); err != nil {
		log.Warning("bundled ipsec checknss:", err, strings.TrimSpace(string(out)))
	}
	_ = os.MkdirAll("/run/pluto", 0o755)

	// pluto in the foreground so procMgr supervises it and captures its log
	// (--stderrlog routes pluto's log to stderr, which procMgr records).
	args := []string{"--nofork", "--stderrlog", "--config", "/etc/ipsec.conf", "--nssdir", libreswanNssDir()}
	if err := procmgr.GetProcManager().Start(ipsecProcName, bundledPlutoPath(), args, nil, ""); err != nil {
		return err
	}

	// Loading a conn needs pluto's control socket, which appears ~1s after start.
	if WaitForPath(plutoCtl, 8*time.Second) {
		// EVERY conn in the file, not the one name this used to hardcode: L2TP
		// writes one connection per inbound when each has its own listen address,
		// and `auto --add l2tp-psk` against a file that only holds l2tp-psk-3 and
		// l2tp-psk-4 loads nothing at all ("no connection named"). Read back what
		// was written rather than recomputing it, so an operator override is
		// loaded too.
		conf, _ := os.ReadFile("/etc/ipsec.conf")
		for _, name := range ipsecConnNames(string(conf)) {
			if out, err := exec.CommandContext(context.Background(), bundledIpsecPath(), "auto", "--add", name).CombinedOutput(); err != nil {
				log.Warning("bundled ipsec auto --add", name+":", err, strings.TrimSpace(string(out)))
			}
		}
	} else {
		log.Warning("bundled pluto: control socket never appeared at", plutoCtl)
	}
	return nil
}

// ipsecConnNames lists the connections defined in an ipsec.conf, in file order.
// Falls back to the panel-wide name when the file could not be read or defines
// nothing, so a missing file behaves exactly as the hardcoded name did.
func ipsecConnNames(conf string) []string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		// `conn` is only a section header at column 0; the keywords inside a
		// stanza are indented, and `config setup` is not a conn.
		if !strings.HasPrefix(line, "conn ") {
			continue
		}
		if name := strings.TrimSpace(strings.TrimPrefix(line, "conn ")); name != "" {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return []string{ipsecConnName}
	}
	return out
}

// IpsecConnNames is the exported form of ipsecConnNames for the protocol
// packages' tests (vpn-ui's test lived in the same package).
func IpsecConnNames(conf string) []string { return ipsecConnNames(conf) }

// StopBundledPluto stops the panel-managed pluto child (best-effort clean IKE
// shutdown first).
func StopBundledPluto() error {
	_ = exec.Command(bundledIpsecPath(), "whack", "--shutdown").Run()
	return procmgr.GetProcManager().Stop(ipsecProcName)
}

// BundledPlutoRunning reports whether the panel-managed pluto child is alive.
func BundledPlutoRunning() bool {
	return procmgr.GetProcManager().IsRunning(ipsecProcName)
}

// WaitForPath polls until path exists or timeout elapses.
func WaitForPath(path string, timeout time.Duration) bool {
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
