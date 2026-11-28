// Package procmgr supervises the bundled VPN daemons (openvpn, xl2tpd, pptpd,
// ocserv, accel-ppp, ...) as child processes of the panel binary, and manages
// the panel's own systemd unit. Ported from vpn-ui web/service/procmgr.go +
// systemd.go.
//
// ADAPTATION: vpn-ui resolved daemons through its embedded backend/ bundle
// package (go:embed'd daemon binaries) and read the service name from its
// settings service. Neither exists in pxpanel yet, so both seams are behind
// small interfaces (BundleProvider, ServiceNameStore) with inert defaults; the
// bundle/build wave and the settings wave replace them via SetBundleProvider /
// SetServiceNameStore. With the defaults, daemons resolve from PATH and the
// systemd integration is fully functional for a fixed service name.
package procmgr

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/vpn/log"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
)

// BundleProvider abstracts the daemon-bundle layer (vpn-ui's backend/ package:
// embedded per-arch binaries (go:embed) + relocatable trees). The zero/noop provider
// means "this build ships no bundles": every daemon resolves from PATH, which is
// correct for a host where the operator installed them.
//
// TODO(bundle wave): implement over the extracted backend embeds and install
// with SetBundleProvider.
type BundleProvider interface {
	// DaemonPath resolves a flat bundled binary by name, "" when absent.
	DaemonPath(name string) string
	// AccelBinPath resolves inside the accel-ppp relocatable bundle TREE (SSTP).
	AccelBinPath(name string) string
	// StrongswanBinPath resolves inside the strongSwan relocatable bundle TREE.
	StrongswanBinPath(name string) string
	// UsingBundledPppd reports whether the bundled pppd (OpenSSL legacy provider
	// for MS-CHAP/MPPE) is in play rather than the host's.
	UsingBundledPppd() bool
	// PppdBundledPath is the bundled pppd path passed as pptpd's --ppp argument.
	PppdBundledPath() string
	// OpenSSLModulesDir feeds OPENSSL_MODULES for the bundled pppd.
	OpenSSLModulesDir() string
	// LinkPptpCtrl symlinks the bundled pptpctrl to pptpd's compiled-in path.
	LinkPptpCtrl() error
	// DistroUnitExists reports whether the DISTRO ships the named unit (vs. one
	// we generated).
	DistroUnitExists(name string) bool
	// UsingBundledIpsec reports whether a libreswan bundle replaces the distro
	// ipsec.service (vpn-ui ipsec_bundle.go:usingBundledIpsec).
	UsingBundledIpsec() bool
	// HasStrongswanBundle / StrongswanBundleRoot / LibreswanBundleRoot expose
	// the relocatable trees the orphan-reap and unit migration match against.
	HasStrongswanBundle() bool
	StrongswanBundleRoot() string
	LibreswanBundleRoot() string

	// --- IPsec bundle lifecycle (vpn-ui backend/libreswan.go + strongswan.go).
	// Driven by the ipsec wave (internal/vpn/ipsec); implemented over the
	// extracted embeds by the bundle wave. The no-bundle defaults below keep
	// every caller on the distro ipsec.service path.
	IpsecBundledPath() string         // bundled `ipsec` launcher (backend.IpsecBundled)
	PlutoBundledPath() string         // bundled pluto daemon (backend.PlutoBundled)
	LibreswanNssDir() string          // NSS db dir the bundled pluto uses (backend.LibreswanNssDir)
	LibreswanBundleReady() bool       // the libreswan tree is already on disk
	ExtractLibreswanBundle() error    // unpack the libreswan tree (idempotent)
	StrongswanBundleReady() bool      // the strongSwan tree is already on disk
	ExtractStrongswanBundle() error   // unpack the strongSwan tree (idempotent)
	LinkStrongswanIpsecDir() error    // symlink the bundle's ipsec.d dir (backend.LinkStrongswanIpsecDir)
	StrongswanDefaultConfDir() string // plugin conf.d dir (backend.StrongswanDefaultConfDir), "" = none
}

// noopBundle is the no-bundles default.
type noopBundle struct{}

func (noopBundle) DaemonPath(string) string         { return "" }
func (noopBundle) AccelBinPath(string) string       { return "" }
func (noopBundle) StrongswanBinPath(string) string  { return "" }
func (noopBundle) UsingBundledPppd() bool           { return false }
func (noopBundle) PppdBundledPath() string          { return "" }
func (noopBundle) OpenSSLModulesDir() string        { return "" }
func (noopBundle) LinkPptpCtrl() error              { return nil }
func (noopBundle) DistroUnitExists(string) bool     { return false }
func (noopBundle) UsingBundledIpsec() bool          { return false }
func (noopBundle) HasStrongswanBundle() bool        { return false }
func (noopBundle) StrongswanBundleRoot() string     { return "" }
func (noopBundle) LibreswanBundleRoot() string      { return "" }
func (noopBundle) IpsecBundledPath() string         { return "" }
func (noopBundle) PlutoBundledPath() string         { return "" }
func (noopBundle) LibreswanNssDir() string          { return "" }
func (noopBundle) LibreswanBundleReady() bool       { return false }
func (noopBundle) ExtractLibreswanBundle() error    { return nil }
func (noopBundle) StrongswanBundleReady() bool      { return false }
func (noopBundle) ExtractStrongswanBundle() error   { return nil }
func (noopBundle) LinkStrongswanIpsecDir() error    { return nil }
func (noopBundle) StrongswanDefaultConfDir() string { return "" }

// The active provider always carries the legacy-layout fallback (see
// legacybundle.go): the real bundle answers first, then the previous panel
// generation's locations, then distro PATH.
var (
	bundleMu sync.Mutex
	bundle   BundleProvider = wrapLegacy(noopBundle{})
)

// SetBundleProvider installs the daemon-bundle layer. Call once at startup,
// before any Init* provisioning runs. The provider is chained behind the
// legacy-layout fallback, so a real bundle simply wins over the adopted
// previous-generation daemons wherever it has an answer.
func SetBundleProvider(b BundleProvider) {
	bundleMu.Lock()
	defer bundleMu.Unlock()
	if b != nil {
		bundle = wrapLegacy(b)
	}
}

func currentBundle() BundleProvider {
	bundleMu.Lock()
	defer bundleMu.Unlock()
	return bundle
}

// Exported wrappers the protocol-service packages call. vpn-ui kept daemonBin /
// pppdEnv / pptpdArgs / linkPptpCtrl in the same package as its services; here
// they live in procmgr and are re-exported for the per-protocol packages
// (pptp/l2tp waves). DaemonBin/MigrateFromSystemd sit next to ProcManager.
func PppdEnv() []string   { return pppdEnv() }
func PptpdArgs() []string { return pptpdArgs() }
func LinkPptpCtrl()       { linkPptpCtrl() }

// Bundles returns the active BundleProvider — the seam that replaces vpn-ui's
// direct backend.* reads (IpsecBundled, StrongswanBinPath, bundle roots, …) in
// the protocol waves.
func Bundles() BundleProvider { return currentBundle() }

// InstalledCoresFunc reports the cores this host has provisioned (same seam as
// manifest.InstalledCoresFunc). The orphan-reap in migrateFromSystemd only runs
// for cores this host actually installed.
//
// TODO(core wave): wire to the core catalog's provisioned-protocol set.
var InstalledCoresFunc func() map[string]bool

// daemonBin resolves a bundled daemon (preferred) or a host binary from PATH.
func daemonBin(name string) string {
	b := currentBundle()
	if p := b.DaemonPath(name); p != "" {
		return p
	}
	// accel-ppp (SSTP) ships as a relocatable bundle TREE rooted at a fixed path,
	// not a flat BinDir binary, so its launchers (accel-pppd/accel-cmd) resolve
	// here rather than via DaemonPath.
	if p := b.AccelBinPath(name); p != "" {
		return p
	}
	// strongSwan (IKEv2) also ships as a relocatable bundle TREE, so charon/swanctl/pki
	// resolve to their launcher wrappers here rather than via DaemonPath.
	if p := b.StrongswanBinPath(name); p != "" {
		return p
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return name
}

// pppdEnv returns the environment a pppd-based daemon (xl2tpd/pptpd) needs so
// OpenSSL finds the bundled legacy provider for MS-CHAP/MPPE. Empty for a system
// pppd (whose OpenSSL providers differ and must not be overridden).
func pppdEnv() []string {
	b := currentBundle()
	if b.UsingBundledPppd() {
		return []string{"OPENSSL_MODULES=" + b.OpenSSLModulesDir()}
	}
	return nil
}

// pptpdArgs returns pptpd's launch args: foreground, plus the bundled pppd when
// the bundle is in use.
func pptpdArgs() []string {
	b := currentBundle()
	args := []string{"--fg"}
	if b.UsingBundledPppd() {
		args = append(args, "--ppp", b.PppdBundledPath())
	}
	return args
}

// linkPptpCtrl ensures pptpd can exec the bundled pptpctrl from its compiled
// path. Previously done while writing the systemd unit; still required now that
// pptpd runs as a child process.
func linkPptpCtrl() {
	if err := currentBundle().LinkPptpCtrl(); err != nil {
		log.Warning("PPTP: failed to link pptpctrl:", err)
	}
}

// commandExists reports whether name resolves on PATH.
// (vpn-ui core.go:commandExists — folded in.)
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// The process manager proper: each managed process
//   - captures stdout+stderr into a bounded ring buffer for the "Logs" viewer,
//   - is auto-restarted if it exits unexpectedly (mirrors systemd Restart=on-failure),
//   - dies with the panel (StopAll on shutdown), and its whole process group is
//     signalled so pppd children spawned by xl2tpd/pptpd are reaped too.

const procLogMaxLines = 800

// procLog is a bounded in-memory ring buffer of a daemon's recent output.
type procLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *procLog) Write(p []byte) (int, error) {
	// Stamp each captured line so the Logs viewer shows when output arrived
	// (daemon stdout/stderr has no timestamp of its own). Matches the panel
	// logger's time format for consistency across cores.
	ts := time.Now().Format("2006/01/02 15:04:05")
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ln := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if ln == "" {
			continue
		}
		l.lines = append(l.lines, ts+" "+ln)
	}
	if over := len(l.lines) - procLogMaxLines; over > 0 {
		l.lines = l.lines[over:]
	}
	return len(p), nil
}

func (l *procLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func (l *procLog) add(line string) { _, _ = l.Write([]byte(line + "\n")) }

// managedProc is one supervised child daemon.
type managedProc struct {
	name string
	log  *procLog

	mu      sync.Mutex
	bin     string
	args    []string
	env     []string
	dir     string
	cmd     *exec.Cmd
	stopped bool // Stop() called → suppress auto-restart
	gen     int  // bumped on every (re)start/stop; supervisors compare against it
}

// ProcManager supervises the bundled VPN daemons as child processes.
type ProcManager struct {
	mu    sync.Mutex
	procs map[string]*managedProc
}

var procMgr = &ProcManager{procs: map[string]*managedProc{}}

// GetProcManager returns the shared process manager.
func GetProcManager() *ProcManager { return procMgr }

func (m *ProcManager) get(name string) *managedProc {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.procs[name]
}

// Start (re)launches the named daemon with the given command, replacing any
// running instance. Output is captured to the daemon's log ring buffer.
func (m *ProcManager) Start(name, bin string, args, env []string, dir string) error {
	m.mu.Lock()
	p := m.procs[name]
	if p == nil {
		p = &managedProc{name: name, log: &procLog{}}
		m.procs[name] = p
	}
	m.mu.Unlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	// Supersede any current instance/supervisor and stop it.
	p.gen++
	old := p.cmd
	p.terminateLocked()
	// Wait for the old instance to actually exit before launching the replacement.
	// terminateLocked only *signals* it; relaunching immediately races the dying
	// process for its listening port. Single-port daemons (ocserv binds one TCP+UDP
	// port) then fail the new instance with "bind: Address in use" → exit 1 → a 5s
	// procmgr restart window during which every client connection is refused.
	if old != nil && old.Process != nil {
		waitProcessExit(old.Process.Pid)
	}
	p.bin, p.args, p.env, p.dir = bin, args, env, dir
	p.stopped = false
	return p.launchLocked()
}

// waitProcessExit blocks until pid has exited — and thus released its ports —
// escalating a graceful SIGTERM to SIGKILL if ignored. Bounded (~3s) so a wedged
// process can't stall a restart forever. The old instance's supervisor reaps it
// via cmd.Wait() concurrently (outside p.mu), so Kill(pid,0) flips to ESRCH once
// it's gone.
func waitProcessExit(pid int) {
	for i := 0; i < 60; i++ { // up to ~3s (60 × 50ms)
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return
		}
		if i == 20 { // ~1s in and still alive → force it
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// launchLocked spawns the process and its supervisor goroutine (p.mu held).
func (p *managedProc) launchLocked() error {
	// A supervised daemon lives until Stop kills it, so its context never
	// cancels — CommandContext here only satisfies the context-carrying rule.
	cmd := exec.CommandContext(context.Background(), p.bin, p.args...)
	cmd.Dir = p.dir
	if len(p.env) > 0 {
		cmd.Env = append(os.Environ(), p.env...)
	}
	cmd.Stdout = p.log
	cmd.Stderr = p.log
	// Own process group so we can signal pppd/helper children too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		p.log.add("[procmgr] failed to start " + p.bin + ": " + err.Error())
		return err
	}
	p.cmd = cmd
	p.log.add("[procmgr] started: " + p.bin + " " + strings.Join(p.args, " "))
	gen := p.gen
	go p.supervise(cmd, gen)
	return nil
}

// supervise waits for the process; if it exits without an explicit Stop and is
// still the current generation, it is restarted after a short delay.
func (p *managedProc) supervise(cmd *exec.Cmd, gen int) {
	waitErr := cmd.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()
	if gen != p.gen || p.stopped {
		return // superseded or intentionally stopped
	}
	msg := "exited cleanly"
	if waitErr != nil {
		msg = "exited: " + waitErr.Error()
	}
	log.Warningf("procmgr: %s %s — restarting in 5s", p.name, msg)
	p.log.add("[procmgr] " + msg + " — restarting in 5s")
	restartGen := p.gen
	go func() {
		time.Sleep(5 * time.Second)
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.stopped || p.gen != restartGen {
			return
		}
		p.gen++
		// Reap the crashed process's orphaned group (e.g. xl2tpd/pptpd's pppd children,
		// which survive the parent's death and would otherwise wedge a fresh daemon —
		// the "says running but not working" state that only a manual restart cleared).
		// Start() does this before every launch; the auto-restart must too.
		p.terminateLocked()
		_ = p.launchLocked()
	}()
}

// terminateLocked signals the current process group with SIGTERM (p.mu held).
func (p *managedProc) terminateLocked() {
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	pid := p.cmd.Process.Pid
	// Negative pid → whole process group (reaps pppd children). Fall back to the
	// bare process if the group signal fails.
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
	}
}

// Stop terminates the named daemon and disables auto-restart.
//
// It WAITS for the process to actually go, escalating to SIGKILL, rather than
// signalling and returning. terminateLocked only sends SIGTERM, and a daemon that is
// mid-retry can sit on it: a pppd dialling with `persist` outlived Stop by twelve
// minutes on a failed SSTP dial, respawning its pty child the whole time and taking
// its netdev up and down, while the driver's Down had already deleted every file it
// wrote. Nothing was left holding a reference to it, so only a kill -9 by hand or a
// reboot cleared it.
//
// Bounded at ~3s by waitProcessExit, which is the same escalation Start already
// performs before relaunching, so a wedged daemon cannot stall a teardown either.
func (m *ProcManager) Stop(name string) error {
	p := m.get(name)
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopped = true
	p.gen++
	var pid int
	if p.cmd != nil && p.cmd.Process != nil {
		pid = p.cmd.Process.Pid
	}
	p.terminateLocked()
	if pid > 0 {
		waitProcessExit(pid)
	}
	return nil
}

// StopByPrefix stops every managed daemon whose name starts with prefix
// (e.g. "openvpn-server-" for all OpenVPN instances).
func (m *ProcManager) StopByPrefix(prefix string) {
	for _, name := range m.namesWithPrefix(prefix) {
		_ = m.Stop(name)
	}
}

func (m *ProcManager) namesWithPrefix(prefix string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var names []string
	for n := range m.procs {
		if strings.HasPrefix(n, prefix) {
			names = append(names, n)
		}
	}
	return names
}

// IsRunning reports whether the named daemon is currently up.
func (m *ProcManager) IsRunning(name string) bool {
	p := m.get(name)
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.stopped && p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil
}

// AnyRunningWithPrefix reports whether any managed daemon with the given name
// prefix is up (e.g. any OpenVPN transport for an inbound).
func (m *ProcManager) AnyRunningWithPrefix(prefix string) bool {
	for _, n := range m.namesWithPrefix(prefix) {
		if m.IsRunning(n) {
			return true
		}
	}
	return false
}

// Logs returns the captured output of the named daemon (most recent lines).
func (m *ProcManager) Logs(name string) string {
	p := m.get(name)
	if p == nil {
		return ""
	}
	return p.log.String()
}

// LogsByPrefix concatenates the logs of all daemons matching the prefix, each
// section headed by its name. Used for cores that run several processes
// (OpenVPN: one per inbound/transport).
func (m *ProcManager) LogsByPrefix(prefix string) string {
	names := m.namesWithPrefix(prefix)
	if len(names) == 0 {
		return ""
	}
	var b strings.Builder
	for i, n := range names {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString("===== " + n + " =====\n")
		b.WriteString(m.Logs(n))
		b.WriteString("\n")
	}
	return b.String()
}

// alive reports whether the named process is actually still running (ignoring
// the stopped flag).
func (m *ProcManager) alive(name string) bool {
	p := m.get(name)
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil
}

// kill SIGKILLs the named process group (last resort for a straggler).
func (m *ProcManager) kill(name string) {
	p := m.get(name)
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil && p.cmd.Process != nil {
		pid := p.cmd.Process.Pid
		if syscall.Kill(-pid, syscall.SIGKILL) != nil {
			_ = p.cmd.Process.Kill()
		}
	}
}

// StopAll terminates every managed daemon and waits for them to exit (panel
// shutdown). Daemons that don't exit within the grace period are SIGKILLed, so
// nothing is left holding a port for the next panel start.
func (m *ProcManager) StopAll() {
	m.mu.Lock()
	names := make([]string, 0, len(m.procs))
	for n := range m.procs {
		names = append(names, n)
	}
	m.mu.Unlock()

	for _, n := range names {
		_ = m.Stop(n) // SIGTERM
	}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		anyAlive := false
		for _, n := range names {
			if m.alive(n) {
				anyAlive = true
				break
			}
		}
		if !anyAlive {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	for _, n := range names {
		if m.alive(n) {
			m.kill(n)
		}
	}
}

// bundledDaemonBin resolves a daemon to a path INSIDE one of our bundles, or ""
// when this build has no bundle for it. daemonBin falls back to PATH, which is
// right for launching but catastrophic for `pkill -f`: it would match the host's
// own daemon. Two callers must never confuse the two, so they are two functions.
func bundledDaemonBin(name string) string {
	b := currentBundle()
	if p := b.DaemonPath(name); p != "" {
		return p
	}
	if p := b.AccelBinPath(name); p != "" {
		return p
	}
	if p := b.StrongswanBinPath(name); p != "" {
		return p
	}
	return ""
}

// BundledDaemonBin resolves a daemon to a path INSIDE one of our bundles, or ""
// when this build has no bundle for it. The "is the binary shipped at all"
// check (vpn-ui's backend.DaemonPath != "") — never to launch or pkill.
// (mtproto wave addition; DaemonBin/MigrateFromSystemd/NamesWithPrefix live in
// proto_exports.go.)
func BundledDaemonBin(name string) string { return bundledDaemonBin(name) }

// unitEnabled / unitActive read a systemd unit's two independent states. Both are
// recorded before we disable a unit, because they come apart: a distro xl2tpd can
// be enabled but stopped, and restoring only "active" would lose the boot setting.
func unitEnabled(unit string) bool {
	out, _ := exec.CommandContext(context.Background(), "systemctl", "is-enabled", unit).Output()
	return strings.TrimSpace(string(out)) == "enabled"
}

func unitActive(unit string) bool {
	out, _ := exec.CommandContext(context.Background(), "systemctl", "is-active", unit).Output()
	return strings.TrimSpace(string(out)) == "active"
}

// disableUnitRecording stops and disables a systemd unit, having first written
// down whether it was enabled and whether it was running.
//
// The unit is only recorded when the distro provides it (DistroUnitExists) or it
// is currently in use: one of OUR generated units in /etc/systemd/system carries
// no operator intent worth restoring, and the file is deleted a few lines later
// anyway.
func disableUnitRecording(unit, core string) {
	name := unit
	if !strings.Contains(name, ".") {
		name += ".service"
	}
	enabled, active := unitEnabled(name), unitActive(name)
	if enabled || active || currentBundle().DistroUnitExists(name) {
		manifest.RecordUnit(name, core, enabled, active)
	}
	_ = exec.CommandContext(context.Background(), "systemctl", "disable", "--now", name).Run()
}

// migrateOnce tears down the previous systemd-based design (bundled units +
// running instances) so the panel can own the daemons as child processes.
// Idempotent and safe to call every startup: once the units are gone it is a
// no-op.
var migrateOnce sync.Once

func migrateFromSystemd() {
	migrateOnce.Do(func() {
		if !commandExists("systemctl") {
			return
		}
		// EVERY disable below is now SCOPED and RECORDED, and both halves matter.
		//
		// These are not only OUR units. openvpn-server@, xl2tpd, pptpd and ipsec are
		// the distro's own units on a host that had those daemons before the panel,
		// and this ran unconditionally on every provisioning pass. A host that
		// installed nothing but WireGuard still had its working xl2tpd stopped and
		// disabled, and nothing ever gave it back.
		//
		// The scope is "have we got a daemon of our own to run in its place", read
		// off the extracted binary.
		//
		// disableUnitRecording captures the unit's enabled/active state first, and
		// the core uninstall replays it.
		if bundledDaemonBin("openvpn") != "" {
			// Stop + disable OpenVPN per-inbound instances.
			out, _ := exec.CommandContext(context.Background(), "systemctl", "list-units", "--all", "--no-legend", "openvpn-server@*").Output()
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Fields(strings.TrimLeft(line, "●* "))
				if len(fields) > 0 && strings.HasPrefix(fields[0], "openvpn-server@") {
					disableUnitRecording(fields[0], "openvpn")
				}
			}
		}
		// Stop + disable the single-instance daemons.
		if bundledDaemonBin("xl2tpd") != "" {
			disableUnitRecording("xl2tpd", "l2tp")
		}
		if bundledDaemonBin("pptpd") != "" {
			disableUnitRecording("pptpd", "pptp")
		}
		// When we run our own bundled pluto, the host ipsec.service must not also be
		// running — it would hold UDP 500/4500 and conflict with the bundled daemon.
		if currentBundle().UsingBundledIpsec() {
			disableUnitRecording("ipsec", "l2tp")
		}
		// Remove the unit files the old design generated.
		for _, f := range []string{
			"/etc/systemd/system/openvpn-server@.service",
			"/etc/systemd/system/xl2tpd.service",
			"/etc/systemd/system/pptpd.service",
		} {
			_ = os.Remove(f)
		}
		_ = exec.CommandContext(context.Background(), "systemctl", "daemon-reload").Run()
		log.Info("procmgr: migrated VPN daemons off systemd (now child processes)")

		// Kill orphaned bundled daemons left by a previous panel that was killed
		// without a clean shutdown (SIGKILL/crash) — they would hold the ports the
		// child processes need. Safe: procMgr has spawned nothing yet at this
		// point, so only pre-existing processes match.
		//
		// "Pre-existing" is exactly the problem, though, so the reap is scoped twice
		// over. It only runs for a core this host has actually installed, and it only
		// matches a BUNDLED binary path, never a PATH-resolved one: with a system
		// daemon and no bundle, daemonBin("openvpn") resolves to /usr/sbin/openvpn and
		// `pkill -f /usr/sbin/openvpn` killed the operator's own running OpenVPN on
		// every panel start.
		if commandExists("pkill") {
			installedCore := map[string]bool{}
			if InstalledCoresFunc != nil {
				installedCore = InstalledCoresFunc()
			}
			// accel-pppd (SSTP) runs through the bundle's musl loader-wrapper, so its
			// cmdline contains ".../sbin/accel-pppd.bin"; a `-f` match on the resolved
			// launcher path (".../sbin/accel-pppd") is a substring of that and reaps a
			// stale orphan from a crashed panel. accel-pppd does NOT retitle itself
			// (unlike ocserv), so it does not need the exact-name `-x` pass below.
			for _, d := range []struct{ daemon, core string }{
				{"openvpn", "openvpn"}, {"xl2tpd", "l2tp"}, {"pptpd", "pptp"}, {"accel-pppd", "sstp"},
			} {
				if !installedCore[d.core] {
					continue
				}
				bin := bundledDaemonBin(d.daemon)
				if bin == "" {
					continue // no bundle: whatever is running is the host's, not ours
				}
				_ = exec.CommandContext(context.Background(), "pkill", "-KILL", "-f", bin).Run()
			}
			// Orphaned bundled pluto from a crashed panel (holds UDP 500/4500).
			b := currentBundle()
			if b.UsingBundledIpsec() && b.LibreswanBundleRoot() != "" {
				_ = exec.CommandContext(context.Background(), "pkill", "-KILL", "-f", b.LibreswanBundleRoot()+"/libexec/ipsec/pluto.bin").Run()
			}
			// Orphaned bundled charon (IKEv2) from a crashed panel — it also holds UDP
			// 500/4500. charon runs via the musl loader wrapper, so its cmdline contains
			// the absolute charon.bin path; match on that.
			if b.HasStrongswanBundle() && b.StrongswanBundleRoot() != "" {
				_ = exec.CommandContext(context.Background(), "pkill", "-KILL", "-f", b.StrongswanBundleRoot()+"/libexec/ipsec/charon.bin").Run()
			}
			// Orphaned ocserv from a crashed/killed previous panel. ocserv RENAMES its
			// processes to ocserv-main/-sm/-worker, so `pkill -f <exec path>` can never
			// match them — kill by EXACT process name instead (-x). An exact-name kill
			// cannot tell our orphan from a distro ocserv the operator runs under
			// systemd, and it killed that too, on every panel start. Gated on the
			// OpenConnect core being installed, which is the only state in which any
			// ocserv on this box can plausibly be ours.
			if installedCore["openconnect"] {
				for _, comm := range []string{"ocserv-main", "ocserv-sm", "ocserv-worker", "ocserv"} {
					_ = exec.CommandContext(context.Background(), "pkill", "-KILL", "-x", comm).Run()
				}
			}
		}
	})
}
