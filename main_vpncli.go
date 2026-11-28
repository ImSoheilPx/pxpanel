package main

// The VPN management CLI verbs ported from vpn-ui main.go: `info`, `ctl` (the
// control-socket client; the server half is main_ctlserver.go), the `cert
// -selfsign` helper, the legacy-settings lift behind `migrate`, and the
// OpenVPN hook entry points (openvpn-auth / openvpn-connect /
// openvpn-disconnect / openvpn-evict) whose implementations live in
// internal/vpn/openvpn/lease.go and are invoked by the generated server
// configs as `<binary> openvpn-auth <inbound_id> <cred_file>` etc.

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/config"
	"github.com/ImSoheilPx/pxpanel/internal/database"
	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/logger"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/cert"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/coresettings"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/mtproto"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/openvpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"
	"github.com/ImSoheilPx/pxpanel/internal/web/service"
	"github.com/ImSoheilPx/pxpanel/internal/web/service/panel"
	"github.com/ImSoheilPx/pxpanel/internal/xray"

	"github.com/op/go-logging"
)

// ---------------------------------------------------------------------------
// init shared by the verbs that reach the database or the vpn.DB seams
// ---------------------------------------------------------------------------

// initVpnCliDB opens the database and hands the handle to the vpn subtree, the
// same wiring runWebServer does. The CLI verbs run before/without the web
// server, and every reader below (SettingService, UserService, the mtproto
// lift's vpn.DB, the OpenVPN hooks' vpn.RadiusSecret) is DB-backed: calling one
// before InitDB would dereference a nil handle.
func initVpnCliDB() error {
	if err := database.InitDB(config.GetDBPath()); err != nil {
		return err
	}
	vpn.SetDB(database.GetDB)
	return nil
}

// ---------------------------------------------------------------------------
// info
// ---------------------------------------------------------------------------

// panelInfo is the panel's login/access + service + core state, as printed by
// `pxpanel info`. The JSON field names are a CONTRACT with scripts (what
// --json emits and what --get <field> looks up): keep these names stable; add,
// don't rename (vpn-ui panelInfo's rule).
type panelInfo struct {
	Version              string `json:"version"`
	Username             string `json:"username"`
	Port                 int    `json:"port"`
	WebBasePath          string `json:"webBasePath"`
	ListenIP             string `json:"listenIP"`
	SSL                  bool   `json:"ssl"`
	CertFile             string `json:"certFile"`
	KeyFile              string `json:"keyFile"`
	HasDefaultCredential bool   `json:"hasDefaultCredential"`
	IP                   string `json:"ip"`
	URL                  string `json:"url"`

	SystemdAvailable bool   `json:"systemdAvailable"`
	SystemdUnit      string `json:"systemdUnit"`
	SystemdInstalled bool   `json:"systemdInstalled"`
	SystemdEnabled   bool   `json:"systemdEnabled"`
	SystemdActive    bool   `json:"systemdActive"`
	SystemdState     string `json:"systemdState"` // no-systemd | not-installed | active | inactive

	// PanelRunning is the only trustworthy answer to "is the panel up?": it is
	// true when a live panel answers on the control socket. The systemd fields
	// cannot answer it, because the panel may be running OUTSIDE systemd, in
	// which case SystemdActive is false while the panel serves happily.
	PanelRunning bool   `json:"panelRunning"`
	SocketPath   string `json:"socketPath"`
	ExePath      string `json:"exePath"`

	// XrayAccessLog is the file the panel's own Xray Logs page reads
	// (xray.GetAccessLogPath). Empty means the access log is disabled: the
	// shipped default is literally "none", normalized here so the one rule a
	// consumer needs is "empty means no access log".
	XrayAccessLog string `json:"xrayAccessLog"`

	// Protocol cores + host prerequisites (target addition over vpn-ui's
	// panelInfo: the Core Settings service exposes the same tables the
	// dashboard's Core Settings page renders).
	Cores  []coresettings.CoreStatus  `json:"cores,omitempty"`
	System *coresettings.SystemStatus `json:"system,omitempty"`
}

// collectPanelInfo reads the panel's current settings and service state. The
// DB must already be open (see runInfo).
//
// resolvePublicIP gates the IP/URL lookup because it is an HTTP round-trip to
// an external service with a 3s timeout PER provider: on a box with no
// outbound internet every field read would stall for many seconds. Callers
// that only want, say, systemdUnit pass false.
func collectPanelInfo(resolvePublicIP bool) panelInfo {
	settingService := service.SettingService{}
	userService := panel.UserService{}

	info := panelInfo{Version: config.GetPanelVersion()}

	info.Port, _ = settingService.GetPort()
	info.WebBasePath, _ = settingService.GetBasePath()
	if info.WebBasePath == "" {
		info.WebBasePath = "/"
	}
	info.ListenIP, _ = settingService.GetListen()
	info.CertFile, _ = settingService.GetCertFile()
	info.KeyFile, _ = settingService.GetKeyFile()
	// The web server serves HTTPS only with BOTH files set, so report SSL the
	// same way it decides, not on the cert alone.
	info.SSL = info.CertFile != "" && info.KeyFile != ""

	if u, err := userService.GetFirstUser(); err == nil && u != nil {
		info.Username = u.Username
		info.HasDefaultCredential, _ = userService.HasDefaultCredential()
	}

	if resolvePublicIP {
		ip := publicIPv4()
		scheme := "http"
		host := ip
		if info.SSL {
			scheme = "https"
			// The panel serves a cert whose name is the DOMAIN (Let's Encrypt)
			// or the server IP (self-signed); a browser sent to https://<IP>
			// when the cert names only a domain fails the name check. Fall
			// back to the detected IP when the cert has no usable name.
			if h := certHost(info.CertFile); h != "" {
				host = h
			}
		}
		// JoinHostPort, not "%s:%d": an IPv6 host has to be bracketed or the
		// URL is malformed.
		info.IP = ip
		info.URL = fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(host, strconv.Itoa(info.Port)), info.WebBasePath)
	}

	// Never hardcode "pxpanel": the unit name is operator-configurable, and
	// ServiceState resolves it the same way the panel's own Settings page does.
	sd := procmgr.SystemdService{}
	st := sd.ServiceState()
	info.SystemdAvailable = st.Available
	info.SystemdUnit = st.Name
	info.SystemdInstalled = st.Installed
	info.SystemdEnabled = st.Enabled
	info.SystemdActive = st.Active
	switch {
	case !st.Available:
		info.SystemdState = "no-systemd"
	case !st.Installed:
		info.SystemdState = "not-installed"
	case st.Active:
		info.SystemdState = "active"
	default:
		info.SystemdState = "inactive"
	}

	info.SocketPath = ctlSocketPath()
	info.PanelRunning = ctlPing()
	info.ExePath, _ = os.Executable()

	if p, err := xray.GetAccessLogPath(); err == nil && p != "none" && p != "" {
		info.XrayAccessLog = p
	}

	// Protocol cores + host prerequisites. Zero-value CoreService: the reads
	// are stateless (vpn-ui CoreService's own contract).
	var coreService coresettings.CoreService
	info.Cores = coreService.GetCoresStatus()
	sys := coreService.GetSystemStatus()
	info.System = &sys

	return info
}

// runInfo implements `pxpanel info [--json|--get <field>]`: the panel's login,
// access URL, service state and core status in one place (vpn-ui runInfo).
//
// It opens the DB ITSELF. Every reader below is DB-backed, and calling one
// before InitDB would dereference a nil handle.
func runInfo(args []string) {
	// Services here log through the logger package (xray.GetAccessLogPath
	// warns when the Xray config is unreadable), which needs a live logger.
	logger.InitLogger(logging.INFO)
	if err := initVpnCliDB(); err != nil {
		fmt.Fprintln(os.Stderr, "Database initialization failed:", err)
		os.Exit(1)
	}

	asJSON, field := false, ""
	for i := 0; i < len(args); i++ {
		key := strings.TrimPrefix(strings.TrimPrefix(args[i], "-"), "-")
		if eq := strings.IndexByte(key, '='); eq >= 0 {
			if key[:eq] == "get" {
				field = key[eq+1:]
				continue
			}
		}
		switch key {
		case "json":
			asJSON = true
		case "get":
			if i+1 < len(args) {
				i++
				field = args[i]
			}
		default:
			fmt.Fprintf(os.Stderr, "unknown argument for info: %q (use --json or --get <field>)\n", args[i])
			os.Exit(2)
		}
	}

	if field != "" {
		emitInfoField(field)
		return
	}
	info := collectPanelInfo(true)
	if asJSON {
		out, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "encoding info failed:", err)
			os.Exit(1)
		}
		fmt.Println(string(out))
		return
	}
	printPanelInfo(info)
}

// emitInfoField prints ONE field's raw value, so a shell can branch on it
// without jq and without ever parsing prose. The lookup goes through the
// marshalled JSON rather than a hand-written switch, which is what guarantees
// --get accepts exactly the keys --json emits, forever (vpn-ui emitInfoField).
func emitInfoField(field string) {
	// Only the two fields that need it pay for the public-IP lookup.
	info := collectPanelInfo(field == "ip" || field == "url")
	raw, err := json.Marshal(info)
	if err != nil {
		fmt.Fprintln(os.Stderr, "encoding info failed:", err)
		os.Exit(1)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber() // keep Port an integer instead of float64's "8443.000000"
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		fmt.Fprintln(os.Stderr, "decoding info failed:", err)
		os.Exit(1)
	}
	v, ok := m[field]
	if !ok {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(os.Stderr, "unknown info field %q\nknown fields: %s\n", field, strings.Join(keys, ", "))
		os.Exit(1)
	}
	fmt.Println(v)
}

// printPanelInfo renders the human view.
func printPanelInfo(info panelInfo) {
	fmt.Println("Panel:")
	fmt.Printf("  Version:  %s\n", info.Version)
	fmt.Printf("  Username: %s\n", info.Username)
	fmt.Printf("  Port:     %d\n", info.Port)
	fmt.Printf("  WebPath:  %s\n", info.WebBasePath)
	listen := info.ListenIP
	if listen == "" {
		listen = "(all interfaces)"
	}
	fmt.Printf("  Listen:   %s\n", listen)
	if info.SSL {
		fmt.Println("  SSL:      on")
		fmt.Printf("  Cert:     %s\n", info.CertFile)
		fmt.Printf("  Key:      %s\n", info.KeyFile)
	} else {
		fmt.Println("  SSL:      off (the panel is served over plain HTTP)")
	}
	fmt.Printf("  IP:       %s\n", info.IP)
	fmt.Printf("  URL:      %s\n", info.URL)
	if info.IP == "N/A" {
		fmt.Println("  (could not detect public IP, substitute the server's address in the URL)")
	}
	if info.HasDefaultCredential {
		fmt.Println("  WARNING:  the default panel credential is still in use. Change it.")
	}

	fmt.Println("Service:")
	fmt.Printf("  Unit:     %s (%s)\n", info.SystemdUnit, info.SystemdState)
	if info.SystemdAvailable && info.SystemdInstalled {
		fmt.Printf("  OnBoot:   %v\n", info.SystemdEnabled)
	}
	if info.PanelRunning {
		fmt.Println("  Panel:    running (its control socket answers)")
	} else {
		fmt.Printf("  Panel:    not running (no answer on %s)\n", info.SocketPath)
	}
	if info.XrayAccessLog != "" {
		fmt.Printf("  Xray log: %s\n", info.XrayAccessLog)
	}

	if len(info.Cores) > 0 {
		fmt.Println("Cores:")
		printCoreStatus(info.Cores)
	}
	if info.System != nil {
		fmt.Printf("System:   ipForward=%v nftables=%v iproute=%v modulesOk=%v\n",
			info.System.IpForward, info.System.Nftables, info.System.Iproute, info.System.ModulesOK)
	}
}

// ---------------------------------------------------------------------------
// ctl (client half)
// ---------------------------------------------------------------------------

// ctlDial connects to the LIVE panel's control socket.
func ctlDial() (net.Conn, error) {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	return dialer.DialContext(context.Background(), "unix", ctlSocketPath())
}

// ctlSend sends one command over conn and returns the panel's reply.
func ctlSend(conn net.Conn, cmd string) (ctlControlResponse, error) {
	var resp ctlControlResponse
	req, err := json.Marshal(ctlControlRequest{Cmd: cmd})
	if err != nil {
		return resp, err
	}
	if _, err := conn.Write(append(req, '\n')); err != nil {
		return resp, err
	}
	// No read deadline: cores.restart-all restarts every core and legitimately
	// takes tens of seconds. The panel closes the connection if it dies, which
	// unblocks us.
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return resp, err
	}
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return resp, fmt.Errorf("malformed reply from the panel: %w", jerr)
	}
	return resp, nil
}

// ctlPing reports whether a LIVE panel answers on the control socket. This is
// what lets `info` tell "the panel is up" from "the unit is active": two
// different things on a box where the panel was started by hand.
func ctlPing() bool {
	conn, err := ctlDial()
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	resp, err := ctlSend(conn, "ping")
	return err == nil && resp.OK
}

// runCtl implements `pxpanel ctl <cmd> [--json]`: hand one command to the
// RUNNING panel over its control socket and print the reply.
//
// When the socket is absent or refuses, this reports that the panel is not
// running and exits non-zero. It NEVER falls back to doing the work locally,
// and that is the entire point: Xray and the daemons are children of the live
// panel tracked by its in-process state, so a local fallback would report a
// running Xray as stopped and "restart" it into a second, port-colliding copy.
func runCtl(args []string) {
	asJSON := false
	var cmd string
	for _, a := range args {
		if strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-") == "json" {
			asJSON = true
			continue
		}
		if cmd == "" {
			cmd = a
			continue
		}
		fmt.Fprintf(os.Stderr, "unexpected argument: %q\n", a)
		os.Exit(2)
	}
	if cmd == "" {
		fmt.Fprintf(os.Stderr, "usage: pxpanel ctl <command> [--json]\ncommands: %s\n", ctlCommandList())
		os.Exit(2)
	}

	conn, err := ctlDial()
	if err != nil {
		fmt.Fprintf(os.Stderr, "the pxpanel panel is not running: no answer on %s (%v)\n",
			ctlSocketPath(), err)
		fmt.Fprintln(os.Stderr, "Xray and the VPN daemons are children of the running panel, so they can only")
		fmt.Fprintln(os.Stderr, "be controlled through it. Start the panel first, then retry.")
		os.Exit(1)
	}
	defer conn.Close()

	resp, err := ctlSend(conn, cmd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "control socket error:", err)
		os.Exit(1)
	}
	if asJSON {
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
	} else if !resp.OK {
		fmt.Fprintln(os.Stderr, "error:", resp.Error)
	} else {
		if resp.Msg != "" {
			fmt.Println(resp.Msg)
		}
		printCoreStatus(resp.Cores)
	}
	if !resp.OK {
		os.Exit(1)
	}
}

// printCoreStatus renders `ctl cores.status` as an aligned table.
func printCoreStatus(cores []coresettings.CoreStatus) {
	for _, c := range cores {
		detail := c.Detail
		if detail == "" && c.Inbounds > 0 {
			detail = fmt.Sprintf("%d inbound(s)", c.Inbounds)
		}
		if c.Version != "" {
			detail = strings.TrimSpace(c.Version + " " + detail)
		}
		fmt.Printf("  %-12s %-14s %s\n", c.Name, c.State, detail)
	}
}

// ---------------------------------------------------------------------------
// cert -selfsign
// ---------------------------------------------------------------------------

// generateSelfSignedPanelCert generates a self-signed TLS certificate for the
// panel, writes it into the config dir (+ /cert), and points the panel's
// webCertFile/webKeyFile at it so the web server serves HTTPS (vpn-ui cert
// -selfsign). The cert carries the server's public IP as a SAN; browsers still
// warn on the self-signed issuer, which is expected.
func generateSelfSignedPanelCert() {
	dir := filepath.Join(config.GetDBFolderPath(), "cert")
	ip := publicIPv4()
	certPath, keyPath, err := cert.GeneratePanelSelfSignedCert(dir, ip)
	if err != nil {
		fmt.Fprintln(os.Stderr, "self-signed cert generation failed:", err)
		os.Exit(1)
	}
	fmt.Printf("Generated self-signed panel certificate:\n  cert: %s\n  key:  %s\n", certPath, keyPath)
	updateCert(certPath, keyPath)
}

// certHost returns the host a browser should use to reach a panel serving
// certFile: the leaf certificate's first routable DNS SAN, else its first
// non-loopback IP SAN, else "" when the file cannot be read or parsed.
// "localhost" and loopback IPs are skipped, so a self-signed panel cert (which
// also carries them for local access) still yields the server's public
// address. It reads the FIRST certificate in the PEM and does not fall back to
// the deprecated CN, which browsers no longer match on (vpn-ui certHost).
func certHost(certFile string) string {
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		return ""
	}
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			return ""
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return ""
		}
		for _, name := range parsed.DNSNames {
			if !strings.EqualFold(name, "localhost") {
				return name
			}
		}
		for _, ip := range parsed.IPAddresses {
			if !ip.IsLoopback() {
				return ip.String()
			}
		}
		return ""
	}
}

// publicIPv4 returns the server's public IPv4 the same way the dashboard's
// status resolves it (same providers, same per-provider timeout), or "N/A".
// Callers that do not display the URL should not call this at all.
func publicIPv4() string {
	// The panel's own publicIPv4Services list (web/service/server.go), minus
	// check-host.net which answers HTML without an Accept header.
	for _, u := range []string{
		"https://api4.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://v4.api.ipinfo.io/ip",
		"https://ipv4.myexternalip.com/raw",
		"https://4.ident.me",
	} {
		if ip := fetchPublicIP(u); ip != "" {
			return ip
		}
	}
	return "N/A"
}

// fetchPublicIP fetches one echo service and returns a parseable IP, or "".
func fetchPublicIP(url string) string {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	ip := strings.TrimSpace(string(body))
	if ip == "" || ip == "N/A" || net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

// ---------------------------------------------------------------------------
// migrate: the legacy-settings lift
// ---------------------------------------------------------------------------

// runVpnSettingsLift walks every inbound and lifts legacy VPN settings onto
// the current shape, the half of vpn-ui's MigrateDB this panel's own
// MigrateDB does not carry:
//
//  1. mtproto.LiftClientSettingsToInbound — the one-shot move of connection
//     modes, FakeTLS domain and device cap off an mtproto inbound's CLIENTS
//     and onto the inbound itself. A restored backup, an imported foreign DB
//     or this verb are the only ways a database arrives ALREADY OLD: the
//     mtproto reader tolerates the old shape but a WRITER through the panel's
//     form does not, it would post back what it read.
//  2. per-inbound defaults lift — defaults.MtprotoSettingsLifter (the same
//     pre-move blob rewriter the add path runs) followed by
//     defaults.FillSettingsDefaults, so an inbound missing whole keys of its
//     protocol's shape (a legacy settings blob predating a protocol wave)
//     gets exactly the defaults the panel's own form would store.
//
// Both passes are idempotent and touch only the inbounds that actually change.
// Validation is deliberately NOT run here: a migration entry point should
// lift, not judge, and the daemon configs tolerate what the lifter produces.
func runVpnSettingsLift() {
	// The CLI path does not run runWebServer's wiring, so the vpn.DB handle
	// the mtproto lift reads and writes through has to be injected here.
	if err := initVpnCliDB(); err != nil {
		fmt.Println("warning: legacy-settings lift skipped, database unavailable:", err)
		return
	}

	// 1. Client → inbound policy lift.
	mt := &mtproto.MtprotoService{}
	if err := mt.LiftClientSettingsToInbound(); err != nil {
		fmt.Println("warning: lifting legacy MTProto client settings failed:", err)
	}

	// 2. Per-inbound defaults lift.
	var inboundService service.InboundService
	inbounds, err := inboundService.GetAllInbounds()
	if err != nil {
		fmt.Println("warning: loading inbounds for the legacy-settings lift failed:", err)
		return
	}
	db := database.GetDB()
	lifted := 0
	for _, ib := range inbounds {
		if ib == nil {
			continue
		}
		settings := ib.Settings
		if defaults.MtprotoSettingsLifter != nil {
			settings = defaults.MtprotoSettingsLifter(ib.Protocol, settings)
		}
		filled, ferr := defaults.FillSettingsDefaults(ib.Protocol, settings)
		if ferr != nil {
			fmt.Printf("warning: lifting settings defaults on inbound %d failed: %v\n", ib.Id, ferr)
			continue
		}
		// FillSettingsDefaults returns the input verbatim when nothing was
		// missing, so this compare skips every already-current inbound.
		if filled == ib.Settings || db == nil {
			continue
		}
		if err := db.Model(model.Inbound{}).Where("id = ?", ib.Id).
			Update("settings", filled).Error; err != nil {
			fmt.Printf("warning: storing lifted settings for inbound %d failed: %v\n", ib.Id, err)
			continue
		}
		lifted++
	}
	if lifted > 0 {
		fmt.Printf("lifted legacy VPN settings on %d inbound(s)\n", lifted)
	}
}

// ---------------------------------------------------------------------------
// OpenVPN hook entry points
// ---------------------------------------------------------------------------

// initVpnHookDB best-effort opens the database and injects the vpn.DB handle,
// so the hook processes' secret reader (vpn.RadiusSecret → the settings table)
// works; on failure the hook keeps running and the reader falls back to the
// legacy /etc/ppp/radius/servers file, exactly as the reader itself documents.
func initVpnHookDB() {
	if err := initVpnCliDB(); err != nil {
		fmt.Fprintln(os.Stderr, "warning: database unavailable, RADIUS secret falls back to /etc/ppp/radius/servers:", err)
	}
}

// runOpenvpnAuth dispatches `pxpanel openvpn-auth <inbound_id> <cred_file>`.
// The verbs read os.Args and exit the process by design (they are entry points
// of OpenVPN's own hook scripts, never library calls — see
// internal/vpn/openvpn/lease.go).
func runOpenvpnAuth() {
	initVpnHookDB()
	openvpn.Auth()
}

// runOpenvpnConnect dispatches `pxpanel openvpn-connect <inbound_id> [session_conf]`.
func runOpenvpnConnect() {
	initVpnHookDB()
	openvpn.Connect()
}

// runOpenvpnDisconnect dispatches `pxpanel openvpn-disconnect <inbound_id>`.
func runOpenvpnDisconnect() {
	initVpnHookDB()
	openvpn.Disconnect()
}

// runOpenvpnEvict dispatches `pxpanel openvpn-evict <id> <proto> <ip> [real-address]`.
// Spawned detached by the connect hook's User Limit eviction; needs no DB.
func runOpenvpnEvict() {
	openvpn.Evict()
}
