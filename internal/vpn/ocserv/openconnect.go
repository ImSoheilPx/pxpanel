// Package ocserv is vpn-ui's OpenConnect service (web/service/openconnect.go)
// ported into pxpanel: the ocserv.conf generator, the per-inbound radcli client
// config that points ocserv at the panel's in-process RADIUS server (auth via
// PAP + reply attributes applied with groupconfig=true, so Framed-IP-Address
// pins every device to its panel-assigned block IP), the self-signed TLS cert
// generator, and the occtl-based session control (User Limit eviction +
// whole-account teardown).
//
// Architecturally ocserv is the closest sibling of OpenVPN (internal/vpn/
// openvpn) — a userspace tun daemon whose clients get a source IP inside a
// per-inbound /24, which the shared nftables TPROXY path redirects into Xray.
// It differs in two ways that make it simpler here: a SINGLE listener carries
// both TLS (TCP) and DTLS (UDP) on one port (no udp/tcp split, no 10.3 mirror),
// and it speaks RADIUS natively via radcli — so authentication, per-account IP
// pinning (Framed-IP-Address), and accounting all go through the panel's
// in-process RADIUS server with no per-connection hook scripts (unlike
// OpenVPN).
//
// PORT ADAPTATIONS vs vpn-ui:
//   - database.GetDB() is reached through the root package's injected handle
//     (vpn.SetDB / vpn.DB); the RADIUS secret falls back through
//     vpn.RadiusSecret() (the settings KV row), replacing SettingService.
//   - The inbound/nft service cross-calls resolve against the internal/vpn
//     foundation (nftables.Service); inboundService is dropped rather than
//     importing internal/web (import cycle).
//   - ownPrepareDir is manifest.PrepareDir; daemonBin/migrateFromSystemd/
//     procMgr come from procmgr; vpnBlock/protocolBase/prefixToMask come from
//     the vpnrange package.
//   - generateRadiusDictionary + probeCmd are carried package-locally
//     (radiusclient.go / this file's probeCmd): vpn-ui had them in
//     web/service/radius.go, which is now the radius foundation package and
//     does not export them. TODO(controllers wave): hoist both into a shared
//     spot when the l2tp/pptp radcli writers land and dedupe.
//   - vpn-ui's User-Limit accept-eviction dispatched killOcservByIP(inboundId,
//     ip) from radius.go; the foundation dispatches vpn.EvictProtocolIP
//     (ip-only). The evictor registered in register.go therefore locates the
//     right ocserv instance by scanning the occtl sockets, instead of being
//     handed the inbound id.
//   - Generated-file banners say pxpanel, not vpn-ui.
//
// TODO(controllers wave): the web handlers (generate-ocserv-cert, ocserv
// on-changed regenerations), InitOcserv wiring at server start, and the 10s
// traffic-job call of KillDisabledSessions hang off internal/web later. The
// vpn-ui OUTBOUND driver (vpnout_openconnect.go — the panel as an OpenConnect
// CLIENT, with its bundled vpnc-script) is NOT ported here: it rides the shared
// vpnout driver framework (vpnoutbound.go/vpnoutcarrier.go), which is its own
// wave.
package ocserv

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/util/json_util"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/log"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/nftables"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/radius"
	vpnrange "github.com/ImSoheilPx/pxpanel/internal/vpn/range"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

// OcservService manages OpenConnect (ocserv) server configuration: TLS certs,
// the ocserv.conf + radcli client config, the daemon child process, and routing.
//
// PORT NOTE: vpn-ui's inboundService/nftService fields were web/service types.
// The nft side is the foundation's stateless *nftables.Service; inboundService
// is dropped (see the package doc). SetRadius keeps the vpn-ui shape so the
// wire-up wave can inject the shared RADIUS service exactly as before.
type OcservService struct {
	nft           *nftables.Service
	radiusService *radius.RadiusService
	radiusSecret  string
}

// ocservSettings is the OpenConnect-specific slice of an inbound's Settings JSON.
type ocservSettings struct {
	Dns1 string `json:"dns1"`
	Dns2 string `json:"dns2"`
	Mtu  int    `json:"mtu"`

	// TLS follows the Xray inbound model: either operator-supplied paths
	// (TlsUseFile) or inline PEM content. "Generate Self-Signed Cert" fills the
	// content fields; "Set Default Cert" copies the panel's own webCertFile/
	// webKeyFile paths (TlsUseFile mode). ocserv reads whichever is active from
	// disk, exactly like the panel's own HTTPS listener does.
	TlsUseFile      bool   `json:"tlsUseFile"`
	CertificateFile string `json:"certificateFile"` // path mode: server cert path
	KeyFile         string `json:"keyFile"`         // path mode: server key path
	Certificate     string `json:"certificate"`     // content mode: server cert PEM
	Key             string `json:"key"`             // content mode: server key PEM
	CaCert          string `json:"caCert"`          // optional CA PEM (self-signed)

	ClientToClient    bool           `json:"clientToClient"`
	CrossInbound      bool           `json:"crossInbound"`
	UserLimit         *int           `json:"userLimit"`         // nil=absent(legacy=>1); 0=no limit; else 1..64. Parse-only — enforce via effectiveUserLimit.
	UserLimitStrategy string         `json:"userLimitStrategy"` // "accept" (evict oldest) or "reject"
	IpRanges          []string       `json:"ipRanges"`          // panel-managed 10.4.x /24 ranges
	Clients           []ocservClient `json:"clients"`
}

// effectiveRanges returns the inbound's client /24 ranges, or nil to signal the
// legacy id-derived /24 (10.4.{id}).
func (o *ocservSettings) effectiveRanges() []string { return o.IpRanges }

type ocservClient struct {
	ID       string `json:"id"`       // OpenConnect username
	Password string `json:"password"` // OpenConnect password
	Email    string `json:"email"`    // tracking identifier
	Enable   bool   `json:"enable"`
}

// SetRadius wires the shared RADIUS service + secret for OpenConnect auth/acct.
func (s *OcservService) SetRadius(rs *radius.RadiusService, secret string) {
	s.radiusService = rs
	s.radiusSecret = secret
}

// getRadiusSecret returns the RADIUS shared secret, falling back to the DB setting
// when the in-memory field is empty. Critical: the controller holds its OWN
// zero-value OcservService (SetRadius is only called on the web server's copy), so
// onOcservChanged → writeRadiusClientConfig runs with radiusSecret == "". Without
// this fallback the servers file is written as "127.0.0.1\t" (no secret), radcli
// then can't match the server ("couldn't find RADIUS server 127.0.0.1") and every
// OpenConnect auth fails. Mirrors L2tpService.getRadiusSecret.
//
// PORT NOTE: the fallback reads the settings KV row through vpn.RadiusSecret().
func (s *OcservService) getRadiusSecret() string {
	if s.radiusSecret != "" {
		return s.radiusSecret
	}
	secret, _ := vpn.RadiusSecret()
	return secret
}

func (s *OcservService) GetOcservInbounds() ([]*model.Inbound, error) {
	var inbounds []*model.Inbound
	db := vpn.DB()
	if db == nil {
		return nil, nil
	}
	err := db.Model(model.Inbound{}).Where("protocol = ?", "openconnect").Find(&inbounds).Error
	return inbounds, err
}

func (s *OcservService) parseSettings(inbound *model.Inbound) (*ocservSettings, error) {
	settings := &ocservSettings{}
	err := json.Unmarshal([]byte(inbound.Settings), settings)
	return settings, err
}

// configDir returns the directory holding an OpenConnect inbound's config, radcli,
// and (content-mode) cert files.
func (s *OcservService) configDir(inboundId int) string {
	return fmt.Sprintf("/etc/ocserv/server-%d", inboundId)
}

// ocservBinaryPath returns the ocserv executable the panel runs: the bundled
// static daemon if extracted, else a distro ocserv from PATH.
func (s *OcservService) ocservBinaryPath() string {
	return procmgr.DaemonBin("ocserv")
}

// occtlBinaryPath returns the occtl control tool (bundled alongside ocserv), used
// for programmatic session control (User Limit eviction in Phase 3).
func (s *OcservService) occtlBinaryPath() string {
	return procmgr.DaemonBin("occtl")
}

// ocservBlockFor returns the network address and prefix length of an inbound's
// client block (10.4.x), derived from its stored ranges. The server takes .1;
// clients start at .2. Defaults to the legacy 10.4.{id}.0/24 when no ranges are
// stored.
func ocservBlockFor(inbound *model.Inbound, settings *ocservSettings) (net.IP, int) {
	return vpnrange.VpnBlock(settings.effectiveRanges(), vpnrange.ProtocolBase("openconnect"), inbound.Id)
}

// GetTproxyPort returns the deterministic TPROXY/dokodemo port for the inbound.
// Inbound IDs are globally unique, so this shares the 12300+id formula with
// L2TP/PPTP/OpenVPN without colliding.
func (s *OcservService) GetTproxyPort(inbound *model.Inbound) int {
	return 12300 + inbound.Id
}

// GetDokodemoConfig builds the paired dokodemo-door inbound that captures the
// TPROXY-redirected OpenConnect traffic and feeds it into Xray's routing — the
// same mechanism L2TP/PPTP/OpenVPN use.
func (s *OcservService) GetDokodemoConfig(inbound *model.Inbound) *xray.InboundConfig {
	port := s.GetTproxyPort(inbound)
	settings := `{"network":"tcp,udp","followRedirect":true}`
	streamSettings := `{"sockopt":{"tproxy":"tproxy","mark":255}}`
	sniffing := `{"enabled":true,"destOverride":["http","tls"]}`

	return &xray.InboundConfig{
		Listen:         json_util.RawMessage(`"0.0.0.0"`),
		Port:           port,
		Protocol:       "dokodemo-door",
		Settings:       json_util.RawMessage(settings),
		StreamSettings: json_util.RawMessage(streamSettings),
		Tag:            inbound.Tag,
		Sniffing:       json_util.RawMessage(sniffing),
	}
}

// InitOcserv initializes OpenConnect services on panel startup.
func (s *OcservService) InitOcserv() {
	inbounds, err := s.GetOcservInbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}

	log.Info("OpenConnect: initializing services for", len(inbounds), "inbound(s)")

	if err := s.GenerateAllConfigs(); err != nil {
		log.Warning("OpenConnect: failed to generate configs:", err)
		return
	}
	if err := s.SetupRouting(); err != nil {
		log.Warning("OpenConnect: failed to setup routing:", err)
	}
	if err := s.RestartServices(); err != nil {
		log.Warning("OpenConnect: failed to restart services:", err)
	}
}

// GenerateAllConfigs regenerates every OpenConnect config file from DB state.
func (s *OcservService) GenerateAllConfigs() error {
	inbounds, err := s.GetOcservInbounds()
	if err != nil {
		return err
	}
	if len(inbounds) == 0 {
		return nil
	}

	for _, inbound := range inbounds {
		if err := s.generateServerConfig(inbound); err != nil {
			log.Warning("OpenConnect: skipping inbound", inbound.Id, err)
			continue
		}
		if err := s.writeCertFiles(inbound); err != nil {
			log.Warning("OpenConnect: cert write failed for inbound", inbound.Id, err)
		}
		if err := s.writeRadiusClientConfig(inbound); err != nil {
			log.Warning("OpenConnect: radcli config write failed for inbound", inbound.Id, err)
		}
	}
	return nil
}

// generateServerConfig writes the ocserv.conf for one inbound.
func (s *OcservService) generateServerConfig(inbound *model.Inbound) error {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return err
	}

	dir := s.configDir(inbound.Id)
	// /etc/ocserv is recorded before we implicitly create it, because a distro ocserv
	// owns that directory: its ocserv.conf, its certificates and its ocpasswd live
	// there, and uninstall used to remove the whole thing. We only ever own
	// /etc/ocserv/server-<id> inside it.
	manifest.PrepareDir("/etc/ocserv", "openconnect")
	manifest.PrepareDir(dir, "openconnect")
	// Best-effort: a failed create surfaces immediately in the config write below.
	_ = os.MkdirAll(dir, 0o755)
	manifest.PrepareDir("/var/run/ocserv", "openconnect")
	// Best-effort: ocserv fails visibly at start when its run dir is missing.
	_ = os.MkdirAll("/var/run/ocserv", 0o755)

	conf := applyCoreConfigOverride("openconnect", inbound.Id, "ocserv.conf",
		s.buildServerConfig(inbound, settings))
	return s.writeFile(fmt.Sprintf("%s/ocserv.conf", dir), conf)
}

// ocservProcName returns the process-manager key for an OpenConnect inbound.
func ocservProcName(inboundId int) string {
	return fmt.Sprintf("ocserv-server-%d", inboundId)
}

// certPaths returns the server cert + key file paths ocserv should reference. In
// path mode the operator's own paths are used verbatim; in content mode the PEMs
// are written into the inbound's config dir (see writeCertFiles).
func (s *OcservService) certPaths(inbound *model.Inbound, settings *ocservSettings) (certPath, keyPath string) {
	if settings.TlsUseFile && strings.TrimSpace(settings.CertificateFile) != "" && strings.TrimSpace(settings.KeyFile) != "" {
		return strings.TrimSpace(settings.CertificateFile), strings.TrimSpace(settings.KeyFile)
	}
	dir := s.configDir(inbound.Id)
	return dir + "/server.crt", dir + "/server.key"
}

// hasUsableCert reports whether a server cert+key is available on disk (content
// mode written, or an operator path that exists). ocserv refuses to start without
// one, so RestartServices skips inbounds that have none yet.
func (s *OcservService) hasUsableCert(inbound *model.Inbound, settings *ocservSettings) bool {
	certPath, keyPath := s.certPaths(inbound, settings)
	if _, err := os.Stat(certPath); err != nil {
		return false
	}
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	return true
}

// buildServerConfig returns the ocserv.conf content for an inbound.
func (s *OcservService) buildServerConfig(inbound *model.Inbound, settings *ocservSettings) string {
	id := inbound.Id
	dir := s.configDir(id)
	port := inbound.Port

	netAddr, prefix := ocservBlockFor(inbound, settings)
	network := netAddr.String()
	netmask := vpnrange.PrefixToMask(prefix)

	dns1 := settings.Dns1
	if dns1 == "" {
		dns1 = "8.8.8.8"
	}
	dns2 := settings.Dns2
	if dns2 == "" {
		dns2 = "8.8.4.4"
	}
	mtu := settings.Mtu
	if mtu == 0 {
		mtu = 1420 // conservative default; DTLS/TLS overhead on a 1500 path
	}

	certPath, keyPath := s.certPaths(inbound, settings)

	var b strings.Builder
	b.WriteString("# Auto-generated by pxpanel OpenConnect service — do not edit\n")
	// groupconfig=true makes ocserv APPLY the RADIUS reply attributes to the
	// session — critically Framed-IP-Address, which pins each device to its
	// panel-assigned block IP. Verified: WITHOUT it ocserv ignores Framed-IP and
	// hands out an ipv4-network pool IP instead, so the RADIUS-tracked IP no longer
	// matches the real tunnel IP and per-device User-Limit accept-eviction (occtl
	// disconnect-by-IP) can't find the session, plus source-IP routing for the
	// device breaks. (The "401" that once prompted disabling this was an empty
	// RADIUS shared secret, not groupconfig.)
	fmt.Fprintf(&b, "auth = \"radius[config=%s/radiusclient.conf,groupconfig=true]\"\n", dir)
	fmt.Fprintf(&b, "acct = \"radius[config=%s/radiusclient.conf]\"\n", dir)
	fmt.Fprintf(&b, "tcp-port = %d\n", port)
	fmt.Fprintf(&b, "udp-port = %d\n", port)
	fmt.Fprintf(&b, "socket-file = /var/run/ocserv/ocserv-%d.sock\n", id)
	// occtl control socket — used for programmatic session control (User Limit
	// eviction via `occtl -s <sock> disconnect`).
	b.WriteString("use-occtl = true\n")
	fmt.Fprintf(&b, "occtl-socket-file = %s\n", s.occtlSocket(id))
	b.WriteString("run-as-user = root\n")
	b.WriteString("run-as-group = root\n")
	fmt.Fprintf(&b, "server-cert = %s\n", certPath)
	fmt.Fprintf(&b, "server-key = %s\n", keyPath)
	// Widen TLS to reach old clients: allow TLS 1.0 through 1.3. NORMAL already
	// covers TLS 1.2/1.3 + DTLS (kept intact for UDP); we add TLS 1.0/1.1 back and
	// %COMPAT for legacy interop. An explicit priority string is honored directly by
	// the statically-bundled GnuTLS, so no host crypto policy can veto old TLS.
	b.WriteString("tls-priorities = \"NORMAL:%SERVER_PRECEDENCE:%COMPAT:+VERS-TLS1.0:+VERS-TLS1.1\"\n")
	if strings.TrimSpace(settings.CaCert) != "" && !settings.TlsUseFile {
		fmt.Fprintf(&b, "ca-cert = %s/ca.crt\n", dir)
	}
	// We build ocserv --disable-seccomp, so the isolate-workers syscall sandbox is
	// unavailable; disabling it explicitly avoids a startup error.
	b.WriteString("isolate-workers = false\n")
	b.WriteString("max-clients = 1024\n")
	// max-same-clients = 0 (unlimited) on purpose: the User Limit K is enforced
	// server-side by the panel's RADIUS server, which pins each device to a distinct
	// block IP (Framed-IP-Address) and applies the reject/accept-evict strategy. A
	// native ocserv cap here would refuse the (K+1)-th device BEFORE RADIUS runs,
	// breaking both the reject logging and the accept-then-evict-oldest flow.
	b.WriteString("max-same-clients = 0\n")
	// Keepalive and DPD are what hold the tunnel open through NAT, and ocserv's own
	// sample values (keepalive 32400, dpd 90, mobile-dpd 1800) cannot do it here.
	//
	// keepalive is not a server timer: it is advertised as X-CSTP-Keepalive /
	// X-DTLS-Keepalive and tells the CLIENT how often to send a packet on an idle
	// tunnel. At 32400 (9 hours) an idle client sends nothing at all, so the only
	// traffic keeping the NAT mapping alive is DPD. Worse, ocserv REPLACES dpd with
	// mobile-dpd for any client whose platform header says android or apple-ios
	// (worker-vpn.c: `if (req->is_mobile) ws->user_config->dpd = mobile_dpd`), which is
	// every phone. So a phone was told "DPD every 30 minutes, keepalive every 9 hours"
	// while carrier-grade NAT drops an idle UDP mapping in well under two minutes: after
	// a few idle minutes the path is dead in the server->client direction, the client
	// has no probe due for half an hour to notice, and ocserv only tears the session down
	// after DPD_MAX_TRIES (3) x dpd, i.e. 90 minutes. Both ends believe they are
	// connected, nothing passes, and only a manual client reconnect fixes it.
	//
	// 30s keepalive is the interval every other tunnel protocol here already relies on
	// (WireGuard persistent-keepalive is 25s, IPsec NAT-T ~20s) and it refreshes both the
	// TCP and the DTLS mapping. With that in place DPD only has to answer "is this peer
	// gone", so 60s (probe at 2x, teardown at 3x = 3 minutes) is a genuinely dead link,
	// and a phone's 300s keeps the battery cost near zero while still freeing its
	// User-Limit slot in 15 minutes instead of 90.
	b.WriteString("keepalive = 30\n")
	b.WriteString("dpd = 60\n")
	b.WriteString("mobile-dpd = 300\n")
	b.WriteString("switch-to-tcp-timeout = 25\n")
	b.WriteString("try-mtu-discovery = true\n")
	b.WriteString("cisco-client-compat = true\n")
	b.WriteString("dtls-legacy = true\n")
	b.WriteString("compression = false\n")
	// Auth backend returns the tunnel IP (Framed-IP-Address); no predictable/local
	// pool assignment so the RADIUS pin is authoritative.
	b.WriteString("predictable-ips = false\n")
	fmt.Fprintf(&b, "device = ocserv-%d\n", id)
	fmt.Fprintf(&b, "ipv4-network = %s\n", network)
	fmt.Fprintf(&b, "ipv4-netmask = %s\n", netmask)
	b.WriteString("tunnel-all-dns = true\n")
	fmt.Fprintf(&b, "dns = %s\n", dns1)
	fmt.Fprintf(&b, "dns = %s\n", dns2)
	fmt.Fprintf(&b, "mtu = %d\n", mtu)
	// Full-tunnel: push the default route so ALL client traffic enters the tun,
	// where the nftables TPROXY hook redirects it into Xray (no split routes, no
	// masquerade — Xray owns egress).
	b.WriteString("route = default\n")
	if settings.ClientToClient {
		// Let ocserv bridge client-to-client traffic internally instead of routing
		// it out the tun (where TPROXY would capture it).
		b.WriteString("# client-to-client enabled\n")
	}
	b.WriteString("cert-user-oid = 0.9.2342.19200300.100.1.1\n")
	// log-level 3: surface per-connection auth results (sec-mod / radcli / worker
	// "failed authentication") in the daemon log without the full TLS packet dumps
	// of higher levels — so an auth failure is diagnosable from the captured log.
	b.WriteString("log-level = 3\n")

	return b.String()
}

// writeCertFiles writes the content-mode server cert/key (and optional CA) to the
// inbound's config dir. In path mode ocserv reads the operator's own files, so
// nothing is written here.
func (s *OcservService) writeCertFiles(inbound *model.Inbound) error {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return err
	}
	if settings.TlsUseFile {
		return nil
	}

	dir := s.configDir(inbound.Id)
	_ = os.MkdirAll(dir, 0o755)

	if strings.TrimSpace(settings.Certificate) != "" {
		if err := s.writeFile(dir+"/server.crt", settings.Certificate); err != nil {
			return err
		}
	}
	if strings.TrimSpace(settings.Key) != "" {
		if err := s.writeFileMode(dir+"/server.key", settings.Key, 0o600); err != nil {
			return err
		}
	}
	if strings.TrimSpace(settings.CaCert) != "" {
		if err := s.writeFile(dir+"/ca.crt", settings.CaCert); err != nil {
			return err
		}
	}
	return nil
}

// writeRadiusClientConfig writes the per-inbound radcli client config so ocserv
// authenticates + accounts against the panel's in-process RADIUS server. radcli
// (ocserv's RADIUS library) uses `nas-identifier` (hyphen) — distinct from pppd's
// `nas_identifier` — so it can't share L2TP/PPTP's config; it carries a per-inbound
// nas-identifier `openconnect-{id}` that the RADIUS server resolves directly.
func (s *OcservService) writeRadiusClientConfig(inbound *model.Inbound) error {
	dir := s.configDir(inbound.Id)
	_ = os.MkdirAll(dir, 0o755)

	// Reuse the self-contained dictionary the RADIUS service ships (it already
	// carries NAS-Identifier, Framed-IP-Address, and the accounting attributes).
	if err := generateRadiusDictionary(dir); err != nil {
		return fmt.Errorf("failed to write dictionary: %w", err)
	}

	config := fmt.Sprintf(`# Auto-generated by pxpanel OpenConnect (radcli) — do not edit
authserver	127.0.0.1:1812
acctserver	127.0.0.1:1813
servers		%s/servers
dictionary	%s/dictionary
default_realm
radius_timeout	5
radius_retries	3
nas-identifier	openconnect-%d
bindaddr	*
`, dir, dir, inbound.Id)
	if err := os.WriteFile(dir+"/radiusclient.conf", []byte(config), 0o644); err != nil {
		return fmt.Errorf("failed to write radiusclient.conf: %w", err)
	}

	servers := fmt.Sprintf("127.0.0.1\t%s\n", s.getRadiusSecret())
	return os.WriteFile(dir+"/servers", []byte(servers), 0o600)
}

// SetupRouting prepares the host so OpenConnect client traffic is TPROXY-redirected
// into Xray instead of NAT'd to the internet. Shares the fwmark policy route and
// nftables regeneration with the other VPN protocols.
//
// PORT NOTE: vpn-ui's ApplyNftRules gathered every protocol's subnets in one
// shot; the foundation's ApplyNftRules takes them pre-gathered as RulesInput,
// and GatherRulesInput composes every protocol that registered a steering
// source (register.go) — so this regeneration keeps the other protocols'
// TPROXY rules instead of dropping them (vpn-ui behaviour; a self-only input
// would rebuild the shared vpn table without them, sending every other
// protocol's client traffic straight out the WAN, past Xray and its routing
// rules).
func (s *OcservService) SetupRouting() error {
	_ = s.runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")

	_ = s.runCmd("modprobe", "tun")
	_ = s.runCmd("modprobe", "nf_tproxy_ipv4")

	nftables.EnsureVpnPolicyRoute(s.runCmd)

	svc := s.nft
	if svc == nil {
		svc = &nftables.Service{}
	}
	return svc.ApplyNftRules(nftables.GatherRulesInput())
}

// nftSteeringNets maps the enabled OpenConnect inbounds onto the foundation's
// SteeringNet shape — vpn-ui's ApplyNftRules inline gathering (allNets loop +
// ocservCIDRs) moved to the caller there.
func (s *OcservService) nftSteeringNets() []nftables.SteeringNet {
	inbounds, err := s.GetOcservInbounds()
	if err != nil {
		return nil
	}
	var nets []nftables.SteeringNet
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		n, p := ocservBlockFor(inbound, settings)
		nets = append(nets, nftables.SteeringNet{
			Subnets:    []string{fmt.Sprintf("%s/%d", n.String(), p)},
			C2C:        settings.ClientToClient,
			Cross:      settings.CrossInbound,
			TproxyPort: s.GetTproxyPort(inbound),
		})
	}
	return nets
}

// RestartServices launches (or stops) an ocserv child process per inbound. An
// inbound with no usable server cert yet is skipped (ocserv refuses to start
// without one). Managed ocserv processes with no corresponding enabled inbound
// are stopped.
func (s *OcservService) RestartServices() error {
	procmgr.MigrateFromSystemd()

	inbounds, err := s.GetOcservInbounds()
	if err != nil {
		return err
	}

	mgr := procmgr.GetProcManager()
	bin := s.ocservBinaryPath()
	desired := map[string]bool{}

	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil {
			log.Warning("OpenConnect: skipping inbound", inbound.Id, err)
			continue
		}
		if !s.hasUsableCert(inbound, settings) {
			log.Warning("OpenConnect: inbound", inbound.Id, "has no TLS cert yet — generate a self-signed cert or set a cert path")
			continue
		}
		dir := s.configDir(inbound.Id)
		name := ocservProcName(inbound.Id)
		desired[name] = true
		confPath := fmt.Sprintf("%s/ocserv.conf", dir)
		args := []string{"-f", "-c", confPath}
		if err := mgr.Start(name, bin, args, nil, dir); err != nil {
			log.Warning("OpenConnect: failed to start", name, err)
		}
	}

	for _, name := range mgr.NamesWithPrefix("ocserv-server-") {
		if !desired[name] {
			_ = mgr.Stop(name)
		}
	}
	return nil
}

// StopServices stops all OpenConnect child processes.
func (s *OcservService) StopServices() {
	procmgr.GetProcManager().StopByPrefix("ocserv-server-")
}

// GenerateSelfSignedCert generates a self-signed server certificate + key for
// ocserv. Unlike OpenVPN (which needs a CA + tls-crypt), ocserv only needs a
// server cert the client trusts (or bypasses with --no-cert-check); a single
// self-issued ECDSA P-384 cert suffices. Returns PEM strings: serverCert, serverKey.
//
// serverAddr is the address clients will dial; empty means the address this host
// egresses with. It becomes the CN and the SANs, which is not decoration: a
// certificate with NO subjectAltName cannot be verified by name by anything, so
// every client had to be told to skip the check. This used to mint a fixed CN of
// "vpn-ui OpenConnect Server" and no SAN at all, which meant AnyConnect, the
// openconnect CLI and this panel's own OpenConnect OUTBOUND all failed
// verification against a gateway whose certificate the operator had handed them,
// with nothing wrong on either side but the certificate itself. The IKEv2
// generator has always done this (Ikev2Service.GenerateSelfSignedCert); these two
// were the odd ones out.
func (s *OcservService) GenerateSelfSignedCert(serverAddr string) (string, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate server key: %w", err)
	}

	host := strings.TrimSpace(serverAddr)
	if host == "" {
		host = s.getServerIP()
	}
	cn := host
	if cn == "" {
		// Nothing to name it after. Keep the old CN rather than inventing one, so a
		// host whose address cannot be detected produces exactly what it used to.
		cn = "pxpanel OpenConnect Server"
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"pxpanel"},
			CommonName:   cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if host != "" {
		// Both forms, for the same reason the IKEv2 leaf carries both: an address is
		// an iPAddress SAN to a correct client and a dNSName to several real ones.
		template.DNSNames = []string{host}
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = []net.IP{ip}
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", fmt.Errorf("failed to create server cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return string(certPEM), string(keyPEM), nil
}

// occtlSocket returns the occtl control-socket path for an inbound's ocserv.
func (s *OcservService) occtlSocket(inboundId int) string {
	return fmt.Sprintf("/var/run/ocserv/occtl-%d.sock", inboundId)
}

// vpnProbeTimeout bounds the helper commands the session-control paths shell out
// to (occtl). Carried package-locally from vpn-ui web/service/radius.go, which
// named the same constant for the same reason: occtl talks to ocserv's MAIN
// process, which can itself be waiting on sec-mod, which is waiting for a reply
// we have not written yet — the circular wait that makes an unbounded call stall
// the caller. A missed control call just retries on the next sweep, so failing
// fast is the cheap side.
const vpnProbeTimeout = 3 * time.Second

// probeCmd runs a short-lived helper command under vpnProbeTimeout and returns
// its stdout. (vpn-ui web/service/radius.go probeCmd — carried package-locally;
// see the package doc's TODO about hoisting it into a shared spot.)
func probeCmd(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), vpnProbeTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

// KillClient disconnects a user's active session(s) on an inbound's ocserv via
// occtl. Best-effort: a no-op if the socket/daemon isn't up. `disconnect user`
// drops every session for that username (whole-account teardown), which is what
// the disable/expiry callers want. Per-device eviction (User Limit "accept")
// uses `disconnect id` and is layered on in the RADIUS path.
func (s *OcservService) KillClient(inboundId int, username string) {
	if username == "" {
		return
	}
	sock := s.occtlSocket(inboundId)
	if _, err := os.Stat(sock); err != nil {
		return
	}
	// Bounded like every other occtl call on a RADIUS/job path: this runs from the 10s
	// traffic tick, once per disabled client. See vpnProbeTimeout.
	if _, err := probeCmd(s.occtlBinaryPath(), "-s", sock, "disconnect", "user", username); err != nil {
		log.Debugf("OpenConnect: occtl disconnect user %s failed: %v", username, err)
	}
}

// KillDisabledSessions disconnects active OpenConnect sessions for clients that
// are disabled (in settings or via the client_traffics quota/expiry table).
func (s *OcservService) KillDisabledSessions() {
	inbounds, err := s.GetOcservInbounds()
	if err != nil {
		return
	}
	disabledEmails := s.getDisabledEmails()

	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		for _, client := range settings.Clients {
			if !client.Enable || disabledEmails[client.Email] {
				s.KillClient(inbound.Id, client.ID)
			}
		}
	}
}

// DisableClients disconnects the given client emails' active sessions.
func (s *OcservService) DisableClients(emails []string) {
	if len(emails) == 0 {
		return
	}
	emailSet := make(map[string]bool, len(emails))
	for _, e := range emails {
		emailSet[e] = true
	}

	inbounds, err := s.GetOcservInbounds()
	if err != nil {
		return
	}
	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		for _, client := range settings.Clients {
			if emailSet[client.Email] {
				s.KillClient(inbound.Id, client.ID)
			}
		}
	}
}

// getDisabledEmails returns the set of client emails disabled in client_traffics
// (traffic limit or expiry).
func (s *OcservService) getDisabledEmails() map[string]bool {
	disabled := make(map[string]bool)
	db := vpn.DB()
	if db == nil {
		return disabled
	}
	var emails []string
	db.Model(&xray.ClientTraffic{}).
		Where("enable = ?", false).
		Pluck("email", &emails)
	for _, e := range emails {
		disabled[e] = true
	}
	return disabled
}

// getServerIP returns the server's primary IP address (default-route source).
func (s *OcservService) getServerIP() string {
	output, err := exec.CommandContext(context.Background(), "ip", "-4", "route", "get", "1.1.1.1").Output()
	if err == nil {
		parts := strings.Fields(string(output))
		for i, p := range parts {
			if p == "src" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

func (s *OcservService) writeFile(path, content string) error {
	return s.writeFileMode(path, content, 0o644)
}

func (s *OcservService) writeFileMode(path, content string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

func (s *OcservService) runCmd(name string, args ...string) error {
	cmd := exec.CommandContext(context.Background(), name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Debugf("OpenConnect: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}
