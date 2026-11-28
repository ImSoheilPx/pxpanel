// Package sstp is vpn-ui's Microsoft SSTP (Secure Socket Tunneling Protocol)
// service (web/service/sstp.go) ported verbatim into pxpanel, module import
// rewritten mhsanaei/3x-ui/v2 → ImSoheilPx/pxpanel and the web/service
// cross-calls re-pointed at the internal/vpn foundation seams:
//
//	database.GetDB()          → vpn.DB() (injected handle, cgo-free)
//	SettingService            → vpn.RadiusSecret() (settings-KV seam)
//	procMgr/daemonBin/        → procmgr.GetProcManager()/DaemonBin/
//	migrateFromSystemd          MigrateFromSystemd
//	backend.AccelDictPath     → accelDictPath below (bundle wave TODO)
//	nftService.ApplyNftRules  → nftables.GatherRulesInput()+ApplyNftRules
//	                          (steering-source registry, all protocols)
//	ensureVpnPolicyRoute      → nftables.EnsureVpnPolicyRoute
//	vpnrange helpers          → the range package's exported wrappers
//	applyCoreConfigOverride   → coreconfig.ApplyCoreConfigOverride
//	xray.InboundConfig /      → the target internal/xray package (same shapes)
//	xray.ClientTraffic
//	OcservService.getServerIP → serverIP below (identical detector; the
//	                          OpenConnect wave owns that service)
//	killOcservByIP-analogue   → vpn.RegisterProtocolEvictor (radius dispatches
//	                          teardowns through vpn.EvictProtocolIP); the
//	                          inbound-for-IP routing vpn-ui kept in radius.go
//	                          (sstpInboundForIP) moved here with it
//	logger                    → the vpn/log shim
//
// Deferred to later waves (NOT ported here):
//   - web/service/vpnout_sstp.go — the sstpc CLIENT side. It belongs to the
//     vpnout family (vpnoutbound/vpnoutvia/vpnoutcarrier + the 9 vpnout_*.go),
//     which is its own wave; none of that foundation exists yet.
//   - backend/sstpc.go (client bundle extraction) — rides the same vpnout/bundle
//     wave. The SERVER bundle's accel-pppd/accel-cmd resolution goes through the
//     procmgr BundleProvider seam today.
//   - The config editor's per-core target list (vpn-ui coreconfig.go:
//     sstpConfigTargets) and the controllers/API routes.
//
// TODO(controllers wave): wire InitSstp/GenerateAllConfigs/RestartServices/
// ReconcileDisabled-style jobs, the generate-sstp-cert endpoint, and the
// SetRadius injection at server wire-up (vpn-ui web.go startTask).
//
// SstpService manages Microsoft SSTP server configuration: the bundled
// accel-ppp daemon (one instance per inbound), its TLS certificate, the
// per-inbound accel-ppp.conf, and the shared nftables/TPROXY routing that
// steers client traffic into Xray.
//
// SSTP is a HYBRID of ocserv's and pptp's models:
//   - LIKE ocserv: a native userspace daemon per inbound with its own TLS cert,
//     per-inbound config dir, procMgr child ("sstp-server-<id>"), and a dedicated
//     eviction path (accel-cmd, the analogue of occtl).
//   - LIKE pptp: it is PPP-family, so it uses the arbitrary-/24-list addressing
//     (GetSubnetsForInbound), MSCHAPv2 auth, and — critically — accel-ppp speaks
//     PROPER RADIUS (Framed-IP-Address + NAS-Port in both Access-Request and
//     Acct-Start). So auth/accounting/device-keying flow through the panel's
//     RADIUS server EXACTLY like pptp (no ocserv-style auth-time recording, no
//     accounting skip). Only eviction differs: accel-ppp is a single daemon, so a
//     device is torn down via `accel-cmd terminate ip <ip>`, never killPPPByIP.
package sstp

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
	"strconv"
	"strings"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/util/json_util"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/coreconfig"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/log"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/nftables"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/radius"
	vpnrange "github.com/ImSoheilPx/pxpanel/internal/vpn/range"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

// accelDictPath is the bundled accel-ppp RADIUS dictionary (vpn-ui
// backend.AccelDictPath, product path renamed vpn-ui → pxpanel). accel-ppp uses
// its OWN dictionary format (distinct from radcli's), so the generated
// accel-ppp.conf points its [radius] dictionary= at this bundled file, which
// must carry the MS-CHAP / MS-MPPE attributes MSCHAPv2 needs. The bundle keeps
// the dictionary self-contained here (relative $INCLUDEs to siblings).
//
// TODO(bundle wave): resolve through the procmgr BundleProvider (like
// AccelBinPath) once the embedded accel-ppp bundle lands; the constant assumes
// the vpn-ui bundle layout at the renamed root.
const accelDictPath = "/usr/libexec/pxpanel-accel/share/accel-ppp/radius/dictionary"

// SstpService is the SSTP protocol service (one accel-pppd per inbound).
//
// PORT NOTE: vpn-ui's inboundService/nftService fields were web/service types.
// The nft side is the foundation's stateless *nftables.Service (nil = a fresh
// one, SetupRouting only calls the stateless ApplyNftRules); inboundService is
// dropped (this file never dereferences it). SetRadius keeps the vpn-ui shape
// so the wire-up wave can inject the shared RADIUS service exactly as before.
type SstpService struct {
	nft           *nftables.Service
	radiusService *radius.RadiusService
	radiusSecret  string
}

// sstpSettings is the SSTP-specific slice of an inbound's Settings JSON. It clones
// ocserv's cert model (path | inline PEM | self-signed) and pptp's PPP addressing
// fields (ipRanges/localIp), so the frontend and API serialize identically to
// OpenConnect (users under "clients", cert fields the same).
type sstpSettings struct {
	Dns1 string `json:"dns1"`
	Dns2 string `json:"dns2"`
	Mtu  int    `json:"mtu"`

	// TLS follows the Xray inbound model: either operator-supplied paths
	// (TlsUseFile) or inline PEM content. "Generate Self-Signed Cert" fills the
	// content fields; "Set Default Cert" copies the panel's own webCertFile/
	// webKeyFile paths (TlsUseFile mode). accel-ppp reads whichever is active from
	// disk via [sstp] ssl-pemfile/ssl-keyfile.
	TlsUseFile      bool   `json:"tlsUseFile"`
	CertificateFile string `json:"certificateFile"` // path mode: server cert path
	KeyFile         string `json:"keyFile"`         // path mode: server key path
	Certificate     string `json:"certificate"`     // content mode: server cert PEM
	Key             string `json:"key"`             // content mode: server key PEM
	CaCert          string `json:"caCert"`          // optional CA PEM (self-signed)

	ClientToClient    bool         `json:"clientToClient"`
	CrossInbound      bool         `json:"crossInbound"`
	UserLimit         *int         `json:"userLimit"`         // nil=absent(legacy=>1); 0=no limit; else 1..64. Parse-only — enforce via effectiveUserLimit.
	UserLimitStrategy string       `json:"userLimitStrategy"` // "accept" (evict oldest) or "reject"
	IpRanges          []string     `json:"ipRanges"`          // panel-managed 10.5.x /24 ranges (PPP-family)
	IpRange           string       `json:"ipRange"`           // legacy single-range field (read-only fallback)
	LocalIp           string       `json:"localIp"`           // PPP gateway (first range .1)
	Clients           []sstpClient `json:"clients"`
}

// sstpClient mirrors ocservClient: a MINIMAL client struct with only the fields the
// SSTP service reads. The panel UI posts the FULL client object (tgId, totalGB,
// expiryTime, comment, …); unmarshaling into this minimal struct silently drops the
// extras. Using []model.Client instead FAILS on the UI's string tgId ("cannot unmarshal
// string into Go struct field Client.clients.tgId of type int64") and skips the inbound,
// so accel-pppd never starts and the core stays Stopped.
type sstpClient struct {
	ID       string `json:"id"`       // SSTP username
	Password string `json:"password"` // SSTP password
	Email    string `json:"email"`    // tracking identifier
	Enable   bool   `json:"enable"`
}

// SetRadius wires the shared RADIUS service + secret for SSTP auth/acct.
func (s *SstpService) SetRadius(rs *radius.RadiusService, secret string) {
	s.radiusService = rs
	s.radiusSecret = secret
}

// getRadiusSecret returns the RADIUS shared secret, falling back to the DB setting
// when the in-memory field is empty. The controller holds its OWN zero-value
// SstpService (SetRadius is only called on the web server's copy), so config
// regeneration there runs with radiusSecret == "" — without this fallback the
// accel-ppp.conf server= line would carry an empty secret and every SSTP auth
// would fail. Mirrors OcservService.getRadiusSecret / PptpService.getRadiusSecret.
func (s *SstpService) getRadiusSecret() string {
	if s.radiusSecret != "" {
		return s.radiusSecret
	}
	secret, _ := vpn.RadiusSecret()
	return secret
}

// GetSstpInbounds returns every SSTP inbound.
func (s *SstpService) GetSstpInbounds() ([]*model.Inbound, error) {
	db := vpn.DB()
	var inbounds []*model.Inbound
	if db == nil {
		return nil, nil
	}
	err := db.Model(model.Inbound{}).Where("protocol = ?", "sstp").Find(&inbounds).Error
	return inbounds, err
}

func (s *SstpService) parseSettings(inbound *model.Inbound) (*sstpSettings, error) {
	settings := &sstpSettings{}
	err := json.Unmarshal([]byte(inbound.Settings), settings)
	return settings, err
}

// effectiveRanges returns the inbound's configured /24 ranges, seeding from the
// legacy single ipRange field when the ipRanges list is empty (pptp-like).
func (s *SstpService) effectiveRanges(settings *sstpSettings) []string {
	if len(settings.IpRanges) > 0 {
		return settings.IpRanges
	}
	if settings.IpRange != "" {
		return []string{settings.IpRange}
	}
	return nil
}

// GetSubnetsForInbound returns every /24 prefix ("10.5.x") the inbound's client
// ranges cover. Falls back to the legacy id-derived /24 when nothing is stored.
// PPP-family, exactly like PptpService.GetSubnetsForInbound.
func (s *SstpService) GetSubnetsForInbound(inbound *model.Inbound) []string {
	if settings, err := s.parseSettings(inbound); err == nil {
		if subs := vpnrange.SubnetsOf(s.effectiveRanges(settings)); len(subs) > 0 {
			return subs
		}
	}
	return []string{fmt.Sprintf("10.%d.%d", vpnrange.ProtocolBase("sstp"), inbound.Id)}
}

// GetSubnetForInbound returns the inbound's first /24 subnet (legacy callers).
func (s *SstpService) GetSubnetForInbound(inbound *model.Inbound) string {
	return s.GetSubnetsForInbound(inbound)[0]
}

// GetTproxyPort returns the deterministic TPROXY/dokodemo port for the inbound.
// Inbound IDs are globally unique, so this shares the 12300+id formula with the
// other VPN protocols without colliding.
func (s *SstpService) GetTproxyPort(inbound *model.Inbound) int {
	return 12300 + inbound.Id
}

// GetDokodemoConfig builds the paired dokodemo-door inbound that captures the
// TPROXY-redirected SSTP traffic and feeds it into Xray's routing — the same
// mechanism L2TP/PPTP/OpenVPN/OpenConnect use.
func (s *SstpService) GetDokodemoConfig(inbound *model.Inbound) *xray.InboundConfig {
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

// configDir returns the directory holding an SSTP inbound's accel-ppp.conf, its
// content-mode cert files, and its accel.log. PORT NOTE: vpn-ui used
// /etc/vpn-ui-sstp; the product path is renamed (matches the ownership
// manifest's /etc/pxpanel-* rule).
func (s *SstpService) configDir(inboundId int) string {
	return fmt.Sprintf("/etc/pxpanel-sstp/server-%d", inboundId)
}

// sstpProcName returns the process-manager key for an SSTP inbound's accel-pppd.
func sstpProcName(inboundId int) string {
	return fmt.Sprintf("sstp-server-%d", inboundId)
}

// sstpCliPort is the loopback TCP port accel-pppd exposes for accel-cmd control
// (session eviction / disable), one per inbound. Bound on 127.0.0.1 only, so it
// never reaches the network. Deterministic and disjoint from the 12300+id TPROXY
// band; accel-cmd's own default is 2001, which we override per inbound.
func sstpCliPort(inbound *model.Inbound) int {
	return 13300 + inbound.Id
}

// accelPppdBinaryPath returns the accel-pppd executable the panel runs: the
// bundled loader-wrapper if extracted (resolved via the bundle provider's
// AccelBinPath inside procmgr.DaemonBin), else a distro accel-pppd from PATH.
func (s *SstpService) accelPppdBinaryPath() string {
	return procmgr.DaemonBin("accel-pppd")
}

// certPaths returns the server cert + key file paths accel-pppd should reference.
// In path mode the operator's own paths are used verbatim; in content mode the
// PEMs are written into the inbound's config dir (see writeCertFiles).
func (s *SstpService) certPaths(settings *sstpSettings, inboundId int) (certPath, keyPath string) {
	if settings.TlsUseFile && strings.TrimSpace(settings.CertificateFile) != "" && strings.TrimSpace(settings.KeyFile) != "" {
		return strings.TrimSpace(settings.CertificateFile), strings.TrimSpace(settings.KeyFile)
	}
	dir := s.configDir(inboundId)
	return dir + "/server.crt", dir + "/server.key"
}

// hasUsableCert reports whether a server cert+key is available on disk (content
// mode written, or an operator path that exists). accel-pppd's sstp module refuses
// to start without one, so RestartServices skips inbounds that have none yet.
func (s *SstpService) hasUsableCert(settings *sstpSettings, id int) bool {
	certPath, keyPath := s.certPaths(settings, id)
	if _, err := os.Stat(certPath); err != nil {
		return false
	}
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	return true
}

// gatewayIP returns the local (server) end of each ppp link for this inbound — the
// first range's .1, exactly like the PPTP localip. accel-ppp uses it as the
// [radius] gw-ip-address; each client's own IP comes from RADIUS Framed-IP-Address.
func (s *SstpService) gatewayIP(inbound *model.Inbound, settings *sstpSettings) string {
	ranges := s.effectiveRanges(settings)
	if len(ranges) == 0 {
		ranges = []string{vpnrange.DefaultRange(s.GetSubnetForInbound(inbound))}
	}
	if start, _, ok := vpnrange.ParseRange(ranges[0]); ok {
		return fmt.Sprintf("%d.%d.%d.1", start[0], start[1], start[2])
	}
	if strings.TrimSpace(settings.LocalIp) != "" {
		return strings.TrimSpace(settings.LocalIp)
	}
	return fmt.Sprintf("10.%d.%d.1", vpnrange.ProtocolBase("sstp"), inbound.Id)
}

// InitSstp initializes SSTP services on panel startup.
func (s *SstpService) InitSstp() {
	inbounds, err := s.GetSstpInbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}

	log.Info("SSTP: initializing services for", len(inbounds), "inbound(s)")

	if err := s.GenerateAllConfigs(); err != nil {
		log.Warning("SSTP: failed to generate configs:", err)
		return
	}
	if err := s.SetupRouting(); err != nil {
		log.Warning("SSTP: failed to setup routing:", err)
	}
	if err := s.RestartServices(); err != nil {
		log.Warning("SSTP: failed to restart services:", err)
	}
}

// GenerateAllConfigs regenerates every SSTP accel-ppp.conf (+ content-mode certs)
// from DB state. Unlike ocserv there is no separate radcli file — the RADIUS
// client config (secret, dictionary, nas-identifier) lives inside accel-ppp.conf's
// [radius] section.
func (s *SstpService) GenerateAllConfigs() error {
	inbounds, err := s.GetSstpInbounds()
	if err != nil {
		return err
	}
	if len(inbounds) == 0 {
		return nil
	}

	for _, inbound := range inbounds {
		if err := s.generateServerConfig(inbound); err != nil {
			log.Warning("SSTP: skipping inbound", inbound.Id, err)
			continue
		}
		if err := s.writeCertFiles(inbound); err != nil {
			log.Warning("SSTP: cert write failed for inbound", inbound.Id, err)
		}
	}
	return nil
}

// opensslConfPath is the per-inbound OpenSSL config the SSTP daemon is pointed at
// via OPENSSL_CONF (see RestartServices) so its TLS acceptance follows our
// ssl-protocol setting, not the host's system OpenSSL policy.
func (s *SstpService) opensslConfPath(inboundId int) string {
	return fmt.Sprintf("%s/openssl.cnf", s.configDir(inboundId))
}

// sstpOpenSSLConf is a permissive OpenSSL config. It removes any host-imposed TLS
// floor — Ubuntu/Debian ship MinProtocol=TLSv1.2 in /etc/ssl/openssl.cnf, which the
// bundled OpenSSL would otherwise read and use to veto old-Windows TLS 1.0 — and
// lowers the security level to 1 so legacy SSTP clients (Vista/7, TLS 1.0 +
// AES-CBC-SHA) can complete the handshake. No [provider] section: the default
// provider auto-loads, and MS-CHAP uses low-level MD4 (no legacy provider needed;
// MPPE is disabled for SSTP anyway), so this can't break auth.
const sstpOpenSSLConf = `# Auto-generated by pxpanel (SSTP) — do not edit.
openssl_conf = pxpanel_init

[pxpanel_init]
providers = pxpanel_providers
ssl_conf = pxpanel_ssl

# Activate the default provider explicitly — this mirrors the distro openssl.cnf
# (e.g. Ubuntu) that SSTP already works with, so replacing OPENSSL_CONF changes
# ONLY the TLS floor, not which crypto is available. MS-CHAP needs no legacy
# provider (it uses low-level MD4; MPPE is disabled for SSTP).
[pxpanel_providers]
default = pxpanel_default_sect

[pxpanel_default_sect]
activate = 1

[pxpanel_ssl]
system_default = pxpanel_ssl_defaults

[pxpanel_ssl_defaults]
MinProtocol = TLSv1
CipherString = DEFAULT@SECLEVEL=1
`

// generateServerConfig writes the accel-ppp.conf for one inbound.
func (s *SstpService) generateServerConfig(inbound *model.Inbound) error {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return err
	}

	dir := s.configDir(inbound.Id)
	// Best-effort: a failed create surfaces immediately in the config write below.
	_ = os.MkdirAll(dir, 0o755)

	conf := coreconfig.ApplyCoreConfigOverride("sstp", inbound.Id, "accel-ppp.conf",
		s.buildServerConfig(inbound, settings))
	if err := s.writeFile(fmt.Sprintf("%s/accel-ppp.conf", dir), conf); err != nil {
		return err
	}
	// Permissive OpenSSL config, pointed at via OPENSSL_CONF when the daemon starts,
	// so old-Windows TLS 1.0 isn't vetoed by the host's system OpenSSL policy.
	return s.writeFile(s.opensslConfPath(inbound.Id), sstpOpenSSLConf)
}

// buildServerConfig returns the accel-ppp.conf content for an inbound. The exact
// section/key syntax is verified against the accel-ppp docs (sstp/radius/ppp/log/
// modules configuration pages).
func (s *SstpService) buildServerConfig(inbound *model.Inbound, settings *sstpSettings) string {
	id := inbound.Id
	dir := s.configDir(id)
	port := inbound.Port
	if port == 0 {
		port = 443
	}

	mtu := settings.Mtu
	if mtu == 0 {
		mtu = 1400
	}

	dns1 := settings.Dns1
	if dns1 == "" {
		dns1 = "8.8.8.8"
	}
	dns2 := settings.Dns2
	if dns2 == "" {
		dns2 = "8.8.4.4"
	}

	certPath, keyPath := s.certPaths(settings, id)
	gwIP := s.gatewayIP(inbound, settings)
	secret := s.getRadiusSecret()

	var b strings.Builder
	b.WriteString("# Auto-generated by pxpanel SSTP (accel-ppp) service — do not edit\n\n")

	// Module order matters: `radius` MUST precede `ippool` so a RADIUS
	// Framed-IP-Address wins over any local pool address — that per-device pinning
	// is what makes User Limit (distinct block IP per device) work, exactly like
	// pptp/ocserv. ippool stays loaded only as an inert fallback (our RADIUS always
	// returns Framed-IP for SSTP).
	b.WriteString("[modules]\n")
	b.WriteString("log_file\n")
	b.WriteString("sstp\n")
	b.WriteString("auth_mschap_v2\n")
	b.WriteString("auth_mschap_v1\n")
	b.WriteString("radius\n")
	b.WriteString("ippool\n\n")

	b.WriteString("[core]\n")
	b.WriteString("thread-count=4\n\n")

	b.WriteString("[log]\n")
	fmt.Fprintf(&b, "log-file=%s/accel.log\n", dir)
	b.WriteString("level=3\n\n")

	// accept=ssl: terminate MS-SSTP over HTTPS natively (not behind an SSL proxy).
	b.WriteString("[sstp]\n")
	b.WriteString("verbose=1\n")
	b.WriteString("accept=ssl\n")
	fmt.Fprintf(&b, "ssl-pemfile=%s\n", certPath)
	fmt.Fprintf(&b, "ssl-keyfile=%s\n", keyPath)
	// Widen TLS for maximum device coverage: accept TLS 1.0 through 1.3 and drop the
	// OpenSSL security level to 1 so legacy Windows SSTP clients (Vista / 7, which
	// negotiate TLS 1.0 with AES-CBC-SHA ciphers) can still connect alongside modern
	// Windows. SSTP already runs inside TLS, so this only affects the outer handshake;
	// the far bigger real-world gate is a cert stock Windows trusts (use a real ACME
	// cert — see deploy.sh). Token spellings verified against the bundled libsstp.so.
	b.WriteString("ssl-protocol=tls1,tls1.1,tls1.2,tls1.3\n")
	b.WriteString("ssl-ciphers=DEFAULT@SECLEVEL=1\n")
	fmt.Fprintf(&b, "port=%d\n", port)
	fmt.Fprintf(&b, "ppp-max-mtu=%d\n\n", mtu)

	// mppe=deny: SSTP already runs inside TLS, so link-layer MPPE is redundant.
	b.WriteString("[ppp]\n")
	b.WriteString("verbose=1\n")
	fmt.Fprintf(&b, "mtu=%d\n", mtu)
	fmt.Fprintf(&b, "mru=%d\n", mtu)
	b.WriteString("mppe=deny\n")
	b.WriteString("ipv4=require\n")
	b.WriteString("lcp-echo-interval=30\n")
	b.WriteString("lcp-echo-failure=3\n\n")

	// [dns] pushes the resolver to clients via IPCP. WITHOUT it accel-ppp sends NO DNS, so
	// Windows/iOS SSTP clients keep their pre-tunnel DNS — unreachable once the tunnel owns
	// the default route → domain lookups fail while direct-IP connections still work
	// (the exact "connect but no internet for anything with a hostname" symptom).
	b.WriteString("[dns]\n")
	fmt.Fprintf(&b, "dns1=%s\n", dns1)
	if dns2 != "" {
		fmt.Fprintf(&b, "dns2=%s\n", dns2)
	}
	b.WriteString("\n")

	// [client-ip-range] is MANDATORY for accel-ppp's sstp module and gates the CLIENT'S
	// SOURCE address at connect time (verified on the VM: without it, or with a range not
	// covering the caller, every connection is dropped pre-auth with "IP is out of
	// client-ip-range"). A public SSTP server accepts clients from anywhere, so allow all
	// sources with 0.0.0.0/0 (accel-ppp reports this as "iprange module disabled"). The
	// actual per-device tunnel IP is still pinned by the RADIUS Framed-IP-Address.
	b.WriteString("[client-ip-range]\n")
	b.WriteString("0.0.0.0/0\n\n")

	// Per-inbound NAS-Identifier ("sstp-<id>"): accel-pppd runs one instance per
	// inbound (like ocserv → "openconnect-<id>"), so the RADIUS server resolves the
	// exact inbound directly. gw-ip-address is the local ppp endpoint; the client
	// IP is the RADIUS Framed-IP-Address.
	b.WriteString("[radius]\n")
	b.WriteString("verbose=1\n")
	fmt.Fprintf(&b, "dictionary=%s\n", accelDictPath)
	fmt.Fprintf(&b, "nas-identifier=sstp-%d\n", id)
	b.WriteString("nas-ip-address=127.0.0.1\n")
	fmt.Fprintf(&b, "gw-ip-address=%s\n", gwIP)
	fmt.Fprintf(&b, "server=127.0.0.1,%s,auth-port=1812,acct-port=1813,req-limit=0\n", secret)
	b.WriteString("acct-interim-interval=60\n\n")

	// Loopback TCP control interface for accel-cmd (session eviction / disable).
	b.WriteString("[cli]\n")
	fmt.Fprintf(&b, "tcp=127.0.0.1:%d\n", sstpCliPort(inbound))

	return b.String()
}

// writeCertFiles writes the content-mode server cert/key (and optional CA) to the
// inbound's config dir. In path mode accel-pppd reads the operator's own files, so
// nothing is written here.
func (s *SstpService) writeCertFiles(inbound *model.Inbound) error {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return err
	}
	if settings.TlsUseFile {
		return nil
	}

	dir := s.configDir(inbound.Id)
	// Best-effort: a failed create surfaces immediately in the cert write below.
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

// steeringSource is this protocol's registration in the shared nftables ruleset
// (see the nftables steering registry for why the gathering moved). The enabled
// SSTP inbounds map 1:1 to vpn-ui's per-protocol loops in ApplyNftRules: PPP-family
// client /24s in 10.5.x, accel-ppp terminates SSTP+PPP in userspace and assigns
// each client an in-range peer IP, so the same source-/24 steering redirects its
// traffic into Xray via the inbound's dokodemo port. SSTP supplies no extra
// input/postrouting rules.
func (s *SstpService) steeringSource() nftables.SteeringSource {
	return nftables.SteeringSource{
		Nets: func() []nftables.SteeringNet {
			inbounds, err := s.GetSstpInbounds()
			if err != nil {
				return nil
			}
			var nets []nftables.SteeringNet
			for _, inbound := range inbounds {
				if !inbound.Enable {
					continue
				}
				st, err := s.parseSettings(inbound)
				if err != nil {
					continue
				}
				nets = append(nets, nftables.SteeringNet{
					Subnets:    nftables.SubnetCIDRs(s.GetSubnetsForInbound(inbound)),
					C2C:        st.ClientToClient,
					Cross:      st.CrossInbound,
					TproxyPort: s.GetTproxyPort(inbound),
				})
			}
			return nets
		},
	}
}

// SetupRouting prepares the host so SSTP client traffic is TPROXY-redirected into
// Xray instead of NAT'd to the internet. Shares the fwmark policy route and
// nftables regeneration with the other VPN protocols. SSTP is PPP-family, so it
// needs ppp_generic (already provisioned for l2tp/pptp).
func (s *SstpService) SetupRouting() error {
	_ = s.runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")

	_ = s.runCmd("modprobe", "ppp_generic")
	_ = s.runCmd("modprobe", "nf_tproxy_ipv4")

	nftables.EnsureVpnPolicyRoute(s.runCmd)

	svc := s.nft
	if svc == nil {
		svc = &nftables.Service{}
	}
	return svc.ApplyNftRules(nftables.GatherRulesInput())
}

// RestartServices launches (or stops) an accel-pppd child process per inbound. An
// inbound with no usable server cert yet is skipped (the sstp module refuses to
// start without one). Managed accel-pppd processes with no corresponding enabled
// inbound are stopped. Mirrors OcservService.RestartServices.
func (s *SstpService) RestartServices() error {
	procmgr.MigrateFromSystemd()

	inbounds, err := s.GetSstpInbounds()
	if err != nil {
		return err
	}

	bin := s.accelPppdBinaryPath()
	desired := map[string]bool{}

	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil {
			log.Warning("SSTP: skipping inbound", inbound.Id, err)
			continue
		}
		if !s.hasUsableCert(settings, inbound.Id) {
			log.Warning("SSTP: inbound", inbound.Id, "has no TLS cert yet — generate a self-signed cert or set a cert path")
			continue
		}
		dir := s.configDir(inbound.Id)
		name := sstpProcName(inbound.Id)
		desired[name] = true
		confPath := fmt.Sprintf("%s/accel-ppp.conf", dir)
		// accel-pppd runs in the foreground unless -d is given, so procMgr can
		// supervise it directly (like ocserv -f). It reads its whole RADIUS/TLS
		// config from the file; no pppdEnv (its libs resolve via the bundle wrapper).
		args := []string{"-c", confPath}
		// Point the bundled OpenSSL at our permissive openssl.cnf so TLS 1.0 (old
		// Windows) is honored regardless of the host's system OpenSSL policy. The
		// bundle wrapper still sets OPENSSL_MODULES; this only adds OPENSSL_CONF.
		env := []string{"OPENSSL_CONF=" + s.opensslConfPath(inbound.Id)}
		if err := procmgr.GetProcManager().Start(name, bin, args, env, dir); err != nil {
			log.Warning("SSTP: failed to start", name, err)
		}
	}

	for _, name := range procmgr.GetProcManager().NamesWithPrefix("sstp-server-") {
		if !desired[name] {
			_ = procmgr.GetProcManager().Stop(name)
		}
	}
	return nil
}

// StopServices stops all SSTP child processes.
func (s *SstpService) StopServices() error {
	procmgr.GetProcManager().StopByPrefix("sstp-server-")
	return nil
}

// accelCmd runs accel-cmd against a specific inbound's loopback control port.
// Best-effort; a no-op-ish error is returned if the daemon/socket isn't up.
func (s *SstpService) accelCmd(inbound *model.Inbound, args ...string) error {
	full := append([]string{"-H", "127.0.0.1", "-p", strconv.Itoa(sstpCliPort(inbound))}, args...)
	return s.runCmd(procmgr.DaemonBin("accel-cmd"), full...)
}

// KillClientIP force-disconnects the accel-ppp session holding tunnel IP `ip` on
// the given inbound, via `accel-cmd terminate ip <ip>`. It is the SSTP analogue of
// killPPPByIP/killOcservByIP used by the User-Limit "accept" eviction in radius.go:
// accel-ppp is a single daemon (no per-connection pppd to kill), so the session is
// torn down through its control interface. Best-effort; any error is returned but
// callers treat it as advisory.
func (s *SstpService) KillClientIP(inbound *model.Inbound, ip string) error {
	if strings.TrimSpace(ip) == "" {
		return nil
	}
	return s.accelCmd(inbound, "terminate", "ip", ip)
}

// killClientUser disconnects a user's active session(s) on an inbound via
// `accel-cmd terminate username <u>` (whole-account teardown for disable/expiry).
func (s *SstpService) killClientUser(inbound *model.Inbound, username string) {
	if strings.TrimSpace(username) == "" {
		return
	}
	_ = s.accelCmd(inbound, "terminate", "username", username)
}

// KillDisabledSessions disconnects active SSTP sessions for clients that are
// disabled (in settings or via the client_traffics quota/expiry table).
func (s *SstpService) KillDisabledSessions() {
	inbounds, err := s.GetSstpInbounds()
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
				s.killClientUser(inbound, client.ID)
			}
		}
	}
}

// DisableClients disconnects the given client emails' active sessions.
func (s *SstpService) DisableClients(emails []string) {
	if len(emails) == 0 {
		return
	}
	emailSet := make(map[string]bool, len(emails))
	for _, e := range emails {
		emailSet[e] = true
	}

	inbounds, err := s.GetSstpInbounds()
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
				s.killClientUser(inbound, client.ID)
			}
		}
	}
}

// getDisabledEmails returns the set of client emails disabled in client_traffics
// (traffic limit or expiry).
func (s *SstpService) getDisabledEmails() map[string]bool {
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

// sstpInboundForIP returns the SSTP inbound that owns tunnel IP `ip` — the inbound
// whose panel-managed /24 range covers it — so an accel-cmd eviction reaches that
// inbound's own accel-pppd control socket. PORT NOTE: vpn-ui kept this next to the
// RADIUS server (radius.go:sstpInboundForIP); it moved here with the eviction
// registration, since the accel-pppd is per-inbound and the IP's /24 says which
// daemon holds the session. nil when no SSTP inbound claims the IP.
func sstpInboundForIP(ip string) *model.Inbound {
	dot := strings.LastIndexByte(ip, '.')
	if dot < 0 {
		return nil
	}
	prefix := ip[:dot] // "10.5.3.7" -> "10.5.3"
	var sstpSvc SstpService
	inbounds, err := sstpSvc.GetSstpInbounds()
	if err != nil {
		return nil
	}
	for _, inbound := range inbounds {
		for _, sub := range sstpSvc.GetSubnetsForInbound(inbound) {
			if sub == prefix {
				return inbound
			}
		}
	}
	return nil
}

// serverIP returns the server's primary (default-route source) IP. PORT NOTE:
// vpn-ui reached OcservService.getServerIP (web/service/openconnect.go) — the
// OpenConnect wave owns that service here, and the detector is identical to
// Ikev2Service.getServerIP, so it is duplicated locally instead of imported.
func serverIP() string {
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

// GenerateSelfSignedCert generates a self-signed server certificate + key for
// SSTP. accel-ppp only needs a server cert the client trusts; a single self-issued
// ECDSA P-384 cert suffices. Returns PEM strings: serverCert, serverKey. (Identical
// to OcservService.GenerateSelfSignedCert; the Windows SSTP client's stricter trust
// requirements are surfaced by a warning in the UI, not changed here.)
//
// serverAddr names the gateway and becomes the CN and the SANs; empty means the
// address this host egresses with. See OcservService.GenerateSelfSignedCert for why
// a certificate with no subjectAltName is not verifiable by any client, this
// panel's own SSTP outbound included.
func (s *SstpService) GenerateSelfSignedCert(serverAddr string) (string, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate server key: %w", err)
	}

	host := strings.TrimSpace(serverAddr)
	if host == "" {
		host = serverIP()
	}
	cn := host
	if cn == "" {
		cn = "pxpanel SSTP Server"
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

func (s *SstpService) writeFile(path, content string) error {
	return s.writeFileMode(path, content, 0o644)
}

func (s *SstpService) writeFileMode(path, content string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

func (s *SstpService) runCmd(name string, args ...string) error {
	cmd := exec.CommandContext(context.Background(), name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Debugf("SSTP: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}
