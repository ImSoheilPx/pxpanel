// Package awg is vpn-ui's AmneziaWG service (web/service/awg.go +
// amneziawg_dkms.go + the vendored awgsrc kernel-module tree) ported verbatim
// into pxpanel, module import rewritten mhsanaei/3x-ui/v2 → ImSoheilPx/pxpanel
// and the web/service cross-calls re-pointed at the internal/vpn foundation
// seams (see wgc's package doc for the shared table; the awg-specific ones):
//
//	wgctrl "github.com/Jipok/wgctrl-go"  → unchanged (the AWG-capable fork,
//	                                     now a direct requirement of this module)
//	interfacePrefix                      → pxpanel-awg (per go side; the
//	                                     manifest's AwgOwnedName shape matches)
//	awgBuildDir                          → /usr/src/pxpanel-amneziawg (product
//	                                     rename of /usr/src/vpn-ui-amneziawg)
//	awgsrc                               → internal/vpn/awg/awgsrc (same embed)
//	ProvisionStep / pm.installPackage /  → the pkgmgr package's exported
//	detectPackageManager /                  surface (hostops wrappers)
//	moduleAvailable / runningKernel /
//	osReleaseField / distroPretty /
//	isUbuntu / debKernelArch /
//	fileExists / commandExists
//	ensureAwgObfuscation's setRawInt /
//	userLimitPtrFromRaw / setRawString   → vpn.SetRawInt / UserLimitPtrFromRaw /
//	                                     SetRawString
//
// Deferred to later waves (NOT ported here):
//   - web/service/vpnout_awg.go — the awg CLIENT side; vpnout family wave.
//   - The core-catalog call site that runs ensureAmneziawg during Core
//     Settings provisioning (vpn-ui corecatalog.go), and removeAmneziawgModule's
//     uninstall call site — both land with the core wave; both entry points are
//     exported from dkms.go here.
//   - The controller endpoint (GET /:id/awg-configs) and the config modal.
//
// TODO(controllers wave): wire InitAwg/GenerateAllConfigs/RestartServices into
// the server lifecycle, register the rbridge sweeper adapter at wire-up, and
// call ReconcileAllKeys on the inbound-save path.
//
// AwgService manages "AmneziaWG" , obfuscated WireGuard on the in-kernel `amneziawg`
// module, driven natively from Go via the AmneziaWG-aware wgctrl fork (netlink). It is a
// sibling of WgcService ("wg-c"): the account/IP/limit/accounting model is identical
// (gateway model, one keypair per account, rbridge-swept), so this reuses the shared
// helpers (nextPow2, allowedIPsKey, WgcEffectiveK, ComputeVpnClientIP, PppSubnetsOrDefault,
// VpnBlock, VpnAccountBlock, the raw-JSON helpers). The differences from wg-c are: (1) the
// `amneziawg` kernel module + link kind (a separate, DKMS-built out-of-tree module, base 8
// -> 10.8/16); (2) the AWG 1.0 obfuscation params (Jc/Jmin/Jmax/S1/S2/H1-H4) rendered into
// [Interface] and pushed to the device; (3) the wgctrl fork instead of upstream wgctrl.
// Magic headers H1-H4 are minted server-side.
package awg

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"math/bits"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/logger"
	"github.com/ImSoheilPx/pxpanel/internal/util/json_util"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/nftables"
	pkgmgr "github.com/ImSoheilPx/pxpanel/internal/vpn/pkgmgr"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/wgc"
	"github.com/ImSoheilPx/pxpanel/internal/xray"

	wgctrl "github.com/Jipok/wgctrl-go"
	"github.com/Jipok/wgctrl-go/wgtypes"
	"github.com/vishvananda/netlink"

	vpnrange "github.com/ImSoheilPx/pxpanel/internal/vpn/range"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/rbridge"
)

// AwgService manages the awg data plane. See the package comment.
type AwgService struct {
	nftService nftables.Service

	mu        sync.Mutex
	firstSeen map[string]time.Time // deviceKey -> first-seen handshake (oldest-first eviction)
	lastObfs  map[string]string    // iface -> last-applied obfuscation signature (force re-apply on edit)
}

const (
	// awgIfacePrefix names the per-inbound kernel interfaces (pxpanel-awg<id>).
	// PORT NOTE: pxpanel's interfacePrefix (task-mandated rename of vpn-ui's
	// "awg", matching amneziawgkern); short enough that pxpanel-awg<id> stays
	// within the 15-char IFNAMSIZ limit for realistic inbound ids.
	awgIfacePrefix = "pxpanel-awg"
	// amneziawgModule is the out-of-tree AmneziaWG kernel module (built via DKMS, base 8).
	amneziawgModule = "amneziawg"
	// amneziawgLinkKind is the rtnetlink link kind the module registers (ip link add type amneziawg).
	amneziawgLinkKind = "amneziawg"
	// wgDefaultMTU mirrors wg-c's standard tunnel MTU.
	wgDefaultMTU = 1420
	// wgHandshakeStale mirrors wg-c's liveness window.
	wgHandshakeStale = 180 * time.Second
)

func init() {
	// nftables steering (vpn-ui: the awg block of NftService.ApplyNftRules).
	nftables.RegisterSteeringSource("awg", nftables.SteeringSource{Nets: awgSteeringNets})
	// Session→inbound attribution for the RADIUS server (vpn-ui radius.go read
	// AwgService.GetSubnetsForInbound directly).
	vpn.RegisterSubnetResolver("awg", func(inbound *model.Inbound) []string {
		if inbound == nil {
			return nil
		}
		return (&AwgService{}).GetSubnetsForInbound(inbound)
	})
}

// awgSteeringNets is the SteeringSource the shared ruleset builder consumes.
func awgSteeringNets() []nftables.SteeringNet {
	db := vpn.DB()
	if db == nil {
		return nil
	}
	var inbounds []*model.Inbound
	if err := db.Model(model.Inbound{}).Where("protocol = ?", "awg").Find(&inbounds).Error; err != nil {
		return nil
	}
	var nets []nftables.SteeringNet
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := (&AwgService{}).parseSettings(inbound)
		if err != nil {
			continue
		}
		nets = append(nets, nftables.SteeringNet{
			Subnets:    awgCIDRs(inbound, settings),
			C2C:        settings.ClientToClient,
			Cross:      settings.CrossInbound,
			TproxyPort: (&AwgService{}).GetTproxyPort(inbound),
		})
	}
	return nets
}

// awgSettings is the AmneziaWG slice of an inbound's Settings JSON. Clones wgcSettings and
// adds the AWG 1.0 obfuscation parameters. All obfuscation params must match between server
// and client EXCEPT Jc/Jmin/Jmax (junk counts may differ per peer). Magic headers H1-H4 are
// stored as strings (the AmneziaWG 2.0 form allows ranges like "5-9"; 1.0 uses single values).
type awgSettings struct {
	ServerPrivKey string `json:"serverPrivKey"`
	ServerPubKey  string `json:"serverPubKey"`
	PskEnable     bool   `json:"pskEnable"`

	Dns1 string `json:"dns1"`
	Dns2 string `json:"dns2"`
	Mtu  int    `json:"mtu"`

	// AWG 1.0 obfuscation parameters (per-inbound, shared by all this inbound's clients).
	Jc   *int   `json:"jc"`
	Jmin *int   `json:"jmin"`
	Jmax *int   `json:"jmax"`
	S1   *int   `json:"s1"`
	S2   *int   `json:"s2"`
	H1   string `json:"h1"`
	H2   string `json:"h2"`
	H3   string `json:"h3"`
	H4   string `json:"h4"`

	ClientToClient    bool               `json:"clientToClient"`
	CrossInbound      bool               `json:"crossInbound"`
	UserLimit         *int               `json:"userLimit"`
	UserLimitStrategy string             `json:"userLimitStrategy"`
	IpRanges          []string           `json:"ipRanges"`
	ExternalProxy     []awgExternalProxy `json:"externalProxy"`
	Clients           []awgClient        `json:"clients"`
}

// awgExternalProxy is one alternate Endpoint written into the generated client config + QR.
type awgExternalProxy struct {
	Dest   string `json:"dest"`
	Port   int    `json:"port"`
	Remark string `json:"remark"`
}

// awgDevice is ONE device slot of an account: its own keypair (and optional preshared key)
// and, derived from its index, its own /32 out of the account's block.
//
// Per-device keypairs are REQUIRED, not a nicety. WireGuard/AmneziaWG identifies a peer by
// its public key and tracks a single endpoint per peer, so two devices sharing one keypair
// cannot be online at once: whichever handshakes last steals the tunnel and the other goes
// dark. Handing out one config per account also hands both devices the same Address, so
// they present the same tunnel IP. K device slots => K keypairs => K configs => K distinct
// IPs, which is what makes "User Limit K" actually mean K simultaneous devices.
type awgDevice struct {
	PrivKey string `json:"privKey"`
	PubKey  string `json:"pubKey"`
	Psk     string `json:"psk"`
}

// awgClient is one AmneziaWG account. Identity is Email; each device's public key is its
// credential. Devices holds one entry per device slot (sized to the inbound's User Limit).
// The legacy top-level PrivKey/PubKey/Psk are the pre-per-device shape and are read as
// device 0 when Devices is empty, so an inbound created before this change keeps working.
type awgClient struct {
	Email   string      `json:"email"`
	Enable  bool        `json:"enable"`
	PrivKey string      `json:"privKey"`
	PubKey  string      `json:"pubKey"`
	Psk     string      `json:"psk"`
	Devices []awgDevice `json:"devices"`
	Slot    *int        `json:"slot"` // address-pool slot; nil = fall back to list index
}

// deviceList returns the account's device slots, seeding from the legacy single-keypair
// fields when the per-device array has not been written yet.
func (c *awgClient) deviceList() []awgDevice {
	if len(c.Devices) > 0 {
		return c.Devices
	}
	if strings.TrimSpace(c.PubKey) != "" {
		return []awgDevice{{PrivKey: c.PrivKey, PubKey: c.PubKey, Psk: c.Psk}}
	}
	return nil
}

func (o *awgSettings) effectiveRanges() []string { return o.IpRanges }

func (o *awgSettings) mtu() int {
	if o.Mtu > 0 {
		return o.Mtu
	}
	return wgDefaultMTU
}

// awgObfs is the resolved (defaults applied) AWG 1.0 obfuscation parameter set.
type awgObfs struct {
	Jc, Jmin, Jmax, S1, S2 int
	H1, H2, H3, H4         string
}

// resolveObfs applies recommended defaults for any unset numeric params (magic headers are
// minted by ReconcileKeys, so they are normally present).
func (o *awgSettings) resolveObfs() awgObfs {
	pick := func(p *int, def int) int {
		if p != nil {
			return *p
		}
		return def
	}
	return awgObfs{
		Jc:   pick(o.Jc, 4),
		Jmin: pick(o.Jmin, 8),
		Jmax: pick(o.Jmax, 80),
		S1:   pick(o.S1, 77),
		S2:   pick(o.S2, 90),
		H1:   o.H1, H2: o.H2, H3: o.H3, H4: o.H4,
	}
}

func (b awgObfs) sig() string {
	return fmt.Sprintf("%d|%d|%d|%d|%d|%s|%s|%s|%s", b.Jc, b.Jmin, b.Jmax, b.S1, b.S2, b.H1, b.H2, b.H3, b.H4)
}

// apply writes the obfuscation params into a wgtypes.Config (only when H1-H4 are present).
func (b awgObfs) apply(cfg *wgtypes.Config) {
	jc, jmin, jmax, s1, s2 := b.Jc, b.Jmin, b.Jmax, b.S1, b.S2
	cfg.Jc, cfg.Jmin, cfg.Jmax = &jc, &jmin, &jmax
	cfg.S1, cfg.S2 = &s1, &s2
	if b.H1 != "" {
		h1, h2, h3, h4 := b.H1, b.H2, b.H3, b.H4
		cfg.H1, cfg.H2, cfg.H3, cfg.H4 = &h1, &h2, &h3, &h4
	}
}

// awgIfaceName returns the kernel interface name for an inbound.
func awgIfaceName(id int) string { return fmt.Sprintf("%s%d", awgIfacePrefix, id) }

func (s *AwgService) GetAwgInbounds() ([]*model.Inbound, error) {
	db := vpn.DB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Where("protocol = ?", "awg").Find(&inbounds).Error
	return inbounds, err
}

func (s *AwgService) parseSettings(inbound *model.Inbound) (*awgSettings, error) {
	settings := &awgSettings{}
	err := json.Unmarshal([]byte(inbound.Settings), settings)
	return settings, err
}

// awgBlockFor returns an inbound's client block network + prefix in the 10.8 /16.
func awgBlockFor(inbound *model.Inbound, settings *awgSettings) (net.IP, int) {
	return vpnrange.VpnBlock(settings.effectiveRanges(), vpnrange.ProtocolBase("awg"), inbound.Id)
}

// awgCIDRs returns the single block CIDR for an AmneziaWG inbound (10.8.x).
// (vpn-ui nftables.go:awgCIDRs.)
func awgCIDRs(inbound *model.Inbound, settings *awgSettings) []string {
	n, p := awgBlockFor(inbound, settings)
	return []string{fmt.Sprintf("%s/%d", n.String(), p)}
}

func (s *AwgService) GetSubnetForInbound(inbound *model.Inbound) string {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		settings = &awgSettings{}
	}
	netAddr, prefix := awgBlockFor(inbound, settings)
	return fmt.Sprintf("%s/%d", netAddr.String(), prefix)
}

func (s *AwgService) GetSubnetsForInbound(inbound *model.Inbound) []string {
	return []string{s.GetSubnetForInbound(inbound)}
}

// GetTproxyPort returns the deterministic TPROXY/dokodemo port (shared 12300+id).
func (s *AwgService) GetTproxyPort(inbound *model.Inbound) int {
	return 12300 + inbound.Id
}

// GetDokodemoConfig builds the paired dokodemo-door inbound feeding TPROXY traffic into Xray.
func (s *AwgService) GetDokodemoConfig(inbound *model.Inbound) *xray.InboundConfig {
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

// awgAccountBlock mirrors wgcAccountBlock in the 10.8 /16 (gateway model, block sized to K).
// The slot comes from the account (model.Client.Slot), not from its position in clients[]:
// see wgcAccountBlock for why that distinction is load-bearing here.
func (s *AwgService) awgAccountBlock(inbound *model.Inbound, settings *awgSettings, accountSlot int) (string, int) {
	ranges := settings.effectiveRanges()
	k := vpnrange.WgcEffectiveK(settings.UserLimit)
	if k <= 1 {
		if ip := vpnrange.ComputeVpnClientIP(ranges, inbound.Id, accountSlot, "awg"); ip != nil {
			return ip.String(), 32
		}
		return "", 0
	}
	bs := nextPow2(k)
	subnets := vpnrange.PppSubnetsOrDefault(ranges, "awg", inbound.Id)
	subnet, hostBase, ok := vpnrange.VpnAccountBlock(subnets, accountSlot, bs)
	if !ok {
		return "", 0
	}
	return fmt.Sprintf("%s.%d", subnet, hostBase), 32 - bits.Len(uint(bs)-1)
}

// awgDeviceIPs returns the account's K per-device tunnel IPs, in slot order. Device d gets
// the d-th address of the account's block, so the block CIDR used for routing/accounting
// still covers every device. K<=1 collapses to the single legacy address.
func (s *AwgService) awgDeviceIPs(inbound *model.Inbound, settings *awgSettings, accountSlot int) []string {
	ranges := settings.effectiveRanges()
	k := vpnrange.WgcEffectiveK(settings.UserLimit)
	if k <= 1 {
		if ip := vpnrange.ComputeVpnClientIP(ranges, inbound.Id, accountSlot, "awg"); ip != nil {
			return []string{ip.String()}
		}
		return nil
	}
	bs := nextPow2(k)
	subnets := vpnrange.PppSubnetsOrDefault(ranges, "awg", inbound.Id)
	return vpnrange.VpnAccountDeviceIPs(subnets, accountSlot, bs)
}

// nextPow2 returns the smallest power of two >= n (>=1). (vpn-ui wgc.go; the range
// package keeps the same fold unexported, so the protocol copy stays here.)
func nextPow2(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

func (s *AwgService) awgAccountCIDR(inbound *model.Inbound, settings *awgSettings, accountSlot int) string {
	ip, prefix := s.awgAccountBlock(inbound, settings, accountSlot)
	if ip == "" {
		return ""
	}
	return fmt.Sprintf("%s/%d", ip, prefix)
}

func (s *AwgService) disabledEmails() map[string]bool {
	disabled := make(map[string]bool)
	db := vpn.DB()
	if db == nil {
		return disabled
	}
	var emails []string
	db.Model(&xray.ClientTraffic{}).Where("enable = ?", false).Pluck("email", &emails)
	for _, e := range emails {
		disabled[e] = true
	}
	return disabled
}

// InitAwg brings AmneziaWG up on panel startup.
func (s *AwgService) InitAwg() {
	inbounds, err := s.GetAwgInbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}
	logger.Info("AmneziaWG: initializing services for", len(inbounds), "inbound(s)")
	s.ReconcileAllKeys()
	if err := s.GenerateAllConfigs(); err != nil {
		logger.Warning("AmneziaWG: failed to generate configs:", err)
		return
	}
	if err := s.SetupRouting(); err != nil {
		logger.Warning("AmneziaWG: failed to setup routing:", err)
	}
}

// GenerateAllConfigs reconciles every kernel pxpanel-awg<id> interface to DB state, exactly
// like WgcService.GenerateAllConfigs but with the obfuscation parameters applied at the
// device.
func (s *AwgService) GenerateAllConfigs() error {
	inbounds, err := s.GetAwgInbounds()
	if err != nil {
		return err
	}

	wanted := make(map[string]bool)
	if len(inbounds) > 0 {
		disabled := s.disabledEmails()
		cl, err := wgctrl.New()
		if err != nil {
			return fmt.Errorf("wgctrl: %w", err)
		}
		defer cl.Close()

		for _, inbound := range inbounds {
			if !inbound.Enable {
				continue
			}
			// Claimed before the reconcile is attempted; see WgcService.GenerateAllConfigs
			// for why a failed reconcile must not hand the interface to removeStaleLinks.
			wanted[awgIfaceName(inbound.Id)] = true

			settings, err := s.parseSettings(inbound)
			if err != nil {
				logger.Warning("AmneziaWG: skipping inbound", inbound.Id, err)
				continue
			}
			if strings.TrimSpace(settings.ServerPrivKey) == "" {
				logger.Warning("AmneziaWG: inbound", inbound.Id, "has no server key yet")
				continue
			}
			priv, err := wgtypes.ParseKey(settings.ServerPrivKey)
			if err != nil {
				logger.Warning("AmneziaWG: inbound", inbound.Id, "bad server key:", err)
				continue
			}
			iface := awgIfaceName(inbound.Id)
			blockNet, prefix := awgBlockFor(inbound, settings)
			if err := s.ensureLink(iface, settings.mtu(), blockNet, prefix); err != nil {
				logger.Warning("AmneziaWG: interface setup failed for", iface, err)
				continue
			}
			port := inbound.Port
			desiredPeers := s.buildPeers(inbound, settings, disabled)
			if err := s.reconcilePeers(cl, iface, &priv, port, settings.resolveObfs(), desiredPeers); err != nil {
				logger.Warning("AmneziaWG: configure device failed for", iface, err)
				continue
			}
		}
	}

	s.removeStaleLinks(wanted)
	return nil
}

// buildPeers returns one peer per enabled, non-disabled account (gateway model).
func (s *AwgService) buildPeers(inbound *model.Inbound, settings *awgSettings, disabled map[string]bool) []wgtypes.PeerConfig {
	var peers []wgtypes.PeerConfig
	for i, client := range settings.Clients {
		if client.Email == "" || !client.Enable || disabled[client.Email] {
			continue
		}
		ips := s.awgDeviceIPs(inbound, settings, vpnrange.SlotOr(client.Slot, i))
		// One peer PER DEVICE, each cryptokey-routed to its own /32. Pinning the peer to a
		// single address (not the whole block) is what stops one device from sourcing
		// another's IP, and gives every device an identity the data plane can tell apart.
		for d, dev := range client.deviceList() {
			if d >= len(ips) {
				break // more stored keypairs than the current User Limit allows
			}
			if strings.TrimSpace(dev.PubKey) == "" {
				continue
			}
			pub, err := wgtypes.ParseKey(dev.PubKey)
			if err != nil {
				continue
			}
			_, ipNet, err := net.ParseCIDR(ips[d] + "/32")
			if err != nil {
				continue
			}
			pc := wgtypes.PeerConfig{
				PublicKey:         pub,
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{*ipNet},
			}
			if settings.PskEnable && strings.TrimSpace(dev.Psk) != "" {
				if psk, err := wgtypes.ParseKey(dev.Psk); err == nil {
					pc.PresharedKey = &psk
				}
			}
			peers = append(peers, pc)
		}
	}
	return peers
}

// reconcilePeers applies the desired peer set + obfuscation to iface INCREMENTALLY (see
// WgcService.reconcilePeers). Obfuscation params + key + port are (re)applied when the device
// is fresh OR any of them changed (tracked via lastObfs), so an obfuscation edit takes effect
// without disturbing unrelated live sessions.
func (s *AwgService) reconcilePeers(cl *wgctrl.Client, iface string, priv *wgtypes.Key, port int, obfs awgObfs, desired []wgtypes.PeerConfig) error {
	dev, derr := cl.Device(iface)
	curAllowed := make(map[string]string)
	if derr == nil && dev != nil {
		for _, p := range dev.Peers {
			curAllowed[p.PublicKey.String()] = allowedIPsKey(p.AllowedIPs)
		}
	}

	desiredKeys := make(map[string]bool, len(desired))
	var ops []wgtypes.PeerConfig
	for _, pc := range desired {
		pk := pc.PublicKey.String()
		desiredKeys[pk] = true
		if cur, ok := curAllowed[pk]; !ok || cur != allowedIPsKey(pc.AllowedIPs) {
			ops = append(ops, pc)
		}
	}
	for pk := range curAllowed {
		if !desiredKeys[pk] {
			if key, err := wgtypes.ParseKey(pk); err == nil {
				ops = append(ops, wgtypes.PeerConfig{PublicKey: key, Remove: true})
			}
		}
	}

	needKey := derr != nil || dev == nil || dev.PublicKey != priv.PublicKey()
	needPort := derr != nil || dev == nil || dev.ListenPort != port
	needObfs := needKey || s.obfsChanged(iface, obfs)
	if !needKey && !needPort && !needObfs && len(ops) == 0 {
		return nil
	}
	cfg := wgtypes.Config{ReplacePeers: false, Peers: ops}
	if needKey {
		cfg.PrivateKey = priv
	}
	if needPort {
		cfg.ListenPort = &port
	}
	if needObfs {
		obfs.apply(&cfg)
	}
	if err := cl.ConfigureDevice(iface, cfg); err != nil {
		return err
	}
	s.rememberObfs(iface, obfs)
	return nil
}

func (s *AwgService) obfsChanged(iface string, obfs awgObfs) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastObfs[iface] != obfs.sig()
}

func (s *AwgService) rememberObfs(iface string, obfs awgObfs) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastObfs == nil {
		s.lastObfs = make(map[string]string)
	}
	s.lastObfs[iface] = obfs.sig()
}

// allowedIPsKey renders a peer's AllowedIPs as a stable, order-independent comparison key.
// (vpn-ui wgc.go:allowedIPsKey; the packages are separate here, so the awg copy lives with
// its reconcile loop.)
func allowedIPsKey(ips []net.IPNet) string {
	parts := make([]string, 0, len(ips))
	for _, n := range ips {
		parts = append(parts, n.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// ensureLink makes sure the kernel amneziawg interface exists (created via netlink as a
// generic link of kind "amneziawg"), has the block gateway address, and is up. A missing
// module surfaces as EOPNOTSUPP on link add so the caller can Warn (kernel-only, no fallback).
func (s *AwgService) ensureLink(iface string, mtu int, blockNet net.IP, prefix int) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		// See wg-c's ensureLink: claimed before the LinkAdd so ownership is a record
		// rather than an inference from the name.
		manifest.IfaceCreated(iface, "awg")
		la := netlink.NewLinkAttrs()
		la.Name = iface
		if mtu > 0 {
			la.MTU = mtu
		}
		if addErr := netlink.LinkAdd(&netlink.GenericLink{LinkAttrs: la, LinkType: amneziawgLinkKind}); addErr != nil {
			if vpn.ErrNotSupported(addErr) {
				return fmt.Errorf("amneziawg kernel module unavailable (run Core Settings setup to DKMS-build it): %w", addErr)
			}
			return addErr
		}
		if link, err = netlink.LinkByName(iface); err != nil {
			return err
		}
	} else if manifest.ForbidsDelete(manifest.KindIface, iface) {
		return fmt.Errorf("%s already exists and was not created by pxpanel; not touching it", iface)
	}
	if blockNet != nil {
		v4 := blockNet.To4()
		if v4 != nil {
			gw := net.IPv4(v4[0], v4[1], v4[2], v4[3]+1)
			addr := &netlink.Addr{IPNet: &net.IPNet{IP: gw, Mask: net.CIDRMask(prefix, 32)}}
			_ = netlink.AddrReplace(link, addr)
			// Same stale-address cleanup as wg-c; see dropForeignV4Addrs there.
			dropForeignV4Addrs(link, addr)
		}
	}
	return netlink.LinkSetUp(link)
}

// dropForeignV4Addrs removes every IPv4 address on link except keep. (vpn-ui
// wgc.go:dropForeignV4Addrs; the packages are separate here, so the copy travels with the
// ensureLink it serves.)
func dropForeignV4Addrs(link netlink.Link, keep *netlink.Addr) {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return
	}
	for i := range addrs {
		if addrs[i].IPNet == nil || addrs[i].IPNet.String() == keep.IPNet.String() {
			continue
		}
		if err := netlink.AddrDel(link, &addrs[i]); err != nil {
			logger.Debugf("AmneziaWG: could not remove stale address %s from %s: %v",
				addrs[i].IPNet, link.Attrs().Name, err)
		}
	}
}

// removeStaleLinks deletes every pxpanel-awg<id> interface not present in keep.
//
// Same fix as wg-c's: this matched a bare name prefix with no link-type check, so anything
// at all on the host called "awg<something>" was deleted on the next reconcile tick. See
// AwgOwnsLink in the manifest package for the ownership test that replaced it.
func (s *AwgService) removeStaleLinks(keep map[string]bool) {
	links, err := netlink.LinkList()
	if err != nil {
		return
	}
	for _, l := range links {
		name := l.Attrs().Name
		if keep[name] || !manifest.AwgOwnsLink(l) {
			continue
		}
		if err := netlink.LinkDel(l); err == nil {
			manifest.RemoveEntry(manifest.KindIface, name)
		}
	}
}

// SetupRouting shares the fwmark policy route + nftables regeneration with the other VPN
// protocols; best-effort modprobe of the amneziawg module.
func (s *AwgService) SetupRouting() error {
	_ = s.runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")
	_ = s.runCmd("modprobe", amneziawgModule)

	nftables.EnsureVpnPolicyRoute(s.runCmd)
	return s.nftService.ApplyNftRules(nftables.GatherRulesInput())
}

func (s *AwgService) RestartServices() error { return s.GenerateAllConfigs() }

func (s *AwgService) StopServices() error {
	s.removeStaleLinks(map[string]bool{})
	return nil
}

// AmneziawgAvailable reports whether the out-of-tree amneziawg module is usable.
func (s *AwgService) AmneziawgAvailable() bool {
	return pkgmgr.ModuleAvailable(amneziawgModule)
}

// AnyInterfaceUp reports whether at least one pxpanel-awg interface exists and is up.
//
// Ownership-checked like the stale-link sweep: a prefix match let an operator's own "awg0"
// make the status row claim the AmneziaWG core was running.
func (s *AwgService) AnyInterfaceUp() bool {
	links, err := netlink.LinkList()
	if err != nil {
		return false
	}
	for _, l := range links {
		if manifest.AwgOwnsLink(l) && l.Attrs().Flags&net.FlagUp != 0 {
			return true
		}
	}
	return false
}

// AwgClientConfig is an account's rendered client config (for the panel + QR).
type AwgClientConfig struct {
	DeviceIndex int    `json:"deviceIndex"`
	IP          string `json:"ip"`
	Remark      string `json:"remark"`
	PublicKey   string `json:"publicKey"`
	Config      string `json:"config"`
	// PreSharedKey is this device's own preshared key, empty when PSK is off. See
	// WgcClientConfig, same field for the same reason.
	PreSharedKey string `json:"psk"`
	// Host/Port mirror this config's own Endpoint= — see WgcClientConfig, same reason.
	Host string `json:"host"`
	Port int    `json:"port"`
}

func (o *awgSettings) dnsList() string {
	var parts []string
	if d := strings.TrimSpace(o.Dns1); d != "" {
		parts = append(parts, d)
	}
	if d := strings.TrimSpace(o.Dns2); d != "" {
		parts = append(parts, d)
	}
	if len(parts) == 0 {
		return "1.1.1.1, 1.0.0.1"
	}
	return strings.Join(parts, ", ")
}

// RenderClientConfigs returns the AmneziaWG .conf(s) for the account with the given email.
// Identical to WgcService.RenderClientConfigs plus the AWG 1.0 obfuscation lines in [Interface]
// (which a plain WireGuard client rejects , an AmneziaWG-aware client is required).
func (s *AwgService) RenderClientConfigs(inbound *model.Inbound, email, endpointHost string) ([]AwgClientConfig, error) {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return nil, err
	}
	obfs := settings.resolveObfs()

	type endpointTarget struct {
		host   string
		port   int
		remark string
	}
	var targets []endpointTarget
	for _, ep := range settings.ExternalProxy {
		dest := strings.TrimSpace(ep.Dest)
		if dest == "" {
			continue
		}
		port := ep.Port
		if port <= 0 {
			port = inbound.Port
		}
		targets = append(targets, endpointTarget{host: dest, port: port, remark: strings.TrimSpace(ep.Remark)})
	}
	if len(targets) == 0 {
		host := endpointHost
		if l := strings.TrimSpace(inbound.Listen); l != "" && l != "0.0.0.0" {
			host = l
		}
		targets = append(targets, endpointTarget{host: host, port: inbound.Port})
	}

	var out []AwgClientConfig
	for i, client := range settings.Clients {
		if client.Email != email {
			continue
		}
		ips := s.awgDeviceIPs(inbound, settings, vpnrange.SlotOr(client.Slot, i))
		devices := client.deviceList()
		if len(ips) == 0 || len(devices) == 0 {
			break
		}
		// ONE CONFIG PER DEVICE. Each carries its own keypair and its own /32, so importing
		// device 1 on one machine and device 2 on another gives them distinct tunnel IPs and
		// lets both stay connected at once. Handing the same config to two devices cannot
		// work: they would share a keypair, and the server keeps one endpoint per peer.
		for d, dev := range devices {
			if d >= len(ips) || strings.TrimSpace(dev.PrivKey) == "" {
				continue
			}
			cidr := ips[d] + "/32"
			// Per device, not per endpoint: see WgcService.RenderClientConfigs.
			psk := ""
			if settings.PskEnable && strings.TrimSpace(dev.Psk) != "" {
				psk = dev.Psk
			}
			for ti, t := range targets {
				var b strings.Builder
				b.WriteString("[Interface]\n")
				b.WriteString("PrivateKey = " + dev.PrivKey + "\n")
				b.WriteString("Address = " + cidr + "\n")
				b.WriteString("DNS = " + settings.dnsList() + "\n")
				fmt.Fprintf(&b, "MTU = %d\n", settings.mtu())
				// AWG 1.0 obfuscation (must match the server, except Jc/Jmin/Jmax).
				fmt.Fprintf(&b, "Jc = %d\n", obfs.Jc)
				fmt.Fprintf(&b, "Jmin = %d\n", obfs.Jmin)
				fmt.Fprintf(&b, "Jmax = %d\n", obfs.Jmax)
				fmt.Fprintf(&b, "S1 = %d\n", obfs.S1)
				fmt.Fprintf(&b, "S2 = %d\n", obfs.S2)
				b.WriteString("H1 = " + obfs.H1 + "\n")
				b.WriteString("H2 = " + obfs.H2 + "\n")
				b.WriteString("H3 = " + obfs.H3 + "\n")
				b.WriteString("H4 = " + obfs.H4 + "\n")
				b.WriteString("\n[Peer]\n")
				b.WriteString("PublicKey = " + settings.ServerPubKey + "\n")
				if psk != "" {
					b.WriteString("PresharedKey = " + psk + "\n")
				}
				fmt.Fprintf(&b, "Endpoint = %s:%d\n", t.host, t.port)
				b.WriteString("AllowedIPs = 0.0.0.0/0\n")
				b.WriteString("PersistentKeepalive = 25\n")
				// Label each config with its device slot so it is obvious that device 1 and
				// device 2 are DIFFERENT configs to import on different machines, not copies.
				remark := ""
				if len(devices) > 1 {
					remark = fmt.Sprintf("Device %d", d+1)
				}
				if t.remark != "" {
					if remark != "" {
						remark += " - "
					}
					remark += t.remark
				}
				out = append(out, AwgClientConfig{
					DeviceIndex:  d*len(targets) + ti,
					IP:           cidr,
					Remark:       remark,
					PublicKey:    dev.PubKey,
					Config:       b.String(),
					PreSharedKey: psk,
					Host:         t.host,
					Port:         t.port,
				})
			}
		}
		break
	}
	return out, nil
}

// AwgClientParams is WgcClientParams plus AmneziaWG obfuscation, for the Clash
// `type: wireguard` + `amnezia-wg-option` proxy. The base params are the wgc package's
// exported struct (vpn-ui embedded WgcClientParams within one package; the target keeps
// the embedding across the package boundary). The obfuscation values are exported (rather
// than the unexported awgObfs) so the sub package can read them. Keep in lock-step with
// RenderClientConfigs.
type AwgClientParams struct {
	wgc.WgcClientParams
	Jc, Jmin, Jmax, S1, S2 int
	H1, H2, H3, H4         string
}

// RenderClientParams mirrors RenderClientConfigs (same targets/devices loop + obfs)
// but returns structured params instead of .conf text.
func (s *AwgService) RenderClientParams(inbound *model.Inbound, email, endpointHost string) ([]AwgClientParams, error) {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return nil, err
	}
	obfs := settings.resolveObfs()
	type endpointTarget struct {
		host   string
		port   int
		remark string
	}
	var targets []endpointTarget
	for _, ep := range settings.ExternalProxy {
		dest := strings.TrimSpace(ep.Dest)
		if dest == "" {
			continue
		}
		port := ep.Port
		if port <= 0 {
			port = inbound.Port
		}
		targets = append(targets, endpointTarget{host: dest, port: port, remark: strings.TrimSpace(ep.Remark)})
	}
	if len(targets) == 0 {
		host := endpointHost
		if l := strings.TrimSpace(inbound.Listen); l != "" && l != "0.0.0.0" {
			host = l
		}
		targets = append(targets, endpointTarget{host: host, port: inbound.Port})
	}
	dns := strings.Split(settings.dnsList(), ", ")
	mtu := settings.mtu()

	var out []AwgClientParams
	for i, client := range settings.Clients {
		if client.Email != email {
			continue
		}
		ips := s.awgDeviceIPs(inbound, settings, vpnrange.SlotOr(client.Slot, i))
		devices := client.deviceList()
		if len(ips) == 0 || len(devices) == 0 {
			break
		}
		for d, dev := range devices {
			if d >= len(ips) || strings.TrimSpace(dev.PrivKey) == "" {
				continue
			}
			cidr := ips[d] + "/32"
			psk := ""
			if settings.PskEnable && strings.TrimSpace(dev.Psk) != "" {
				psk = dev.Psk
			}
			for _, t := range targets {
				remark := ""
				if len(devices) > 1 {
					remark = fmt.Sprintf("Device %d", d+1)
				}
				if t.remark != "" {
					if remark != "" {
						remark += " - "
					}
					remark += t.remark
				}
				out = append(out, AwgClientParams{
					WgcClientParams: wgc.WgcClientParams{
						Name:         remark,
						PrivateKey:   dev.PrivKey,
						Address:      cidr,
						PublicKey:    settings.ServerPubKey,
						PreSharedKey: psk,
						Host:         t.host,
						Port:         t.port,
						MTU:          mtu,
						DNS:          dns,
						AllowedIPs:   []string{"0.0.0.0/0"},
					},
					Jc: obfs.Jc, Jmin: obfs.Jmin, Jmax: obfs.Jmax, S1: obfs.S1, S2: obfs.S2,
					H1: obfs.H1, H2: obfs.H2, H3: obfs.H3, H4: obfs.H4,
				})
			}
		}
		break
	}
	return out, nil
}

// ReconcileKeys ensures the server keypair, per-client keypairs/PSKs, AND the obfuscation
// params (default junk/padding sizes + minted unique magic headers) exist, operating on raw
// JSON to preserve unknown UI fields. Returns whether inbound.Settings changed.
func (s *AwgService) ReconcileKeys(inbound *model.Inbound) (bool, error) {
	var raw map[string]json.RawMessage
	if len(inbound.Settings) > 0 {
		if err := json.Unmarshal([]byte(inbound.Settings), &raw); err != nil {
			return false, err
		}
	}
	if raw == nil {
		raw = map[string]json.RawMessage{}
	}
	changed := false

	if strings.TrimSpace(vpn.JsonString(raw["serverPrivKey"])) == "" {
		priv, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return changed, err
		}
		vpn.SetRawString(raw, "serverPrivKey", priv.String())
		vpn.SetRawString(raw, "serverPubKey", priv.PublicKey().String())
		changed = true
	} else if priv, err := wgtypes.ParseKey(vpn.JsonString(raw["serverPrivKey"])); err == nil {
		if vpn.JsonString(raw["serverPubKey"]) != priv.PublicKey().String() {
			vpn.SetRawString(raw, "serverPubKey", priv.PublicKey().String())
			changed = true
		}
	}

	if ensureAwgObfuscation(raw) {
		changed = true
	}

	pskEnable := vpn.JsonBool(raw["pskEnable"])

	var clients []map[string]json.RawMessage
	if cb, ok := raw["clients"]; ok {
		_ = json.Unmarshal(cb, &clients)
	}
	// One keypair PER DEVICE SLOT, sized to the inbound's User Limit. K devices need K
	// keypairs: two devices sharing one would fight over the single endpoint the server
	// keeps per peer, and would be handed the same tunnel IP.
	k := vpnrange.WgcEffectiveK(vpn.UserLimitPtrFromRaw(raw))
	for _, c := range clients {
		var devices []map[string]json.RawMessage
		if db, ok := c["devices"]; ok {
			_ = json.Unmarshal(db, &devices)
		}
		// Adopt a pre-per-device account's single keypair as device 0 so existing inbounds
		// keep their working config instead of silently getting a new key.
		if len(devices) == 0 && strings.TrimSpace(vpn.JsonString(c["privKey"])) != "" {
			d0 := map[string]json.RawMessage{}
			vpn.SetRawString(d0, "privKey", vpn.JsonString(c["privKey"]))
			vpn.SetRawString(d0, "pubKey", vpn.JsonString(c["pubKey"]))
			vpn.SetRawString(d0, "psk", vpn.JsonString(c["psk"]))
			devices = append(devices, d0)
			changed = true
		}
		// Grow to K, then trim anything beyond it (lowering the User Limit revokes the
		// surplus devices' keys, which is what makes the limit enforceable).
		for len(devices) < k {
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return changed, err
			}
			d := map[string]json.RawMessage{}
			vpn.SetRawString(d, "privKey", key.String())
			vpn.SetRawString(d, "pubKey", key.PublicKey().String())
			devices = append(devices, d)
			changed = true
		}
		if len(devices) > k {
			devices = devices[:k]
			changed = true
		}
		for _, d := range devices {
			if key, err := wgtypes.ParseKey(vpn.JsonString(d["privKey"])); err == nil {
				if vpn.JsonString(d["pubKey"]) != key.PublicKey().String() {
					vpn.SetRawString(d, "pubKey", key.PublicKey().String())
					changed = true
				}
			}
			if pskEnable {
				if strings.TrimSpace(vpn.JsonString(d["psk"])) == "" {
					psk, err := wgtypes.GenerateKey()
					if err != nil {
						return changed, err
					}
					vpn.SetRawString(d, "psk", psk.String())
					changed = true
				}
			} else if vpn.JsonString(d["psk"]) != "" {
				vpn.SetRawString(d, "psk", "")
				changed = true
			}
		}
		db, _ := json.Marshal(devices)
		c["devices"] = db
		// Keep the legacy fields mirroring device 0 so anything still reading them (and the
		// UI's read-only key display) stays correct.
		if len(devices) > 0 {
			vpn.SetRawString(c, "privKey", vpn.JsonString(devices[0]["privKey"]))
			vpn.SetRawString(c, "pubKey", vpn.JsonString(devices[0]["pubKey"]))
			vpn.SetRawString(c, "psk", vpn.JsonString(devices[0]["psk"]))
		}
	}

	if changed {
		if len(clients) > 0 {
			cb, _ := json.Marshal(clients)
			raw["clients"] = cb
		}
		out, err := json.Marshal(raw)
		if err != nil {
			return changed, err
		}
		inbound.Settings = string(out)
	}
	return changed, nil
}

func (s *AwgService) ReconcileAllKeys() bool {
	db := vpn.DB()
	if db == nil {
		return false
	}
	var inbounds []*model.Inbound
	if err := db.Where("protocol = ?", "awg").Find(&inbounds).Error; err != nil {
		return false
	}
	any := false
	for _, ib := range inbounds {
		changed, err := s.ReconcileKeys(ib)
		if err != nil {
			logger.Warningf("AmneziaWG: key reconcile failed for inbound %d: %v", ib.Id, err)
			continue
		}
		if changed {
			if err := db.Model(&model.Inbound{}).Where("id = ?", ib.Id).Update("settings", ib.Settings).Error; err != nil {
				logger.Warningf("AmneziaWG: persist keys failed for inbound %d: %v", ib.Id, err)
			} else {
				any = true
			}
		}
	}
	return any
}

// ---- rbridge.Adapter (identical sweep model to WgcService) ------------------------------
var _ rbridge.Adapter = (*AwgService)(nil)

func (s *AwgService) Protocol() string { return "awg" }

func (s *AwgService) Poll() ([]rbridge.Live, error) {
	inbounds, err := s.GetAwgInbounds()
	if err != nil {
		return nil, err
	}
	if len(inbounds) == 0 {
		return nil, nil
	}
	cl, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer cl.Close()

	now := time.Now()
	seen := make(map[string]bool)
	var live []rbridge.Live

	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		iface := awgIfaceName(inbound.Id)
		dev, err := cl.Device(iface)
		if err != nil {
			continue
		}
		type acctInfo struct {
			email  string
			cidr   string
			enable bool
		}
		// EVERY device key maps back to its account, so all K devices are seen as live
		// tunnels of the one account. They share the account's block CIDR as the billing
		// key, which is what keeps usage/quota aggregated per account rather than per device.
		byPub := make(map[string]acctInfo)
		for i, client := range settings.Clients {
			cidr := s.awgAccountCIDR(inbound, settings, vpnrange.SlotOr(client.Slot, i))
			for _, d := range client.deviceList() {
				if strings.TrimSpace(d.PubKey) == "" {
					continue
				}
				byPub[d.PubKey] = acctInfo{
					email:  client.Email,
					cidr:   cidr,
					enable: client.Enable,
				}
			}
		}
		for _, peer := range dev.Peers {
			if peer.LastHandshakeTime.IsZero() || now.Sub(peer.LastHandshakeTime) > wgHandshakeStale {
				continue
			}
			pk := peer.PublicKey.String()
			info, ok := byPub[pk]
			if !ok || info.cidr == "" || info.email == "" {
				continue
			}
			dk := iface + "|" + pk
			seen[dk] = true
			live = append(live, rbridge.Live{
				Protocol:  "awg",
				InboundID: inbound.Id,
				Email:     info.email,
				IP:        info.cidr,
				DeviceKey: dk,
				Disabled:  !info.enable,
				Since:     s.recordFirstSeen(dk, now),
			})
		}
	}
	s.pruneFirstSeen(seen)
	return live, nil
}

func (s *AwgService) Limit(inboundID int) (int, string) {
	inbounds, err := s.GetAwgInbounds()
	if err != nil {
		return 0, ""
	}
	for _, inbound := range inbounds {
		if inbound.Id != inboundID {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil {
			return 0, ""
		}
		return vpnrange.WgcEffectiveK(settings.UserLimit), vpnrange.NormUserLimitStrategy(settings.UserLimitStrategy)
	}
	return 0, ""
}

func (s *AwgService) Evict(l rbridge.Live) error {
	iface, pkStr, ok := strings.Cut(l.DeviceKey, "|")
	if !ok {
		return fmt.Errorf("awg: malformed device key %q", l.DeviceKey)
	}
	pk, err := wgtypes.ParseKey(pkStr)
	if err != nil {
		return err
	}
	cl, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer cl.Close()
	return cl.ConfigureDevice(iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{PublicKey: pk, Remove: true}},
	})
}

func (s *AwgService) recordFirstSeen(key string, now time.Time) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.firstSeen == nil {
		s.firstSeen = make(map[string]time.Time)
	}
	if t, ok := s.firstSeen[key]; ok {
		return t
	}
	s.firstSeen[key] = now
	return now
}

func (s *AwgService) pruneFirstSeen(seen map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.firstSeen {
		if !seen[k] {
			delete(s.firstSeen, k)
		}
	}
}

func (s *AwgService) runCmd(name string, args ...string) error {
	cmd := exec.CommandContext(context.Background(), name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debugf("AmneziaWG: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}

// ensureAwgObfuscation defaults the junk/padding sizes and mints four distinct magic headers
// (in [5, 2^31-1]) when any is missing. Returns whether raw changed.
func ensureAwgObfuscation(raw map[string]json.RawMessage) bool {
	changed := false
	defInts := []struct {
		k string
		v int
	}{{"jc", 4}, {"jmin", 8}, {"jmax", 80}, {"s1", 77}, {"s2", 90}}
	for _, d := range defInts {
		if _, ok := raw[d.k]; !ok {
			vpn.SetRawInt(raw, d.k, d.v)
			changed = true
		}
	}
	need := false
	for _, k := range []string{"h1", "h2", "h3", "h4"} {
		if strings.TrimSpace(vpn.JsonString(raw[k])) == "" {
			need = true
		}
	}
	if need {
		vals := uniqueMagic(4)
		for i, k := range []string{"h1", "h2", "h3", "h4"} {
			vpn.SetRawString(raw, k, vals[i])
		}
		changed = true
	}
	return changed
}

// uniqueMagic returns n distinct random magic-header values (decimal strings) in [5, 2^31-1].
func uniqueMagic(n int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, n)
	for len(out) < n {
		v := randUint31()
		s := fmt.Sprintf("%d", v)
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// randUint31 returns a cryptographically-random integer in [5, 2^31-1].
func randUint31() int64 {
	const lo = 5
	max := big.NewInt(2147483647 - lo)
	n, err := cryptorand.Int(cryptorand.Reader, max)
	if err != nil {
		return lo
	}
	return n.Int64() + lo
}
