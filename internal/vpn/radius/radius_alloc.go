package radius

// Per-account tunnel-IP allocation for the RADIUS auth paths (vpn-ui
// web/service/radius.go: getClientIP / allocateBlockIP / oldestBlockSession /
// killPPPByIP). The block math itself (slots, K-sized device blocks, range
// normalization) lives in the vpnrange package (internal/vpn/range); this file
// is the session-state side of it.
//
// PORT ADAPTATIONS vs vpn-ui:
//   - database.GetDB() is reached through the root package's injected handle
//     (vpn.DB); the per-protocol session teardowns that lived in the protocol
//     services (ocserv occtl, accel-cmd, swanctl) are dispatched through
//     vpn.EvictProtocolIP, and foldClientTraffic through the vpn.TrafficSink
//     port. The shared-settings decode + block math are vpnrange calls.
//   - killPPPByIP is an INJECTED HOOK (PPPKillFunc / SetPPPKiller): the real
//     per-daemon teardown belongs to the pptp/l2tp wave, which registers its
//     killer at wire-up. Until then the generic ip-link-delete probe below
//     (the source implementation, verbatim) keeps PPP teardowns working.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/logger"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	vpnrange "github.com/ImSoheilPx/pxpanel/internal/vpn/range"
)

// ---------------------------------------------------------------------------
// PPP force-disconnect hook
// ---------------------------------------------------------------------------

// PPPKillFunc force-disconnects the PPP (L2TP/PPTP) device whose tunnel address
// is ip, freeing it for the next dial. Best-effort by contract: a lookup or exec
// miss is reported, never fatal.
type PPPKillFunc func(ip string) error

// SetPPPKiller registers the PPP force-disconnect implementation. The pptp/l2tp
// wave wires theirs at service wire-up; before that (and when unset) the
// generic ip-link-delete probe below is used, which is exactly the source
// implementation. Safe to call at any time; the kill itself may run while the
// allocator holds its lock, so the hook pointer lives under its own mutex.
func (s *RadiusService) SetPPPKiller(fn PPPKillFunc) {
	s.pppKillMu.Lock()
	s.pppKiller = fn
	s.pppKillMu.Unlock()
}

// killPPPByIP force-disconnects an L2TP/PPTP device holding tunnel IP ip through
// the injected killer (see SetPPPKiller), falling back to the generic probe.
func (s *RadiusService) killPPPByIP(ip string) {
	s.pppKillMu.Lock()
	fn := s.pppKiller
	s.pppKillMu.Unlock()
	if fn != nil {
		if err := fn(ip); err != nil {
			logger.Debugf("RADIUS: injected PPP kill failed for %s: %v", ip, err)
		}
		return
	}
	if err := pppKillByIPLink(ip); err != nil {
		logger.Debugf("RADIUS: ppp link delete failed for %s: %v", ip, err)
	}
}

// pppKillByIPLink force-disconnects an L2TP/PPTP device by deleting the PPP
// interface whose peer address is ip (freeing the tunnel IP). The supervising
// daemon reaps the orphaned pppd. (vpn-ui web/service/radius.go killPPPByIP.)
func pppKillByIPLink(ip string) error {
	out, err := exec.CommandContext(context.Background(), "ip", "-o", "addr", "show").Output()
	if err != nil {
		return err
	}
	needle := "peer " + ip + "/"
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, needle) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		iface := strings.TrimSuffix(fields[1], ":") // "3: ppp0 ..." -> "ppp0"
		if !strings.HasPrefix(iface, "ppp") {
			continue
		}
		return exec.CommandContext(context.Background(), "ip", "link", "delete", iface).Run()
	}
	return nil
}

// PPPForceDisconnect is the composite PPP teardown the l2tp/pptp waves register
// as their SetPPPKiller implementation: graceful first (kill the owning pppd by
// its pid file — clean shutdown + Acct-Stop), then force the link down by
// deleting the interface, since the pid file may be absent/stale and deleting
// the interface guarantees the tunnel drops. (vpn-ui web/service/radius.go
// KillSessionsByEmail's toKill branch; exported so the per-protocol packages
// wire it through SetPPPKiller at their SetRadius time.)
func (s *RadiusService) PPPForceDisconnect(ip string) error {
	s.killPppdByIP(ip)
	return pppKillByIPLink(ip)
}

// ---------------------------------------------------------------------------
// Deterministic per-account IP selection
// ---------------------------------------------------------------------------

// getClientIP computes the deterministic IP for a VPN client. Returns (nil,false)
// if the client is not found or the range is exhausted, and (nil,true) when the
// account is at its User Limit and the strategy is "reject" — the caller must then
// send an Access-Reject rather than a keyless Access-Accept.
func (s *RadiusService) getClientIP(protocol string, inboundId int, username, station string, nasPort uint32) (net.IP, bool) {
	db := vpn.DB()
	var inbound model.Inbound
	if inboundId > 0 {
		if err := db.First(&inbound, inboundId).Error; err != nil {
			return nil, false
		}
	} else {
		// Protocol-level NAS-Identifier: resolve the account to its inbound by name.
		ib, err := s.findClientInbound(protocol, username)
		if err != nil {
			return nil, false
		}
		inbound = *ib
	}

	type clientEntry struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Slot  *int   `json:"slot"` // address-pool slot; nil = fall back to list index
		// This account's own device cap. nil = inherit the inbound's K, and it can only
		// LOWER it: see resolveUserLimitOverride for why raising it would silently put
		// two customers on one tunnel address.
		UserLimitOverride *int `json:"userLimitOverride"`
	}
	type settingsJSON struct {
		IpRanges          []string      `json:"ipRanges"`
		IpRange           string        `json:"ipRange"`
		LocalIp           string        `json:"localIp"`
		UserLimit         *int          `json:"userLimit"` // nil = absent (legacy => 1); 0 = no limit
		UserLimitStrategy string        `json:"userLimitStrategy"`
		Clients           []clientEntry `json:"clients"`
	}

	var settings settingsJSON
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		return nil, false
	}

	// The account's SLOT, not its position in clients[]: a delete compacts the list, and
	// deriving the address from the position moved every later account (and orphaned the
	// device-lease keys below, which are built from this value).
	clientIndex := -1
	accountSlot := -1
	for i, c := range settings.Clients {
		if c.ID == username || c.Email == username {
			clientIndex, accountSlot = i, vpnrange.SlotOr(c.Slot, i)
			break
		}
	}
	if clientIndex < 0 {
		return nil, false
	}

	ranges := settings.IpRanges
	if len(ranges) == 0 && settings.IpRange != "" {
		ranges = []string{settings.IpRange}
	}

	email := settings.Clients[clientIndex].Email

	// User Limit K>=2 (L2TP/PPTP/OpenConnect — OpenVPN ignores the RADIUS Framed-IP and
	// assigns from its own pool in the connect hook): hand out a FREE IP from the
	// account's block so K devices on one account each get a distinct IP. When the
	// block is full the strategy decides: "reject" denies the dial, "accept" evicts
	// the oldest device. K==1 (and OpenVPN) keeps the legacy per-index IP.
	k := vpnrange.EffectiveUserLimit(settings.UserLimit)
	if protocol != "openvpn" {
		// Enforce the per-account device cap for EVERY K (>=1). blockIPs is the set of
		// addresses the account may use: K==1 is a ONE-IP block (the legacy deterministic
		// IP), so a 2nd device on the account is rejected/evicted instead of silently
		// sharing the first device's IP (which just breaks routing for one of them).
		// K>=2 is the account's K consecutive device IPs. (OpenVPN doesn't reach here —
		// it authenticates via PAP and enforces the cap in its own client-connect hook.)
		var blockIPs []string
		if k <= 1 {
			if ip := vpnrange.ComputeVpnClientIP(ranges, inbound.Id, accountSlot, protocol); ip != nil {
				blockIPs = []string{ip.String()}
			}
		} else {
			blockIPs = vpnrange.VpnAccountDeviceIPs(vpnrange.PppSubnetsOrDefault(ranges, protocol, inbound.Id), accountSlot, k)
		}
		// The account's own cap, applied by TRIMMING the block the inbound's K just
		// laid out - never by asking for a differently sized one. The addresses are a
		// fixed grid on a stride of K (vpnAccountBlock), so the block's START and its
		// STRIDE stay the inbound's whatever this account is capped at; only how many
		// of its own addresses it may hold at once changes. The ones it gives up sit
		// idle rather than moving to a neighbour, which is what keeps this safe.
		//
		// Kept out of the k<=1 branch on purpose: a one-IP block is already the
		// smallest there is and an override can only lower.
		if vpnrange.UserLimitOverrideApplies(&inbound) {
			if kAcct := vpnrange.ResolveUserLimitOverride(k, settings.Clients[clientIndex].UserLimitOverride); kAcct < len(blockIPs) {
				blockIPs = blockIPs[:kAcct]
			}
		}
		if len(blockIPs) == 0 {
			return nil, false
		}
		strategy := vpnrange.NormUserLimitStrategy(settings.UserLimitStrategy)
		return s.allocateBlockIP(inbound.Id, accountSlot, blockIPs, protocol, strategy, station, nasPort, email)
	}
	return vpnrange.ComputeVpnClientIP(ranges, inbound.Id, accountSlot, protocol), false
}

// allocateBlockIP assigns a stable IP inside account `clientIndex`'s K-block (User
// Limit) to the calling device. A device is keyed by (Calling-Station-Id, NAS-Port):
// the NAS-Port (pppd unit) separates distinct devices that share one public IP behind
// a NAT — without it they collapse to one slot and the K cap is bypassed — while a
// redial that reclaims the same freed unit keeps its key and the IP it already holds
// (idempotent), so an unstable/redialing client can't evict itself and reset its
// traffic counter, nor be handed another device's IP. A new device takes a free slot;
// when all K are held the strategy decides — "reject" returns (nil,true) so the caller
// denies, "accept" evicts the account's OLDEST live device. Returns (ip,false) on
// success, (nil,true) on deny.
func (s *RadiusService) allocateBlockIP(inboundId, accountSlot int, blockIPs []string, protocol, strategy, station string, nasPort uint32, email string) (net.IP, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		s.pending = make(map[string]time.Time)
	}
	if s.stationIP == nil {
		s.stationIP = make(map[string]string)
		s.stationSeen = make(map[string]time.Time)
	}
	now := time.Now()

	// This account's device IPs (K of them; K==1 is a single-IP block).
	isBlockIP := make(map[string]bool, len(blockIPs))
	for _, ip := range blockIPs {
		isBlockIP[ip] = true
	}

	// Device key: (protocol, inbound, account, Calling-Station-Id, NAS-Port). The
	// NAS-Port (pppd unit) is what distinguishes two distinct devices on one account
	// behind the same NAT; a redial reclaiming the same freed unit keeps this key.
	skey := ""
	if station != "" {
		skey = fmt.Sprintf("%s:%d:%d:%s:%d", protocol, inboundId, accountSlot, station, nasPort)
	}

	// recordOC records/refreshes an OpenConnect device's session at AUTH (see
	// ocSessionKey). ocserv's Acct-Start can't identify the device (it carries no
	// Framed-IP, and ocserv sends no NAS-Port at all), so this (not handleAcct) is
	// where an OpenConnect session enters s.sessions; handleOcservAcct then keeps it
	// alive and ends it. This is what User-Limit accept-eviction (oldestBlockSession) and
	// traffic attribution (GetSessions) rely on. The transient `pending` lease is the
	// gap between an Access-Accept and its confirming Acct-Start; OpenConnect has no
	// such gap (auth IS the confirmation), so it is cleared here — leaving it would let
	// the ghost-reclaim step below hand a live device's IP to a new one, bypassing the
	// strategy. No-op for l2tp/pptp (their sessions come from Acct-Start with a real
	// Framed-IP) and never reached by OpenVPN. Called under s.mu.
	recordOC := func(ip string) {
		if protocol != "openconnect" {
			return
		}
		delete(s.pending, ip)
		if existing, ok := s.sessions[ocSessionKey(ip)]; ok {
			if email != "" {
				existing.email = email // refresh; keep original `started` for stable evict order
			}
			return
		}
		s.sessions[ocSessionKey(ip)] = &radiusSession{email: email, ip: ip, protocol: protocol, inboundId: inboundId, started: now}
	}

	// assign claims ip for this station: it wins the slot, so drop any OTHER station's
	// stale claim on the same ip, record ours, and reserve it (pending) until Acct-Start
	// (OpenConnect confirms immediately via recordOC, which clears the pending lease).
	assign := func(ip string) (net.IP, bool) {
		if skey != "" {
			for key, oip := range s.stationIP {
				if oip == ip && key != skey {
					delete(s.stationIP, key)
					delete(s.stationSeen, key)
				}
			}
			s.stationIP[skey] = ip
			s.stationSeen[skey] = now
		}
		s.pending[ip] = now
		recordOC(ip)
		return net.ParseIP(ip).To4(), false
	}

	if protocol == "openconnect" {
		logger.Debugf("RADIUS: oc alloc idx=%d station=%q nasPort=%d skey=%q block=%v", accountSlot, station, nasPort, skey, blockIPs)
	}

	// IDEMPOTENT REDIAL: a client (by Calling-Station-Id) keeps the block IP it already
	// holds — no eviction, no counter churn. Without this, a device whose CHAP/tunnel
	// flaps re-authenticates every ~1s, is treated as a new device each time, evicts its
	// own prior session (resetting that IP's traffic counter -> "counted delta 0") and
	// can be handed the account's other device's IP (duplicate).
	//
	// OpenConnect is EXCLUDED: it is a PPP-only protection. ocserv sends no NAS-Port
	// (nasPort=0 always), so the skey is just protocol:inbound:idx:Calling-Station-Id —
	// and two devices on one account behind the SAME public IP (two phones on home wifi:
	// the common case) collapse to ONE skey. Idempotent-redial would then hand the 2nd
	// device the 1st's IP instead of a free one / an eviction, so it never gets a routable
	// address (no internet) and the 1st is never evicted — exactly the reported bug.
	// OpenConnect auths once per tunnel (no CHAP flapping), so a fresh free-IP-or-evict
	// allocation per auth is correct and safe.
	//
	// SSTP (accel-ppp) is EXCLUDED for the SAME reason: accel-ppp sends nasPort=0 for
	// every session (verified live — two devices on one account behind ONE NAT collapsed
	// to a single tunnel IP 10.5.2.2), and SSTP auths once per TLS tunnel (no CHAP flap),
	// so it takes the free-IP-or-evict path like OpenConnect, not idempotent-redial.
	if skey != "" && protocol != "openconnect" && protocol != "sstp" && protocol != "ikev2" {
		if ip, ok := s.stationIP[skey]; ok && isBlockIP[ip] {
			s.stationSeen[skey] = now
			s.pending[ip] = now
			recordOC(ip) // openconnect: refresh session, clear the transient pending lease
			return net.ParseIP(ip).To4(), false
		}
	}
	// Prune long-abandoned station claims (client gone for good) so the map can't grow
	// without bound; active clients refresh their timestamp above. Deliberately outside
	// the redial branch: the protocols excluded from it still WRITE these maps in assign,
	// so leaving the prune inside meant an openconnect/sstp/ikev2-only server accumulated
	// an entry per (device, account) forever.
	for key, ts := range s.stationSeen {
		if now.Sub(ts) > pendingLeaseTTL {
			delete(s.stationSeen, key)
			delete(s.stationIP, key)
		}
	}

	// OpenConnect reconcile against ocserv's ground truth. The panel never sees an
	// OpenConnect disconnect (Acct is ignored — the session is auth-managed), so a
	// dead device's oc: session lingers until the periodic CleanStaleSessions sweep.
	// Left in place it wrongly OCCUPIES a block slot: a genuine RE-DIAL of the same
	// device (same skey, now with idempotent-redial disabled) would be rejected as
	// "block full", and occupancy is inflated. So before deciding, drop this account's
	// block sessions whose IP no longer routes through an ocserv device — i.e. the
	// tunnel is gone. A truly-live device (a real 2nd device on the account) still
	// routes via ocserv, stays counted, and keeps the K cap honest. Only IPs that
	// actually hold a session are probed, so this is at most K-devices `ip route get`s.
	if protocol == "openconnect" {
		for _, ip := range blockIPs {
			sid := ocSessionKey(ip)
			sess, ok := s.sessions[sid]
			if !ok {
				continue
			}
			// Don't reclaim a session still establishing (its ocserv route may not be in
			// the kernel yet) or one ocserv has just reported alive: in both cases the
			// probe reads a false negative and we would free a live device's IP, which
			// hands the account's next device an address already in use. See
			// ocProbeReady. Only past those does "no ocserv route" mean the tunnel is
			// genuinely gone.
			if !ocProbeReady(sess, now) {
				continue
			}
			if !s.ocIsActive(ip) {
				delete(s.sessions, sid)
				// Best-effort: the tunnel is gone, so a failed counter teardown
				// only leaves a stale set to be reclaimed on the next pass.
				_ = s.nft.RemoveClientAccounting("openconnect", ip)
				logger.Debugf("RADIUS: oc reclaimed stale block IP %s (ocserv tunnel gone)", ip)
			}
		}
	}

	// Real occupancy = live session IPs + still-valid pending allocations (a lingering
	// station claim with no session/pending does NOT block a new device). Expired
	// pending leases (auth without a following Acct-Start) are reclaimed here.
	used := make(map[string]bool, len(s.sessions)+len(s.pending))
	for _, sess := range s.sessions {
		used[sess.ip] = true
	}
	for ip, ts := range s.pending {
		if now.Sub(ts) > pendingLeaseTTL {
			delete(s.pending, ip)
			continue
		}
		used[ip] = true
	}

	// (1) A free slot for this new device.
	blockSet := make(map[string]bool, len(blockIPs))
	for _, ip := range blockIPs {
		blockSet[ip] = true
		if !used[ip] {
			return assign(ip)
		}
	}

	// (2) Reclaim the OLDEST abandoned gap-lease (pending older than the grace) before
	// evicting/denying. A fresh in-flight dial (younger than the grace) and a live
	// session (never in s.pending — cleared at Acct-Start) are both left untouched.
	var ghostIP string
	var ghostTS time.Time
	for _, ip := range blockIPs {
		if ts, ok := s.pending[ip]; ok && now.Sub(ts) > pendingReclaimGrace {
			if ghostIP == "" || ts.Before(ghostTS) {
				ghostIP, ghostTS = ip, ts
			}
		}
	}
	if ghostIP != "" {
		return assign(ghostIP)
	}

	// (3) Block full. "accept": evict the account's oldest live device and reuse its IP.
	if strategy == "accept" {
		if victimSID, victimIP := oldestBlockSession(s.sessions, blockSet); victimIP != "" {
			victim := s.sessions[victimSID]
			delete(s.sessions, victimSID)
			// Fold the evicted device's final counter bytes into its quota BEFORE deleting
			// the nft counters — same as the Acct-Stop path (see handleAcct) — otherwise
			// eviction silently drops the traffic accumulated since the last 10s collection.
			// Under a redial storm (pptp CHAP churn re-keys the same device to a new NAS-Port,
			// tripping this evict-and-readmit repeatedly) that lost traffic zeroes out real
			// usage — the pptp multi-user "counted 0" bug. Folding first can't over-count:
			// ReadAndResetClientCounters zeroes the counter, so the readmit starts from 0.
			if victim != nil && victim.email != "" {
				up, down := s.nft.ReadAndResetClientCounters(protocol, victimIP)
				vpn.TrafficSinkFor().FoldClientTraffic(victim.email, victim.protocol, victim.inboundId, up, down)
			}
			_ = s.nft.RemoveClientAccounting(protocol, victimIP) // best-effort teardown; the next reconcile re-derives the counters
			// Force the old device's link down (vpn-ui dispatched straight into the
			// protocol services). PORT: every teardown goes through the injected seams —
			// vpn.EvictProtocolIP for the daemon-backed protocols (no evictor registered
			// yet = logged skip, nothing torn down blindly), the PPP-kill hook for the
			// pppd-backed ones. inboundId is this account's inbound — the one whose
			// daemon holds victimIP.
			switch protocol {
			case "ikev2":
				// A single shared charon serves every inbound — terminate by virtual IP,
				// ASYNCHRONOUSLY. The kill MUST NOT run inside this RADIUS auth handler:
				// swanctl --list-sas blocks while THIS device's own IKE_SA is
				// mid-authentication (its charon worker thread is blocked in eap-radius
				// waiting for the very Access-Accept we're about to return) — a circular
				// wait through charon's SA-manager lock that fails the new device.
				// Returning first lets charon finish this handshake and release the SA;
				// the goroutine's list-sas is then instant. It targets the OLDEST SA on
				// the IP, so the just-admitted new device (briefly sharing the reused
				// vip) is safe.
				go func() { _ = vpn.EvictProtocolIP("ikev2", victimIP) }()
			case "openconnect", "sstp":
				if err := vpn.EvictProtocolIP(protocol, victimIP); err != nil {
					logger.Debugf("RADIUS: user-limit accept — no %s evictor registered; cannot disconnect %s (%v)", protocol, victimIP, err)
				}
			default:
				s.killPPPByIP(victimIP)
			}
			logger.Infof("RADIUS: user-limit accept — evicted oldest device ip=%s proto=%s to admit new device", victimIP, protocol)
			return assign(victimIP)
		}
		// No live device to evict (all slots pending/mid-handshake) — deny for now.
	}

	// "reject" (default) or nothing evictable: deny the dial.
	return nil, true
}

// oldestBlockSession returns the (session id, IP) of the longest-connected live
// session whose IP falls inside blockIPs (one account's K device IPs), or ("","")
// when none do. Pure selection — the eviction side effects (nft/kill/pending) are
// the caller's.
func oldestBlockSession(sessions map[string]*radiusSession, blockIPs map[string]bool) (sid, ip string) {
	var started time.Time
	for id, sess := range sessions {
		if !blockIPs[sess.ip] {
			continue
		}
		if sid == "" || sess.started.Before(started) {
			sid, ip, started = id, sess.ip, sess.started
		}
	}
	return sid, ip
}
