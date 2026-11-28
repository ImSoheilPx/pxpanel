// Package radius is vpn-ui's in-binary RADIUS server (web/service/radius.go)
// ported into pxpanel: Access-Request auth (MS-CHAPv2, PAP, EAP-MSCHAPv2 via
// radius_eap.go) against the panel DB, Acct-Start/Stop/Interim handling that
// drives the nftables per-account counters and an in-memory session registry,
// and the rbridge.Sink implementation the non-RADIUS sweeper writes through.
//
// PORT ADAPTATIONS vs vpn-ui:
//   - database.GetDB() is reached through the root package's injected handle
//     (vpn.SetDB / vpn.DB) so this package never imports the CGO sqlite driver
//     and cross-compiles for GOOS=linux on any host.
//   - foldClientTraffic (trafficmultiplier.go) is called through the
//     vpn.TrafficSink port; the default sink does the plain client_traffics
//     UPDATE, and the account/membership wave replaces it with the multiplier +
//     breakdown implementation (vpn.SetTrafficSink).
//   - The per-protocol session teardowns that lived in protocol services
//     (ocserv occtl, accel-cmd, swanctl) are dispatched through
//     vpn.EvictProtocolIP; the protocol wave registers its evictors.
//   - ikev2's swanctl liveness probe is likewise registered via
//     vpn.RegisterIPProber; per-protocol subnet readers via
//     vpn.RegisterSubnetResolver. The l2tp/pptp/openvpn/openconnect probes and
//     the shared settings-JSON subnet decode are built in below.
package radius

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/logger"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/nftables"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/rbridge"

	"layeh.com/radius"
	"layeh.com/radius/rfc2759"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/rfc3079"
	"layeh.com/radius/vendors/microsoft"
)

// RadiusService embeds a RADIUS server for PPP (L2TP/PPTP) authentication and accounting.
// Auth: pppd sends Access-Request with MS-CHAPv2 → we query the DB → Accept/Reject.
// Acct: pppd sends Acct-Start/Stop → we manage nft counters and track sessions in memory.
type RadiusService struct {
	nft         *nftables.Service
	authServer  *radius.PacketServer
	acctServer  *radius.PacketServer
	mu          sync.Mutex
	sessions    map[string]*radiusSession // key: Acct-Session-Id
	pending     map[string]time.Time      // key: freshly allocated IP awaiting Acct-Start (User Limit blocks)
	stationIP   map[string]string         // key: "proto:idx:Calling-Station-Id" -> its stable block IP
	stationSeen map[string]time.Time      // last time each station authenticated (for pruning)
	secret      []byte
	eapSessions map[string]*eapState // key: hex(State attr): in-flight EAP-MSCHAPv2 exchanges (IKEv2/strongSwan)
	// ocActiveFn overrides the OpenConnect liveness probe (isIPActive) — set in unit
	// tests where no real ocserv route table exists. nil in production.
	ocActiveFn func(ip string) bool
	// lookupFn overrides the account-password lookup (lookupPassword) — set in unit
	// tests where no database exists. nil in production.
	lookupFn func(protocol string, inboundId int, username string) (string, error)
	// pppKiller is the injected PPP force-disconnect (SetPPPKiller); nil = the
	// generic ip-link-delete probe (pppKillByIPLink). Guarded by its own mutex,
	// never s.mu: the kill is invoked from inside allocateBlockIP, which holds
	// s.mu for the whole allocation.
	pppKiller PPPKillFunc
	pppKillMu sync.Mutex
}

// ocIsActive reports whether an OpenConnect tunnel IP is still live (routes via an
// ocserv device), through the injectable probe so tests can stub it.
func (s *RadiusService) ocIsActive(ip string) bool {
	if s.ocActiveFn != nil {
		return s.ocActiveFn(ip)
	}
	return s.isIPActive(ip, "openconnect")
}

// pendingLeaseTTL is how long a block-allocated IP is held between the
// Access-Accept that assigned it and the Acct-Start that confirms it. An auth
// that never starts a session (retry, abandoned dial) frees the IP after this.
const pendingLeaseTTL = 90 * time.Second

// pendingReclaimGrace is the minimum age of a pending block-lease before it may
// be reclaimed for a different dial. Longer than a normal auth->Acct-Start gap
// (a few seconds), so a device still mid-handshake is never handed its slot to
// someone else; far shorter than pendingLeaseTTL, so a genuinely abandoned
// (ghost) lease is reclaimed promptly instead of wedging the account until TTL.
const pendingReclaimGrace = 15 * time.Second

// ocStaleReclaimGrace is how long an OpenConnect block session is trusted as "still
// establishing" before its missing ocserv route is taken to mean the tunnel is gone.
// Long enough that a freshly-authed session's route is in the kernel; short enough
// that a genuine re-dial of a dropped device isn't blocked as "block full" for long.
const ocStaleReclaimGrace = 15 * time.Second

// ocInterimInterval is the Acct-Interim-Interval the panel asks ocserv for, so it is
// also how often a live OpenConnect session announces itself (see handleOcservAcct).
const ocInterimInterval = 60

// ocHeartbeatGrace is how long an OpenConnect session is trusted on its last
// Interim-Update alone.
//
// ocserv reports on a 30s check tick and fuzzes the interval by a few seconds, so the
// real gap between updates is up to ~95s rather than the 60s asked for; radcli retries a
// packet the panel does not answer, so a lost one is not a third case. 150s therefore
// carries a comfortable margin over one gap while still bounding how long a session that
// went silent WITHOUT a stop (an ocserv crash) keeps its address before the route probe
// takes over.
const ocHeartbeatGrace = 150 * time.Second

type radiusSession struct {
	email    string
	ip       string
	protocol string // "l2tp", "pptp", "openvpn", or "openconnect"
	// inboundId is which inbound of that protocol is serving this session, and is
	// what lets the tick attribute its bytes to one membership instead of to the
	// account as a whole. 0 means it could not be told, which is billed to the
	// account and left out of the per-inbound breakdown rather than guessed at.
	//
	// openvpn, openconnect and sstp name it in their NAS-Identifier
	// ("<proto>-<inboundId>"). l2tp, pptp and ikev2 share one daemon and send a bare
	// protocol name, so theirs is resolved from the tunnel address against each
	// inbound's own pool (sessionInboundByIP).
	inboundId int
	started   time.Time // session start; used to pick the oldest device to evict
	// heard is the last time the DAEMON itself confirmed the tunnel is up (an
	// OpenConnect Interim-Update). Zero for the protocols whose accounting the panel
	// does not use as a heartbeat, so a zero value must never read as "long ago".
	heard time.Time
	// acctID is the daemon's own Acct-Session-Id, learned from that same
	// Interim-Update. OpenConnect sessions are keyed by tunnel IP, and an address
	// outlives the device that held it, so this is the only way to tell whether a later
	// Acct-Stop is ending THIS session or the predecessor that used to hold the address.
	// Empty until the first interim, and unused by the protocols keyed by session id.
	acctID string
}

// ocSessionKey is the s.sessions map key for an auth-recorded OpenConnect session.
// ocserv's accounting can identify neither the device nor its IP (it sends no
// Framed-IP-Address and no NAS-Port), so — unlike l2tp/pptp — an OpenConnect session
// can't be keyed by Acct-Session-Id at Acct-Start. It is instead recorded at AUTH and
// keyed by its assigned tunnel IP, which is unique per device (each holds a distinct
// block IP) and, with groupconfig=true, equals the real ocserv tunnel IP. The "oc:"
// prefix can't collide with a real ocserv Acct-Session-Id.
func ocSessionKey(ip string) string { return "oc:" + ip }

// runningRadius points at the RadiusService whose servers are currently bound.
// The embedded RADIUS server lives in-process (not a child daemon), so the Core
// Settings restart/stop controls act on this instance rather than a PID.
var runningRadius *RadiusService

// Start launches the RADIUS auth (1812) and accounting (1813) servers on localhost.
func (s *RadiusService) Start(secret string) error {
	s.nft = &nftables.Service{}
	s.sessions = make(map[string]*radiusSession)
	s.pending = make(map[string]time.Time)
	return s.listen(secret)
}

// listen (re)creates and serves the auth/acct packet servers. It does NOT touch
// the sessions map, so a restart preserves active-session tracking (the map is
// shared by reference with the L2TP/PPTP/OpenVPN services).
func (s *RadiusService) listen(secret string) error {
	s.secret = []byte(secret)

	s.authServer = &radius.PacketServer{
		Addr:         "127.0.0.1:1812",
		Handler:      radius.HandlerFunc(s.handleAuth),
		SecretSource: radius.StaticSecretSource(s.secret),
	}
	s.acctServer = &radius.PacketServer{
		Addr:         "127.0.0.1:1813",
		Handler:      radius.HandlerFunc(s.handleAcct),
		SecretSource: radius.StaticSecretSource(s.secret),
	}

	go func() {
		if err := s.authServer.ListenAndServe(); err != nil {
			logger.Warning("RADIUS: auth server stopped:", err)
		}
	}()
	go func() {
		if err := s.acctServer.ListenAndServe(); err != nil {
			logger.Warning("RADIUS: acct server stopped:", err)
		}
	}()

	runningRadius = s
	logger.Info("RADIUS: listening on 127.0.0.1:1812 (auth) and :1813 (acct)")
	return nil
}

// Stop gracefully shuts down both RADIUS servers.
func (s *RadiusService) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if s.authServer != nil {
		// Teardown best-effort: a timed-out shutdown leaves the listener to the
		// process exit that always follows Stop.
		_ = s.authServer.Shutdown(ctx)
		s.authServer = nil
	}
	if s.acctServer != nil {
		_ = s.acctServer.Shutdown(ctx)
		s.acctServer = nil
	}
}

// StopRadius stops the embedded RADIUS servers. Exported for the Core Settings
// "Stop" control. Note: this halts L2TP/PPTP/OpenVPN authentication until a
// restart, so it is a deliberate, admin-triggered action.
func StopRadius() error {
	if runningRadius == nil {
		return fmt.Errorf("RADIUS server is not running")
	}
	runningRadius.Stop()
	logger.Info("RADIUS: stopped")
	return nil
}

// RestartRadius restarts the embedded RADIUS servers, picking up the current
// shared secret from settings. The in-memory session map is preserved.
func RestartRadius() error {
	if runningRadius == nil {
		return fmt.Errorf("RADIUS server is not running")
	}
	secret, _ := vpn.RadiusSecret()
	if secret == "" {
		secret = string(runningRadius.secret)
	}
	runningRadius.Stop()
	if runningRadius.sessions == nil {
		runningRadius.sessions = make(map[string]*radiusSession)
	}
	return runningRadius.listen(secret)
}

// handleAuth processes RADIUS Access-Request packets with MS-CHAPv2 authentication.
// NAS-Identifier encodes the protocol and inbound ID (e.g. "l2tp-3" or "pptp-5").
func (s *RadiusService) handleAuth(w radius.ResponseWriter, r *radius.Request) {
	username := rfc2865.UserName_GetString(r.Packet)
	nasID := rfc2865.NASIdentifier_GetString(r.Packet)
	challenge := microsoft.MSCHAPChallenge_Get(r.Packet)
	response := microsoft.MSCHAP2Response_Get(r.Packet)

	// Per-device identity for User Limit K>1 (see allocateBlockIP): Calling-Station-Id
	// (the client's remote IP) PLUS NAS-Port (the pppd unit number). Two distinct
	// devices on one account behind the SAME NAT share a Calling-Station-Id, so the
	// NAS-Port is what tells them apart and keeps the K cap honest; a unit is reused
	// once freed, so a genuine redial that reclaims it stays idempotent.
	station := rfc2865.CallingStationID_GetString(r.Packet)
	nasPort := uint32(rfc2865.NASPort_Get(r.Packet))

	if username == "" || nasID == "" {
		logger.Debug("RADIUS: auth rejected — missing username or NAS-Identifier")
		// Reply writes are best-effort: the client retransmits if the datagram is
		// lost, and there is nothing to recover on a failed send.
		_ = w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	// Parse NAS-Identifier: "l2tp-{id}" or "pptp-{id}"
	protocol, inboundId, err := parseNASIdentifier(nasID)
	if err != nil {
		logger.Infof("RADIUS: auth rejected — invalid NAS-Identifier %q", nasID)
		_ = w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	// EAP (IKEv2 via strongSwan's eap-radius plugin): EAP-MSCHAPv2 is a multi-round
	// Access-Challenge exchange, unlike the single-shot PAP / native-MS-CHAPv2 paths
	// below. Delegate the whole conversation as soon as an EAP-Message is present.
	if eap := getEAPMessage(r.Packet); len(eap) > 0 {
		s.handleEAPAuth(w, r, protocol, inboundId, username, station, nasPort, eap)
		return
	}

	// Look up the client password from the database
	password, err := s.lookupClient(protocol, inboundId, username)
	if err != nil {
		logger.Infof("RADIUS: auth rejected — %s user=%s nas=%s", err, username, nasID)
		_ = w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	// PAP authentication. Both OpenVPN's auth hook and OpenConnect (ocserv via
	// radcli) authenticate with a plaintext User-Password.
	userPassword := rfc2865.UserPassword_GetString(r.Packet)
	if userPassword != "" {
		if userPassword != password {
			logger.Infof("RADIUS: auth rejected (PAP) — wrong password user=%s nas=%s", username, nasID)
			_ = w.Write(r.Response(radius.CodeAccessReject))
			return
		}
		accept := r.Response(radius.CodeAccessAccept)
		// OpenConnect is RADIUS-authoritative for the tunnel IP: ocserv runs with
		// predictable-ips=false and NO local pool, so it provisions each session from
		// the Access-Accept's Framed-IP-Address. A keyless accept leaves ocserv with
		// no IP to assign — the session can't come up and the client sees an auth
		// failure. This branch therefore mirrors the MS-CHAPv2 path for openconnect:
		// assign the per-user source IP and apply the User-Limit gate (reject
		// strategy). OpenVPN assigns IPs via CCD and enforces User Limit in its
		// connect hook, so it keeps taking the bare accept unchanged.
		if protocol == "openconnect" {
			clientIP, deny := s.getClientIP(protocol, inboundId, username, station, nasPort)
			if deny {
				logger.Infof("RADIUS: auth rejected — user-limit reached (strategy=reject) user=%s nas=%s", username, nasID)
				_ = w.Write(r.Response(radius.CodeAccessReject))
				return
			}
			// A keyless Access-Accept is not a safe fallback for OpenConnect. ocserv would
			// then lease from its OWN pool, which spans the very block the panel hands out
			// by account slot, and it registers no lease at all for an explicitly assigned
			// address (ip-lease.c sets ->db only on the pool path), so its duplicate check
			// cannot see the addresses we assign: it can pick one a live device already
			// holds. Two tunnels on one address leaves the older one's return traffic on the
			// newer tun, so it stays "connected" and passes nothing. Such an address is also
			// outside the routing backstop's valid-IP list, so Xray blackholes it anyway.
			if clientIP == nil {
				logger.Infof("RADIUS: auth rejected: no tunnel IP available (pool exhausted?) user=%s nas=%s", username, nasID)
				_ = w.Write(r.Response(radius.CodeAccessReject))
				return
			}
			_ = rfc2865.FramedIPAddress_Set(accept, clientIP)
			// The session was recorded at auth (getClientIP -> allocateBlockIP). ocserv
			// won't drive Acct-Start usefully, so create the nft accounting counters here
			// too, off the lock, otherwise this device's traffic is never counted and
			// account usage/quota enforcement silently no-ops for OpenConnect. Idempotent.
			if err := s.nft.AddClientAccounting(protocol, clientIP.String()); err != nil {
				logger.Warning("RADIUS: failed to add openconnect nft accounting:", err)
			}
			// Interim accounting is not billing here (nft counters do that): it is the only
			// liveness signal ocserv gives the panel, see handleOcservAcct.
			_ = rfc2869.AcctInterimInterval_Set(accept, rfc2869.AcctInterimInterval(ocInterimInterval))
			logger.Infof("RADIUS: auth accepted (PAP) user=%s nas=%s ip=%v", username, nasID, clientIP)
		} else {
			logger.Infof("RADIUS: auth accepted (PAP) user=%s nas=%s", username, nasID)
		}
		_ = w.Write(accept)
		return
	}

	// MS-CHAPv2 authentication
	if len(challenge) != 16 || len(response) != 50 {
		logger.Infof("RADIUS: auth rejected — bad MS-CHAPv2 lengths (challenge=%d response=%d) user=%s",
			len(challenge), len(response), username)
		_ = w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	ident := response[0]
	peerChallenge := response[2:18]
	peerResponse := response[26:50]

	ntResponse, err := rfc2759.GenerateNTResponse(challenge, peerChallenge, []byte(username), []byte(password))
	if err != nil {
		logger.Warning("RADIUS: GenerateNTResponse failed:", err)
		_ = w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	if !bytes.Equal(ntResponse, peerResponse) {
		logger.Debugf("RADIUS: auth rejected — wrong password user=%s nas=%s", username, nasID)
		_ = w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	// Build Access-Accept with MS-CHAPv2 success + MPPE keys
	accept := r.Response(radius.CodeAccessAccept)

	// Authenticator response (S=... string for client verification)
	authResp, _ := rfc2759.GenerateAuthenticatorResponse(challenge, peerChallenge, ntResponse, []byte(username), []byte(password))
	success := make([]byte, 43)
	success[0] = ident
	copy(success[1:], authResp)
	// Attribute setters below can only fail on an over-long value; every value
	// here is fixed-size, and the Accept carrying them is best-effort anyway.
	_ = microsoft.MSCHAP2Success_Add(accept, success)

	// MPPE keys (required for PPTP, harmlessly ignored by L2TP)
	recvKey, _ := rfc3079.MakeKey(ntResponse, []byte(password), false)
	sendKey, _ := rfc3079.MakeKey(ntResponse, []byte(password), true)
	_ = microsoft.MSMPPERecvKey_Add(accept, recvKey)
	_ = microsoft.MSMPPESendKey_Add(accept, sendKey)
	_ = microsoft.MSMPPEEncryptionPolicy_Add(accept, microsoft.MSMPPEEncryptionPolicy_Value_EncryptionRequired)
	// 128-bit only: with "40or128 allowed" the server pppd settles on weak 40-bit
	// MPPE (offers +L -S), which 128-bit-requiring clients (Windows/NM default)
	// reject with "MPPE required but peer negotiation failed".
	_ = microsoft.MSMPPEEncryptionTypes_Add(accept, microsoft.MSMPPEEncryptionTypes_Value_RC4128bitAllowed)

	// Assign deterministic IP so per-user Xray routing works via source IP. A deny
	// means the account is at its User Limit and the strategy is "reject".
	clientIP, deny := s.getClientIP(protocol, inboundId, username, station, nasPort)
	if deny {
		logger.Infof("RADIUS: auth rejected — user-limit reached (strategy=reject) user=%s nas=%s", username, nasID)
		_ = w.Write(r.Response(radius.CodeAccessReject))
		return
	}
	if clientIP != nil {
		_ = rfc2865.FramedIPAddress_Set(accept, clientIP)
	}

	// Request periodic accounting updates (60s minimum for pppd)
	_ = rfc2869.AcctInterimInterval_Set(accept, rfc2869.AcctInterimInterval(60))

	logger.Infof("RADIUS: auth accepted user=%s nas=%s ip=%v", username, nasID, clientIP)
	_ = w.Write(accept)
}

// handleAcct processes RADIUS Accounting-Request packets (Start/Stop/Interim-Update).
func (s *RadiusService) handleAcct(w radius.ResponseWriter, r *radius.Request) {
	statusType := rfc2866.AcctStatusType_Get(r.Packet)
	sessionID := rfc2866.AcctSessionID_GetString(r.Packet)
	username := rfc2865.UserName_GetString(r.Packet)
	nasID := rfc2865.NASIdentifier_GetString(r.Packet)
	framedIP := rfc2865.FramedIPAddress_Get(r.Packet)

	// Always acknowledge
	defer func() { _ = w.Write(r.Response(radius.CodeAccountingResponse)) }()

	// The inbound id is kept, not discarded. It is the only thing that lets this
	// session's bytes be attributed to ONE membership instead of to the account as a
	// whole, and openvpn, openconnect and sstp all put it right here in the
	// NAS-Identifier. It is 0 for l2tp, pptp and ikev2, which send a bare protocol
	// name; theirs is resolved from the tunnel address below.
	protocol, nasInboundId, err := parseNASIdentifier(nasID)
	if err != nil {
		logger.Debugf("RADIUS: acct ignored — invalid NAS-Identifier %q", nasID)
		return
	}

	// OpenConnect sessions are CREATED by the AUTH path (see allocateBlockIP), because
	// ocserv's Acct-Start identifies nothing: main opens the accounting session before it
	// leases the tunnel IP, so that packet carries no Framed-IP-Address (and ocserv sends
	// no NAS-Port at all). Its LATER packets do carry one: the worker reports its assigned
	// address with every stats message, which sec-mod copies into the accounting info, so
	// Interim-Update and Stop both name the tunnel IP that keys the session. Those two are
	// the only word the panel ever gets from ocserv about a session it did not just
	// authenticate, so they are handled rather than discarded. The deferred
	// Accounting-Response above still ACKs every packet so ocserv does not retry.
	if protocol == "openconnect" {
		s.handleOcservAcct(statusType, sessionID, username, framedIP, nasInboundId)
		return
	}

	switch statusType {
	case rfc2866.AcctStatusType_Value_Start:
		ip := framedIP.String()
		if ip == "<nil>" || ip == "" {
			// NOTE: ocserv's Accounting-Request omits Framed-IP-Address, so OpenConnect
			// sessions are not recorded here and User-Limit accept-eviction has nothing
			// to evict (strategy-accept). A recovery keyed by Calling-Station-Id proved
			// ambiguous when two devices share a station (handed the 2nd device the 1st's
			// IP), so proper tracking needs the auth step to record the session directly.
			logger.Debugf("RADIUS: acct-start missing Framed-IP user=%s", username)
			return
		}

		// Look up email for this username
		email := s.lookupEmail(protocol, username)
		if email == "" {
			logger.Debugf("RADIUS: acct-start no email found for user=%s nas=%s", username, nasID)
			return
		}

		// Resolved off the lock: it reads the inbounds of one protocol, and the three
		// that need it (l2tp, pptp, ikev2) have a handful each.
		inboundId := nasInboundId
		if inboundId == 0 {
			inboundId = s.sessionInboundByIP(protocol, ip)
		}

		s.mu.Lock()
		s.sessions[sessionID] = &radiusSession{
			email:     email,
			ip:        ip,
			protocol:  protocol,
			inboundId: inboundId,
			started:   time.Now(),
		}
		delete(s.pending, ip) // confirmed: the session now holds this block IP
		s.mu.Unlock()

		// Add nft accounting counters for this client
		if err := s.nft.AddClientAccounting(protocol, ip); err != nil {
			logger.Warning("RADIUS: failed to add nft accounting:", err)
		}

		logger.Infof("RADIUS: acct-start user=%s email=%s ip=%s proto=%s session=%s", username, email, ip, protocol, sessionID)

	case rfc2866.AcctStatusType_Value_Stop:
		s.mu.Lock()
		sess, ok := s.sessions[sessionID]
		if ok {
			delete(s.sessions, sessionID)
		}
		// Whose IP is being stopped, and does ANOTHER live session still own it? Under
		// User-Limit "accept" a freed IP is immediately reassigned to a new device, and
		// the evicted device's Acct-Stop can arrive AFTER the newcomer's Acct-Start (the
		// evicted IKEv2 SA is torn down asynchronously — see allocateBlockIP). Removing
		// the nft counter (or folding+resetting it) on that late stop would wipe the
		// newcomer's accounting → its traffic counts as 0 (the multi-user regression).
		// So if the IP is now held by a different session, this stop is stale: ACK it but
		// touch nothing. The evicting path already folded the old device's bytes.
		stopIP := framedIP.String()
		if ok {
			stopIP = sess.ip
		}
		reassigned := false
		if stopIP != "" && stopIP != "<nil>" {
			for sid, o := range s.sessions {
				if sid != sessionID && o.ip == stopIP && o.protocol == protocol {
					reassigned = true
					break
				}
			}
		}
		s.mu.Unlock()

		if reassigned {
			logger.Infof("RADIUS: acct-stop stale — ip=%s reassigned to a live session, keeping its accounting (user=%s session=%s)", stopIP, username, sessionID)
			return
		}

		if ok {
			// Fold the final counter bytes (accumulated since the last 10s collection)
			// into the client's quota BEFORE the counters are deleted — otherwise a
			// disconnect (or a rapid reconnect) silently drops that traffic, which
			// under-counts usage and under-enforces limits.
			up, down := s.nft.ReadAndResetClientCounters(sess.protocol, sess.ip)
			vpn.TrafficSinkFor().FoldClientTraffic(sess.email, sess.protocol, sess.inboundId, up, down)
			// Remove nft accounting counters
			if err := s.nft.RemoveClientAccounting(sess.protocol, sess.ip); err != nil {
				logger.Warning("RADIUS: failed to remove nft accounting:", err)
			}
			logger.Infof("RADIUS: acct-stop user=%s email=%s ip=%s proto=%s session=%s", username, sess.email, sess.ip, sess.protocol, sessionID)
		} else {
			// Unknown session (e.g. after panel restart) — try cleanup by IP if available
			ip := framedIP.String()
			if ip != "<nil>" && ip != "" {
				// Best-effort cleanup of a session this process never saw; the
				// nft counters are deleted on the next reconcile regardless.
				_ = s.nft.RemoveClientAccounting(protocol, ip)
				logger.Infof("RADIUS: acct-stop (orphan) user=%s ip=%s proto=%s session=%s", username, ip, protocol, sessionID)
			} else {
				logger.Debugf("RADIUS: acct-stop unknown session=%s user=%s", sessionID, username)
			}
		}

	case rfc2866.AcctStatusType_Value_InterimUpdate:
		// For L2TP/PPTP we use nft counters, so interim updates are logged but not processed
		logger.Debugf("RADIUS: acct-interim user=%s session=%s", username, sessionID)

		// Re-add session if missing (e.g. after panel restart)
		s.mu.Lock()
		if _, ok := s.sessions[sessionID]; !ok {
			ip := framedIP.String()
			if ip != "<nil>" && ip != "" {
				email := s.lookupEmail(protocol, username)
				if email != "" {
					inboundId := nasInboundId
					if inboundId == 0 {
						inboundId = s.sessionInboundByIP(protocol, ip)
					}
					s.sessions[sessionID] = &radiusSession{
						email:     email,
						ip:        ip,
						protocol:  protocol,
						inboundId: inboundId,
						started:   time.Now(),
					}
					s.mu.Unlock()
					// Best-effort: the counters are recreated on the next auth if
					// this add fails, and the interim reply is what matters here.
					_ = s.nft.AddClientAccounting(protocol, ip)
					logger.Infof("RADIUS: re-added session from interim user=%s email=%s ip=%s", username, email, ip)
					return
				}
			}
		}
		s.mu.Unlock()
	}
}

// handleOcservAcct applies one OpenConnect Accounting-Request to the auth-created
// session at that tunnel IP (see ocSessionKey).
//
//   - Interim-Update is a heartbeat. It is what lets the route-probe sweep stop
//     second-guessing a live tunnel, and it re-adopts a session the panel lost (a
//     restart, or a sweep that ran while the tunnel was still coming up) instead of
//     leaving its address looking free to the next device on the account.
//   - Stop is the authoritative end of the session, and the only prompt one: without it
//     a dead device's address stays occupied until the next 60s sweep notices its route
//     is gone, which both refuses the account's own redial and delays the counters.
//
// A start (no Framed-IP yet) is ignored, as is any packet the panel cannot key.
//
// inboundId comes from ocserv's own NAS-Identifier ("openconnect-<id>", set by the
// OpenConnect wave's config writer), so an adopted session is attributed to the right
// inbound instead of joining the account's unattributed pool.
func (s *RadiusService) handleOcservAcct(statusType rfc2866.AcctStatusType, sessionID, username string, framedIP net.IP, inboundId int) {
	ip := framedIP.String()
	if ip == "" || ip == "<nil>" {
		logger.Debugf("RADIUS: oc acct without Framed-IP ignored user=%s status=%v", username, statusType)
		return
	}
	sid := ocSessionKey(ip)
	now := time.Now()

	switch statusType {
	case rfc2866.AcctStatusType_Value_InterimUpdate:
		s.mu.Lock()
		if sess, ok := s.sessions[sid]; ok {
			sess.heard = now
			sess.acctID = sessionID // whose session this address currently is
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()

		// Unknown live tunnel: adopt it. The email lookup is a DB read, so it runs off
		// the lock (every RADIUS auth on the box waits behind that mutex).
		email := s.lookupEmail("openconnect", username)
		if email == "" {
			return
		}
		s.mu.Lock()
		if _, exists := s.sessions[sid]; !exists {
			s.sessions[sid] = &radiusSession{email: email, ip: ip, protocol: "openconnect", inboundId: inboundId, started: now, heard: now, acctID: sessionID}
		}
		s.mu.Unlock()
		if err := s.nft.AddClientAccounting("openconnect", ip); err != nil {
			logger.Warning("RADIUS: failed to add openconnect nft accounting:", err)
		}
		logger.Infof("RADIUS: re-added openconnect session from interim user=%s email=%s ip=%s", username, email, ip)

	case rfc2866.AcctStatusType_Value_Stop:
		s.mu.Lock()
		sess, ok := s.sessions[sid]
		if !ok {
			s.mu.Unlock()
			return
		}
		// Under User-Limit "accept" the freed address is handed to the incoming device
		// immediately, so the evicted device's stop can arrive once the newcomer already
		// owns this key. Acting on it would delete a live session and wipe the newcomer's
		// counters (the l2tp Acct-Stop case documents the same hazard). The daemon's own
		// session id settles it whenever the session has been heard from: a stop naming a
		// different one is the predecessor's, and the evicting path has already folded and
		// removed that device's accounting. Before the first interim there is nothing to
		// compare (ocserv's Access-Request carries no session id), so age stands in.
		//
		// A cookie reconnect is deliberately NOT a case here: ocserv refcounts the auth
		// session, so the old worker's close does not reach the accounting module and no
		// stop is sent while the session lives on.
		if sess.acctID != "" && sessionID != "" && sess.acctID != sessionID {
			s.mu.Unlock()
			logger.Infof("RADIUS: oc acct-stop stale: ip=%s belongs to session %s now (stop was for %s)", ip, sess.acctID, sessionID)
			return
		}
		if sess.acctID == "" && now.Sub(sess.started) < ocStaleReclaimGrace {
			s.mu.Unlock()
			logger.Infof("RADIUS: oc acct-stop stale: ip=%s just reassigned, keeping its accounting (user=%s)", ip, username)
			return
		}
		delete(s.sessions, sid)
		s.mu.Unlock()

		// Fold the bytes counted since the last collection before deleting the counters,
		// exactly as the l2tp/pptp Acct-Stop path does.
		up, down := s.nft.ReadAndResetClientCounters("openconnect", ip)
		vpn.TrafficSinkFor().FoldClientTraffic(sess.email, sess.protocol, sess.inboundId, up, down)
		if err := s.nft.RemoveClientAccounting("openconnect", ip); err != nil {
			logger.Warning("RADIUS: failed to remove openconnect nft accounting:", err)
		}
		logger.Infof("RADIUS: oc acct-stop user=%s email=%s ip=%s", username, sess.email, ip)
	}
}

// GetSessions returns an IP→email map for the given protocol, used by traffic collection.
func (s *RadiusService) GetSessions(protocol string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make(map[string]string)
	for _, sess := range s.sessions {
		if sess.protocol == protocol {
			result[sess.ip] = sess.email
		}
	}
	return result
}

// GetSessionInbounds is GetSessions' companion: IP→the inbound serving that tunnel,
// for the same protocol. It is what lets the collector stamp each record with the
// SOURCE of its bytes.
//
// A parallel map rather than a wider GetSessions, because the session map is what
// every caller of that one wants and none of them should have to unpack a struct to
// get it. Addresses whose inbound could not be told are simply absent, which the
// collector reads as "unknown" and bills to the account without attributing it.
func (s *RadiusService) GetSessionInbounds(protocol string) map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make(map[string]int)
	for _, sess := range s.sessions {
		if sess.protocol == protocol && sess.inboundId != 0 {
			result[sess.ip] = sess.inboundId
		}
	}
	return result
}

// RadiusService is the rbridge.Sink: the rbridge Sweeper writes reconciled sessions and reads the
// disabled-account set through it, so ownership of the session store stays here in RADIUS.
var _ rbridge.Sink = (*RadiusService)(nil)

// localSessionKey is the s.sessions key for a tunnel reconciled by the rbridge sweep (non-RADIUS
// protocols: ikev2 psk/eap-tls, wireguard, ...). The "cp:<proto>:" prefix keeps it distinct from a
// daemon Acct-Session-Id and from the "oc:" openconnect keys, and namespaces protocols so one
// protocol's reconcile never touches another's sessions.
func localSessionKey(protocol, ip string) string { return "cp:" + protocol + ":" + ip }

// ReconcileLocalSessions replaces the tracked rbridge-managed sessions for one protocol with
// `desired` (tunnel IP -> account + serving inbound). Newly seen IPs gain an nft accounting
// counter; vanished IPs are folded into client_traffics and their counter removed (mirrors
// Acct-Stop). Called each tick by the rbridge Sweeper. It only touches this protocol's
// "cp:<proto>:"-keyed sessions, so it never disturbs RADIUS-tracked sessions (e.g. ikev2
// eap-mschapv2, keyed by Acct-Session-Id).
func (s *RadiusService) ReconcileLocalSessions(protocol string, desired map[string]rbridge.Reconciled) {
	// The inbound id travels with a departing session because it is needed AFTER the
	// session has been deleted from the map, to attribute its final bytes.
	type kv struct {
		email     string
		ip        string
		inboundId int
	}
	var gone []kv
	var added []string
	prefix := "cp:" + protocol + ":"

	s.mu.Lock()
	if s.sessions == nil {
		s.sessions = make(map[string]*radiusSession)
	}
	for sid, sess := range s.sessions {
		if sess.protocol != protocol || !strings.HasPrefix(sid, prefix) {
			continue
		}
		if _, ok := desired[sess.ip]; !ok {
			gone = append(gone, kv{sess.email, sess.ip, sess.inboundId})
			delete(s.sessions, sid)
		}
	}
	for ip, want := range desired {
		sid := localSessionKey(protocol, ip)
		if existing, ok := s.sessions[sid]; ok {
			if want.Email != "" {
				existing.email = want.Email
			}
			// Refreshed rather than left alone: a wg-c device that moved to another
			// inbound keeps its address, and a stale id here would bill its traffic to
			// the inbound it left.
			existing.inboundId = want.InboundID
			continue
		}
		s.sessions[sid] = &radiusSession{email: want.Email, ip: ip, protocol: protocol, inboundId: want.InboundID, started: time.Now()}
		added = append(added, ip)
	}
	s.mu.Unlock()

	// Fold + remove counters for vanished IPs OFF the lock (slow nft/db work), same
	// as the Acct-Stop path.
	for _, g := range gone {
		up, down := s.nft.ReadAndResetClientCounters(protocol, g.ip)
		vpn.TrafficSinkFor().FoldClientTraffic(g.email, protocol, g.inboundId, up, down)
		_ = s.nft.RemoveClientAccounting(protocol, g.ip)
	}
	for _, ip := range added {
		_ = s.nft.AddClientAccounting(protocol, ip)
	}
}

// DisabledEmails returns the set of accounts currently disabled: a quota/expiry hit or disabled in
// settings (client_traffics.enable = false). It is the rbridge.Sink counterpart of the per-service
// getDisabledEmails helpers.
func (s *RadiusService) DisabledEmails() map[string]bool {
	disabled := make(map[string]bool)
	db := vpn.DB()
	if db == nil {
		return disabled
	}
	var emails []string
	db.Table("client_traffics").Where("enable = ?", false).Pluck("email", &emails)
	for _, e := range emails {
		disabled[e] = true
	}
	return disabled
}

// GetActiveSessionEmails returns a set of emails with active sessions (for online status).
func (s *RadiusService) GetActiveSessionEmails() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make(map[string]bool)
	for _, sess := range s.sessions {
		result[sess.email] = true
	}
	return result
}

// lookupClient queries the DB for the client password. Returns error if client not found,
// disabled, or traffic-limited.
func (s *RadiusService) lookupClient(protocol string, inboundId int, username string) (string, error) {
	db := vpn.DB()

	var inbound model.Inbound
	if inboundId > 0 {
		if err := db.First(&inbound, inboundId).Error; err != nil {
			return "", fmt.Errorf("inbound %d not found", inboundId)
		}
	} else {
		// Protocol-level NAS-Identifier: resolve the account to its inbound by name.
		ib, err := s.findClientInbound(protocol, username)
		if err != nil {
			return "", err
		}
		inbound = *ib
	}

	if !inbound.Enable {
		return "", fmt.Errorf("inbound %d disabled", inboundId)
	}

	if string(inbound.Protocol) != protocol {
		return "", fmt.Errorf("inbound %d protocol mismatch: expected %s got %s", inboundId, protocol, inbound.Protocol)
	}

	// Parse settings to find the client
	type clientEntry struct {
		ID       string `json:"id"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Enable   bool   `json:"enable"`
	}
	type settingsJSON struct {
		Clients []clientEntry `json:"clients"`
	}

	var settings settingsJSON
	if err := jsonUnmarshal([]byte(inbound.Settings), &settings); err != nil {
		return "", fmt.Errorf("failed to parse settings for inbound %d", inboundId)
	}

	for _, client := range settings.Clients {
		if client.ID == username || client.Email == username {
			if !client.Enable {
				return "", fmt.Errorf("client %s disabled in settings", username)
			}

			// Check client_traffics enable (traffic/expiry limits)
			if client.Email != "" {
				var traffic struct{ Enable bool }
				if err := db.Table("client_traffics").
					Select("enable").
					Where("email = ?", client.Email).
					First(&traffic).Error; err == nil && !traffic.Enable {
					return "", fmt.Errorf("client %s traffic limit reached (email=%s)", username, client.Email)
				}
			}

			return client.Password, nil
		}
	}

	return "", fmt.Errorf("client %s not found in inbound %d", username, inboundId)
}

// lookupEmail finds the email for a username across all inbounds of the given protocol.
func (s *RadiusService) lookupEmail(protocol string, username string) string {
	db := vpn.DB()
	var inbounds []*model.Inbound
	db.Where("protocol = ?", protocol).Find(&inbounds)

	type clientEntry struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Slot  *int   `json:"slot"` // address-pool slot; nil = fall back to list index
	}
	type settingsJSON struct {
		Clients []clientEntry `json:"clients"`
	}

	for _, inbound := range inbounds {
		var settings settingsJSON
		if err := jsonUnmarshal([]byte(inbound.Settings), &settings); err != nil {
			continue
		}
		for _, client := range settings.Clients {
			if client.ID == username || client.Email == username {
				return client.Email
			}
		}
	}
	return ""
}

// KillSessionsByEmail tears down every active session whose email is in the set. It
// is the teardown the disable paths call, but the session map is SHARED across
// protocols, so it must dispatch by protocol family — SSTP and OpenConnect are
// HYBRID and must NOT be torn down with the generic PPP kill:
//   - L2TP/PPTP: kill the owning pppd by pid file (clean Acct-Stop) then delete the
//     ppp interface — the same reliable link teardown the User Limit eviction uses.
//   - SSTP: accel-ppp is ONE daemon per inbound (no per-connection pppd, and deleting
//     its ppp iface would desync the daemon), so evict natively through accel-cmd —
//     the analogue of ocserv's occtl path — routed per IP by the registered evictor.
//   - OpenConnect: skipped here entirely; ocserv sessions have no ppp interface and
//     their disable/eviction goes through occtl (the OpenConnect wave's own paths).
//   - IKEv2: a single shared charon serves every inbound, so eviction needs no inbound
//     routing — terminate the IKE SA holding this virtual IP via swanctl (registered
//     evictor).
//
// PORT NOTE: the sstp/ikev2 evictions are dispatched through vpn.EvictProtocolIP;
// until the protocol wave registers them, those calls fail with an explicit error
// and are logged — nothing is torn down blindly.
func (s *RadiusService) KillSessionsByEmail(emails map[string]bool) {
	s.mu.Lock()
	var toKill []string
	var protoKill []string
	var protoSet []string
	for _, sess := range s.sessions {
		if sess.protocol == "openconnect" {
			continue
		}
		if emails[sess.email] {
			switch sess.protocol {
			case "sstp", "ikev2":
				protoKill = append(protoKill, sess.ip)
				protoSet = append(protoSet, sess.protocol)
			default:
				toKill = append(toKill, sess.ip)
			}
		}
	}
	s.mu.Unlock()

	for _, ip := range toKill {
		// Graceful first: kill the owning pppd by its pid file (clean shutdown + Acct-Stop).
		// Then force the link down by deleting the interface — belt-and-suspenders, since the
		// pid file may be absent/stale, and deleting the interface guarantees the tunnel drops
		// (this is the same reliable teardown the User Limit eviction uses).
		s.killPppdByIP(ip)
		s.killPPPByIP(ip)
	}
	// SSTP/IKEv2: native eviction via the registered per-protocol evictor.
	// accel-cmd terminate / swanctl --terminate are idempotent, so a session that
	// another path already reaped is a harmless no-op.
	for i, ip := range protoKill {
		if err := vpn.EvictProtocolIP(protoSet[i], ip); err != nil {
			logger.Debugf("RADIUS: no %s evictor registered; cannot evict %s (%v)", protoSet[i], ip, err)
		}
	}
}

// killPppdByIP finds and kills the pppd process that owns the given PPP client IP.
func (s *RadiusService) killPppdByIP(ip string) {
	// Check all ppp interfaces for matching IP
	output, err := exec.CommandContext(context.Background(), "ip", "-o", "addr", "show").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(output), "\n") {
		if !strings.Contains(line, ip) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		iface := fields[1]
		if !strings.HasPrefix(iface, "ppp") {
			continue
		}
		// Read PID file for this interface
		pidFile := fmt.Sprintf("/var/run/%s.pid", iface)
		pidData, err := os.ReadFile(pidFile)
		if err != nil {
			continue
		}
		pid := strings.TrimSpace(string(pidData))
		if pid != "" {
			// Best-effort kill: the session is already gone from the panel's view,
			// and pppd exiting on its own is the same end state.
			_ = exec.CommandContext(context.Background(), "kill", pid).Run()
			logger.Infof("RADIUS: killed pppd pid=%s iface=%s ip=%s", pid, iface, ip)
		}
	}
}

// CleanStaleSessions removes sessions whose PPP interface no longer exists.
//
// Skips "cp:"-keyed sessions: ReconcileLocalSessions owns those, and it already derives them
// each tick from the protocol's own liveness source (WireGuard handshake times, swanctl SAs),
// folding their bytes on the way out. isIPActive cannot judge them anyway: it looks for the
// address on a local interface, but a WireGuard peer's address is never local, and for the
// gateway model sess.ip is a block CIDR ("10.7.1.2/32") rather than a bare address. So every
// wg-c/awg session read as dead on every pass: the sweep re-added it seconds later, and the
// resulting remove/add churn was what let duplicate accounting rules accumulate.
func (s *RadiusService) CleanStaleSessions() {
	s.mu.Lock()
	now := time.Now()
	var stale []string
	for sid, sess := range s.sessions {
		if strings.HasPrefix(sid, "cp:") {
			continue
		}
		if sess.protocol == "openconnect" && !ocProbeReady(sess, now) {
			continue
		}
		if !s.sessionActive(sess) {
			stale = append(stale, sid)
		}
	}
	for _, sid := range stale {
		sess := s.sessions[sid]
		delete(s.sessions, sid)
		s.mu.Unlock()
		// Fold what the counters hold before deleting them, mirroring Acct-Stop:
		// otherwise every session that ends without one (which is every OpenConnect
		// session that did not report a stop) silently drops its last window of traffic.
		up, down := s.nft.ReadAndResetClientCounters(sess.protocol, sess.ip)
		vpn.TrafficSinkFor().FoldClientTraffic(sess.email, sess.protocol, sess.inboundId, up, down)
		// Best-effort: the session is already deleted above, so a failed counter
		// teardown only leaves a zeroed set to be reclaimed later.
		_ = s.nft.RemoveClientAccounting(sess.protocol, sess.ip)
		logger.Infof("RADIUS: cleaned stale session=%s email=%s ip=%s", sid, sess.email, sess.ip)
		s.mu.Lock()
	}
	s.mu.Unlock()
}

// ocProbeReady reports whether an OpenConnect session may be judged by the route probe
// yet. Both gates exist because a false "stale" verdict does not merely lose the
// session: it frees the address, which the account's next device is then handed while
// the first one is still using it, and ocserv does not detect a duplicate explicitly
// assigned address (see the auth path). Two tunnels on one address means the kernel
// keeps one route and the other device's return traffic goes to the wrong tun: it stays
// connected and passes nothing, which is only cleared by reconnecting it, which then
// does the same to its twin.
//
//   - Just authenticated: the session is recorded at auth, but ocserv only creates the
//     tun (and thus the route) after the client comes back with its cookie, so the probe
//     reads a false negative until then. allocateBlockIP's own reclaim already waits out
//     this window; the 60s sweep did not, and it is a wall-clock tick that can land
//     anywhere, including inside it.
//   - Recently heard from: an Interim-Update is ocserv itself saying the tunnel is up,
//     which beats anything inferred from the routing table.
func ocProbeReady(sess *radiusSession, now time.Time) bool {
	if now.Sub(sess.started) < ocStaleReclaimGrace {
		return false
	}
	if !sess.heard.IsZero() && now.Sub(sess.heard) < ocHeartbeatGrace {
		return false
	}
	return true
}

// vpnProbeTimeout bounds the helper commands the RADIUS paths shell out to (the
// liveness probe, the eviction CLIs). They run while a client's Access-Request is
// waiting and, for the eviction, while s.mu is held, so one that blocks stalls every
// other login on the box. occtl in particular talks to ocserv's MAIN process, which can
// itself be waiting on sec-mod, which is waiting for the very reply we have not written
// yet: the same circular wait the IKEv2 eviction had to be made asynchronous for. A
// missed probe just retries on the next sweep, so failing fast is the cheap side.
const vpnProbeTimeout = 3 * time.Second

// probeCmd runs a short-lived helper command under vpnProbeTimeout and returns its
// stdout.
func probeCmd(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), vpnProbeTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

// sessionActive reports whether a tracked session's tunnel is still up, routing
// OpenConnect through the injectable probe (ocActiveFn) so the sweep can be exercised
// without a real ocserv route table.
func (s *RadiusService) sessionActive(sess *radiusSession) bool {
	if sess.protocol == "openconnect" {
		return s.ocIsActive(sess.ip)
	}
	return s.isIPActive(sess.ip, sess.protocol)
}

// isIPActive checks if a VPN client IP is still reachable through its tunnel.
//
// PORT NOTE: vpn-ui routed the ikev2 branch to Ikev2Service (swanctl SA list). Here
// protocols with a daemon-owned probe consult the registry (vpn.RegisterIPProber);
// the registry's fail-open default treats unregistered protocols as active.
func (s *RadiusService) isIPActive(ip string, protocol string) bool {
	switch protocol {
	case "openvpn":
		// A route to the IP exists through OpenVPN's tun device.
		output, err := probeCmd("ip", "route", "get", ip)
		if err != nil {
			return false // no route = not active
		}
		return strings.Contains(string(output), "tun-ovpn")
	case "openconnect":
		// ocserv client IPs are peers on the ocserv tun (not local addrs), so check
		// for a route through an ocserv device rather than scanning `ip addr show`.
		output, err := probeCmd("ip", "route", "get", ip)
		if err != nil {
			return false
		}
		return strings.Contains(string(output), "ocserv")
	case "ikev2":
		// charon assigns the client's virtual IP as a remote vip (not a local addr),
		// so ask whether any live IKE SA still holds it — the ikev2 wave registers
		// this probe (swanctl --list-sas).
		return vpn.ProbeIPActive("ikev2", ip)
	default: // l2tp / pptp: the IP is assigned to a local PPP interface
		output, err := exec.CommandContext(context.Background(), "ip", "-o", "addr", "show").Output()
		if err != nil {
			return true // assume active on error
		}
		return strings.Contains(string(output), ip)
	}
}

// parseNASIdentifier extracts protocol and inbound ID from a NAS-Identifier.
// Two forms are accepted:
//   - protocol-level, e.g. "l2tp" / "pptp": inboundId is 0, meaning "resolve the
//     account to its owning inbound by username". This is what the shared daemon
//     configs now send — one xl2tpd/pptpd instance serves every inbound of a
//     protocol on its single fixed port, so it can carry only ONE NAS-Identifier.
//   - per-inbound, e.g. "l2tp-3" / "pptp-5": kept for backward compatibility.
func parseNASIdentifier(nasID string) (protocol string, inboundId int, err error) {
	if nasID == "l2tp" || nasID == "pptp" || nasID == "openvpn" || nasID == "openconnect" || nasID == "sstp" || nasID == "ikev2" {
		return nasID, 0, nil
	}

	parts := strings.SplitN(nasID, "-", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid NAS-Identifier format: %s", nasID)
	}

	protocol = parts[0]
	if protocol != "l2tp" && protocol != "pptp" && protocol != "openvpn" && protocol != "openconnect" && protocol != "sstp" && protocol != "ikev2" {
		return "", 0, fmt.Errorf("unknown protocol in NAS-Identifier: %s", protocol)
	}

	_, err = fmt.Sscanf(parts[1], "%d", &inboundId)
	if err != nil {
		return "", 0, fmt.Errorf("invalid inbound ID in NAS-Identifier: %s", nasID)
	}

	return protocol, inboundId, nil
}

// findClientInbound locates the enabled inbound of the given protocol whose
// settings contain a client with this username. Used when the RADIUS request
// carries a protocol-level NAS-Identifier (inboundId 0): a single shared
// xl2tpd/pptpd config serves all inbounds of a protocol, so the account is mapped
// to its owning inbound here rather than via the NAS-Identifier. Usernames are
// expected to be unique across a protocol's inbounds; the first match wins.
func (s *RadiusService) findClientInbound(protocol, username string) (*model.Inbound, error) {
	db := vpn.DB()
	var inbounds []*model.Inbound
	if err := db.Where("protocol = ? AND enable = ?", protocol, true).Find(&inbounds).Error; err != nil {
		return nil, err
	}
	for _, inbound := range inbounds {
		var settings struct {
			Clients []struct {
				ID    string `json:"id"`
				Email string `json:"email"`
			} `json:"clients"`
		}
		if jsonUnmarshal([]byte(inbound.Settings), &settings) != nil {
			continue
		}
		for _, c := range settings.Clients {
			if c.ID == username || c.Email == username {
				return inbound, nil
			}
		}
	}
	return nil, fmt.Errorf("client %s not found in any %s inbound", username, protocol)
}

// sessionInboundByIP resolves a tunnel address to the inbound whose address pool it
// was handed out of. Returns 0 when nothing owns it.
//
// This is how l2tp, pptp and ikev2 sessions learn their inbound. All three share one
// daemon and send a bare protocol name as their NAS-Identifier, which
// parseNASIdentifier resolves to 0, while openvpn, openconnect and sstp name theirs
// outright ("<proto>-<inboundId>") and never come here.
//
// Deliberately NOT findClientInbound or lookupEmail. Both answer "the first inbound
// of this protocol holding a client with that name", by ascending id, which is a
// first-match-wins guess of exactly the kind that produced the bug this attribution
// exists to fix: it would file every membership's bytes under the lowest-id inbound
// and look entirely plausible doing it. The address is a fact - the panel allocated
// it from one specific inbound's pool in getClientIP - so it is matched instead.
func (s *RadiusService) sessionInboundByIP(protocol, ip string) int {
	if ip == "" || ip == "<nil>" {
		return 0
	}
	addr := net.ParseIP(ip)
	if addr == nil {
		return 0
	}
	db := vpn.DB()
	if db == nil {
		return 0
	}
	var inbounds []*model.Inbound
	// Ascending, so a pool an operator has configured to overlap another resolves
	// the same way every tick rather than flapping between two inbounds.
	if err := db.Where("protocol = ?", protocol).Order("id ASC").Find(&inbounds).Error; err != nil {
		logger.Debug("RADIUS: cannot resolve the session inbound for ", protocol, ": ", err)
		return 0
	}
	for _, inbound := range inbounds {
		for _, subnet := range vpn.SubnetsForInbound(protocol, inbound) {
			if subnetHoldsIP(subnet, addr) {
				return inbound.Id
			}
		}
	}
	return 0
}

// subnetHoldsIP reports whether a subnet in either of the two shapes the resolvers
// return covers addr: a CIDR ("10.6.8.0/24", from ikev2-style block pools) or a bare
// /24 prefix ("10.0.7", from l2tp and pptp).
func subnetHoldsIP(subnet string, addr net.IP) bool {
	if subnet == "" {
		return false
	}
	if strings.Contains(subnet, "/") {
		_, network, err := net.ParseCIDR(subnet)
		if err != nil {
			return false
		}
		return network.Contains(addr)
	}
	// A three-octet prefix. Compared octet by octet rather than with a string
	// prefix, which would match 10.0.1 against 10.0.10.x.
	v4 := addr.To4()
	if v4 == nil {
		return false
	}
	return fmt.Sprintf("%d.%d.%d", v4[0], v4[1], v4[2]) == subnet
}

// ResetAllocations drops the RADIUS service's cached per-device IP assignments for
// a protocol (keys are "protocol:inboundId:..."). Call it when an inbound's
// settings change — User Limit, IP ranges, or strategy — because those shift the
// account block layout: an account's device IPs move, and the routing map is
// re-translated to the new IPs. A device that kept its OLD cached IP (via the
// idempotent-redial cache) would then land on an address the new source-IP routing
// rules don't cover, so its traffic isn't routed — the classic "the UI change
// wasn't honored" symptom. Clearing the cache makes each device re-allocate under
// the new layout on its next dial (l2tp/pptp restart the shared daemon here, so
// every device redials anyway). Only the IP caches are touched; live sessions and
// nft accounting counters are left intact.
func ResetAllocations(protocol string) {
	s := runningRadius
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix := protocol + ":"
	for k := range s.stationIP {
		if strings.HasPrefix(k, prefix) {
			delete(s.stationIP, k)
		}
	}
	for k := range s.stationSeen {
		if strings.HasPrefix(k, prefix) {
			delete(s.stationSeen, k)
		}
	}
	// Pending leases are keyed by IP (not by protocol) and live only seconds; drop
	// them all so no stale pre-change lease pins an address under the old layout.
	s.pending = map[string]time.Time{}
}

// jsonUnmarshal is a thin alias so the package's many settings decodes read the
// same as the source (encoding/json) without each file importing it separately.
func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
