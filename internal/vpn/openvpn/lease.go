// The OpenVPN hook-side lease machinery and CLI verbs, ported from vpn-ui
// main.go (readRadiusSecret, openvpnAuth, ovpnLeaseBlockIP + the ovpn* lease
// helpers, openvpnConnect, openvpnDisconnect, openvpnEvict).
//
// The server config generator (openvpn.go buildServerConfig) wires these into
// every OpenVPN instance as the auth-user-pass-verify / client-connect /
// client-disconnect scripts: the panel binary itself is invoked as
// `<binary> openvpn-auth <inbound_id> <cred_file>` etc. by OpenVPN, so the verbs
// are entry points of a SEPARATE SHORT-LIVED PROCESS, never called in-process.
// They therefore keep vpn-ui's os.Args + os.Exit shape verbatim (os.Exit is
// correct here in a way it never is in library code); the CLI dispatch table
// itself hangs off the main binary in the controllers wave.
//
// Auth/acct go to the panel's in-process RADIUS server as PAP Access-Request /
// Acct-Start / Acct-Stop packets with NAS-Identifier "openvpn-<inbound_id>",
// exactly as in vpn-ui — openvpn sessions therefore live in the radius
// foundation's session registry, which already carries the "openvpn" liveness
// probe (plain `ip route get` through the tun-ovpn device).
package openvpn

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/vpn"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

// readRadiusSecret returns the RADIUS shared secret used by the OpenVPN auth/connect
// /disconnect hooks. Canonical source is the panel DB (settings key `radiusSecret`,
// written by getOrCreateRadiusSecret on startup): these hooks are separate short-lived
// processes that don't hold the panel's in-memory secret, and the DB is the single
// source of truth. The legacy /etc/ppp/radius/servers file is only a fallback — it is
// written solely by l2tp/pptp setup, so on an OpenVPN-only box it doesn't exist, which
// is why reading only that file rejected every OpenVPN login ("RADIUS secret not found").
//
// PORT NOTE: vpn-ui read the DB via database.GetSettingValue(config.GetDBPath(), ...)
// against the sqlite file; here the settings KV is reached through the injected
// vpn.DB handle (same row, same key — vpn.RadiusSecret), so the hook process still
// needs no CGO sqlite driver.
func readRadiusSecret() string {
	if secret, ok := vpn.RadiusSecret(); ok && secret != "" {
		return secret
	}
	// Fallback: the radcli servers file, present only when l2tp/pptp is configured.
	data, err := os.ReadFile("/etc/ppp/radius/servers")
	if err != nil {
		return ""
	}
	// Format: "127.0.0.1\t{secret}\n"
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "127.0.0.1" {
			return fields[1]
		}
	}
	return ""
}

// Auth handles OpenVPN auth-user-pass-verify via RADIUS PAP.
// Usage: pxpanel openvpn-auth {inbound_id} {credentials_file}
// The credentials file has username on line 1, password on line 2.
func Auth() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: pxpanel openvpn-auth <inbound_id> <cred_file>")
		os.Exit(1)
	}

	inboundId, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid inbound_id:", os.Args[2])
		os.Exit(1)
	}

	credFile := os.Args[3]
	data, err := os.ReadFile(credFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to read credentials file:", err)
		os.Exit(1)
	}

	lines := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)
	if len(lines) < 2 {
		fmt.Fprintln(os.Stderr, "credentials file must have username and password on separate lines")
		os.Exit(1)
	}
	username := strings.TrimSpace(lines[0])
	password := strings.TrimSpace(lines[1])

	secret := readRadiusSecret()
	if secret == "" {
		fmt.Fprintln(os.Stderr, "RADIUS secret not found")
		os.Exit(1)
	}

	// Send PAP Access-Request
	packet := radius.New(radius.CodeAccessRequest, []byte(secret))
	// Attribute setters can only fail on an over-long (>253-byte) value; these
	// three are the hook's own short arguments, and the exchange below is what
	// reports a request the server rejected.
	_ = rfc2865.UserName_SetString(packet, username)
	_ = rfc2865.UserPassword_SetString(packet, password)
	_ = rfc2865.NASIdentifier_SetString(packet, fmt.Sprintf("openvpn-%d", inboundId))

	resp, err := radius.Exchange(context.Background(), packet, "127.0.0.1:1812")
	if err != nil {
		fmt.Fprintln(os.Stderr, "RADIUS exchange failed:", err)
		os.Exit(1)
	}

	if resp.Code == radius.CodeAccessAccept {
		os.Exit(0) // Accept
	}
	os.Exit(1) // Reject
}

// Connect handles OpenVPN client-connect via RADIUS Acct-Start.
// Usage: pxpanel openvpn-connect {inbound_id}
// Reads common_name and ifconfig_pool_remote_ip from environment.
func Connect() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: pxpanel openvpn-connect <inbound_id>")
		os.Exit(1)
	}

	inboundId, _ := strconv.Atoi(os.Args[2])
	username := os.Getenv("common_name")
	ip := os.Getenv("ifconfig_pool_remote_ip")

	if username == "" || ip == "" {
		os.Exit(0) // Nothing to do
	}

	// User Limit K>=2: if the panel published a block for this account, lease a
	// free IP inside it and push it to this device (duplicate-cn lets K devices
	// share the CN). os.Args[3] is OpenVPN's writable per-session config file.
	leased, mask, reject := ovpnLeaseBlockIP(inboundId, username, ip, ovpnSessionKey())
	if reject {
		// User Limit reached with strategy=reject: a non-zero exit from a
		// client-connect script makes OpenVPN refuse this device.
		fmt.Fprintln(os.Stderr, "user limit reached; rejecting client")
		os.Exit(1)
	}
	if leased != "" {
		if len(os.Args) >= 4 && os.Args[3] != "" {
			_ = os.WriteFile(os.Args[3], []byte(fmt.Sprintf("ifconfig-push %s %s\n", leased, mask)), 0o644)
		}
		ip = leased
	}

	secret := readRadiusSecret()
	if secret == "" {
		os.Exit(0)
	}

	sessionID := fmt.Sprintf("openvpn-%d-%s-%s", inboundId, username, ip)

	packet := radius.New(radius.CodeAccountingRequest, []byte(secret))
	_ = rfc2866.AcctStatusType_Set(packet, rfc2866.AcctStatusType_Value_Start)
	_ = rfc2866.AcctSessionID_SetString(packet, sessionID)
	_ = rfc2865.UserName_SetString(packet, username)
	_ = rfc2865.NASIdentifier_SetString(packet, fmt.Sprintf("openvpn-%d", inboundId))
	_ = rfc2865.FramedIPAddress_Set(packet, net.ParseIP(ip))

	resp, err := radius.Exchange(context.Background(), packet, "127.0.0.1:1813")
	if err != nil {
		fmt.Fprintf(os.Stderr, "RADIUS acct-start failed: %v\n", err)
		os.Exit(0)
	}
	if resp.Code != radius.CodeAccountingResponse {
		fmt.Fprintf(os.Stderr, "RADIUS acct-start unexpected code: %v\n", resp.Code)
	}
	os.Exit(0)
}

// Disconnect handles OpenVPN client-disconnect via RADIUS Acct-Stop.
// Usage: pxpanel openvpn-disconnect {inbound_id}
// Reads common_name and ifconfig_pool_remote_ip from environment.
func Disconnect() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: pxpanel openvpn-disconnect <inbound_id>")
		os.Exit(1)
	}

	inboundId, _ := strconv.Atoi(os.Args[2])
	username := os.Getenv("common_name")
	ip := os.Getenv("ifconfig_pool_remote_ip")

	if username == "" || ip == "" {
		os.Exit(0)
	}

	// Free this device's block gap-lease immediately (leases are named by block IP,
	// keyed by the pool IP) so the slot reopens now instead of at the lease TTL, and
	// recover the leased block IP so this Acct-Stop's session-id matches the Acct-Start
	// the connect hook sent (which used the leased IP, not the pool IP).
	proto := "udp"
	if strings.HasPrefix(ip, "10.3.") {
		proto = "tcp"
	}
	dir := fmt.Sprintf("/etc/openvpn/server-%d", inboundId)
	leaseDir := filepath.Join(dir, "leases-"+proto)
	if leased := ovpnRemoveLeaseBySession(leaseDir, ovpnSessionKey()); leased != "" {
		// Tell the connect hook this address is free NOW; the status file will not say
		// so for up to another 5s, and a redial in between would be refused.
		ovpnWriteRelease(dir, proto, leased)
		ip = leased
	}

	secret := readRadiusSecret()
	if secret == "" {
		os.Exit(0)
	}

	sessionID := fmt.Sprintf("openvpn-%d-%s-%s", inboundId, username, ip)

	// Read session duration from env (OpenVPN provides time_duration in seconds)
	var sessionTime uint32
	if dur := os.Getenv("time_duration"); dur != "" {
		if d, err := strconv.ParseUint(dur, 10, 32); err == nil {
			sessionTime = uint32(d)
		}
	}

	packet := radius.New(radius.CodeAccountingRequest, []byte(secret))
	_ = rfc2866.AcctStatusType_Set(packet, rfc2866.AcctStatusType_Value_Stop)
	_ = rfc2866.AcctSessionID_SetString(packet, sessionID)
	_ = rfc2865.UserName_SetString(packet, username)
	_ = rfc2865.NASIdentifier_SetString(packet, fmt.Sprintf("openvpn-%d", inboundId))
	_ = rfc2865.FramedIPAddress_Set(packet, net.ParseIP(ip))
	if sessionTime > 0 {
		_ = rfc2866.AcctSessionTime_Set(packet, rfc2866.AcctSessionTime(sessionTime))
	}

	_, _ = radius.Exchange(context.Background(), packet, "127.0.0.1:1813")
	os.Exit(0)
}

// Evict runs detached from the (synchronous, management-blocking) client-
// connect hook. It waits for that hook to return so OpenVPN resumes servicing its
// management socket, then disconnects the victim via `kill <real-address>` (the
// classic per-client kill — `client-kill <CID>` only applies to deferred-auth
// clients). The new client reuses the victim's VIRTUAL IP, but real addresses are
// unique, so this hits the old device, not the one just admitted. Falls back to the
// OLDEST client on <ip> when no real address was pre-captured.
// Usage: pxpanel openvpn-evict <id> <proto> <ip> [real-address]
func Evict() {
	if len(os.Args) < 5 {
		return
	}
	inboundId, _ := strconv.Atoi(os.Args[2])
	proto := os.Args[3]
	targetIP := os.Args[4]
	raddr := ""
	if len(os.Args) >= 6 {
		raddr = os.Args[5]
	}
	time.Sleep(1500 * time.Millisecond) // let the connect hook return first

	sock := fmt.Sprintf("/var/run/openvpn/mgmt-%d-%s.sock", inboundId, proto)
	var dialer net.Dialer
	conn, err := dialer.DialContext(context.Background(), "unix", sock)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	if raddr == "" {
		// No pre-captured real address: query live and pick the OLDEST client on
		// targetIP (min connected-since) so the just-admitted client (newest) is
		// never the one killed when two share the virtual IP.
		if _, err := fmt.Fprint(conn, "status 3\n"); err != nil {
			return
		}
		bestSince := int64(1) << 62
		for {
			line, rerr := reader.ReadString('\n')
			if s := strings.TrimRight(line, "\r\n"); s != "" {
				if strings.HasPrefix(s, "CLIENT_LIST\t") {
					f := strings.Split(s, "\t")
					if len(f) > 8 && f[3] == targetIP {
						if since, perr := strconv.ParseInt(strings.TrimSpace(f[8]), 10, 64); perr == nil && since < bestSince {
							bestSince, raddr = since, strings.TrimSpace(f[2])
						}
					}
				}
				if s == "END" {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
	}
	if raddr == "" {
		return
	}
	fmt.Fprintf(conn, "kill %s\n", raddr)
	// Read past the management greeting / async lines until the kill verdict so the
	// command is flushed and processed before we close the socket.
	for i := 0; i < 20; i++ {
		line, rerr := reader.ReadString('\n')
		s := strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(s, "SUCCESS") || strings.HasPrefix(s, "ERROR") {
			break
		}
		if rerr != nil {
			break
		}
	}
}

// ovpnLeaseBlockIP implements the OpenVPN side of the per-account "User Limit"
// block allocation. When the panel has published blocks-<proto>/<CN> for this
// inbound (User Limit K>=2), it leases the lowest free IP inside that account's
// block and returns (ip, serverBlockMask, false) for a `ifconfig-push`. Returns
// ("","",false) for K==1 inbounds (no block file) — the caller keeps the pool IP.
//
// When the block is full the User Limit Strategy decides: "accept" force-kills the
// account's oldest device via the management socket and reuses its IP (returns that
// ip); "reject" (default) returns ("","",true) so the caller fails the connect and
// OpenVPN refuses the device.
//
// "Free" = not currently held by an established client (OpenVPN's own status
// file, authoritative) and not held by a fresh lease (a short-TTL marker that
// bridges the gap between this connect and the client appearing in the status
// file). Leaked leases self-expire, so no long-lived bookkeeping is needed.
// ovpnLeaseReclaimGrace is the minimum age of a gap-lease before it may be
// reclaimed for a new dial. OpenVPN rewrites the status file every 5s, so any
// live device is listed within 5s of connecting; a lease older than this that is
// still absent from the status is therefore an abandoned ghost — safe to reclaim
// without stealing a slot from a device that is merely mid-handshake.
const ovpnLeaseReclaimGrace = 10 * time.Second

func ovpnLeaseBlockIP(inboundId int, username, poolIP, sessionKey string) (string, string, bool) {
	proto := "udp"
	if strings.HasPrefix(poolIP, "10.3.") {
		proto = "tcp"
	}
	dir := fmt.Sprintf("/etc/openvpn/server-%d", inboundId)
	blockFile := filepath.Join(dir, "blocks-"+proto, username)
	data, err := os.ReadFile(blockFile)
	if err != nil {
		return "", "", false // no block published -> K==1, keep the pool IP
	}
	parts := strings.Fields(strings.TrimSpace(string(data)))
	if len(parts) < 2 {
		return "", "", false
	}
	// Block file format: "<serverBlockMask> <ip1> <ip2> ..." — the account's K
	// device IPs (an explicit list, so the block size need not be a power of two).
	mask := parts[0]
	candidates := parts[1:]

	// Serialize concurrent client-connect hooks for this inbound+proto. They run as
	// separate short-lived processes sharing the lease dir, so without a lock two
	// devices dialing at once can both read the block as free and lease the SAME IP
	// (an over-admit / duplicate-IP race). An exclusive flock makes the whole
	// read-decide-write below atomic across hooks; it releases when this process exits.
	if lf, lerr := os.OpenFile(filepath.Join(dir, "connect-"+proto+".lock"), os.O_CREATE|os.O_RDWR, 0o644); lerr == nil {
		defer lf.Close()
		if syscall.Flock(int(lf.Fd()), syscall.LOCK_EX) == nil {
			defer func() { _ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN) }()
		}
	}

	statusPath := fmt.Sprintf("/var/run/openvpn/status-%d-%s.log", inboundId, proto)
	liveStatus := ovpnStatusIPs(statusPath) // devices OpenVPN currently reports connected
	inUse := make(map[string]bool, len(liveStatus))
	for ip := range liveStatus {
		inUse[ip] = true
	}

	// Addresses openvpn has told us are free but the status file still shows connected
	// (it is rewritten only every 5s). Applied after the lease scan below, so a new
	// device that has already leased one of them still counts as holding it.
	released := ovpnReleasedIPs(dir, proto)

	leaseDir := filepath.Join(dir, "leases-"+proto)
	_ = os.MkdirAll(leaseDir, 0o755)
	now := time.Now()
	leaseAge := make(map[string]time.Duration) // block IP -> age of its gap-lease
	if entries, e := os.ReadDir(leaseDir); e == nil {
		for _, ent := range entries {
			p := filepath.Join(leaseDir, ent.Name())
			fi, se := os.Stat(p)
			if se != nil {
				continue
			}
			if now.Sub(fi.ModTime()) > 30*time.Second {
				os.Remove(p) // stale gap-lease past its TTL
				continue
			}
			inUse[ent.Name()] = true // lease file is named by the leased IP
			leaseAge[ent.Name()] = now.Sub(fi.ModTime())
		}
	}

	// A released address is only still in use if something leased it since: the release
	// came from openvpn itself, the status entry behind it is just stale.
	for ip := range released {
		if _, leased := leaseAge[ip]; !leased {
			delete(inUse, ip)
			delete(liveStatus, ip)
		}
	}

	// User Limit K is per ACCOUNT, not per transport. Count this transport's occupied
	// block slots PLUS the account's devices on the OTHER transport (which draws on the
	// same K budget), so an account that enables both udp and tcp can't run K devices on
	// each for 2*K total. The other transport is only consulted when its block exists.
	usedCount := 0
	for _, ip := range candidates {
		if inUse[ip] {
			usedCount++
		}
	}
	otherProto := "tcp"
	if proto == "tcp" {
		otherProto = "udp"
	}
	if oData, oErr := os.ReadFile(filepath.Join(dir, "blocks-"+otherProto, username)); oErr == nil {
		if oIPs := strings.Fields(strings.TrimSpace(string(oData))); len(oIPs) >= 2 {
			oStatus := ovpnStatusIPs(fmt.Sprintf("/var/run/openvpn/status-%d-%s.log", inboundId, otherProto))
			oLease := ovpnLeasedIPs(filepath.Join(dir, "leases-"+otherProto))
			for _, ip := range oIPs[1:] { // skip the mask
				if oStatus[ip] || oLease[ip] {
					usedCount++
				}
			}
		}
	}

	// (1) A free slot for this new device — only while the account is under K in total.
	if usedCount < len(candidates) {
		for _, ip := range candidates {
			if inUse[ip] {
				continue
			}
			ovpnWriteLease(leaseDir, ip, sessionKey)
			ovpnClearRelease(dir, proto, ip)
			return ip, mask, false
		}
	}

	// The block is full — but a gap-lease can outlive its device by up to 30s, so "full"
	// may be an illusion.
	//
	// Reclaiming a slot pinned ONLY by a stale gap-lease is cleanup, not admission, so it
	// happens for EITHER strategy: a ghost is a lease with no device behind it, and
	// handing its address to a new dial keeps the number of LIVE devices within K either
	// way. This used to sit inside the "accept" branch below, which made a "reject"
	// inbound refuse an account's own redial (AUTH_FAILED, since a failing client-connect
	// script is reported to the client as an auth failure) for as long as the previous
	// lease lived. Any dial that does not complete leaves such a lease, so on a
	// reject inbound a client that dropped and came back looked permanently broken while
	// its User Limit was never actually exceeded.
	//
	// A ghost = a lease older than the grace whose IP is NOT in the status. OpenVPN
	// rewrites the status every 5s, so any real device is listed within 5s of connecting;
	// a >grace lease still absent from the status is abandoned, not a device merely
	// mid-handshake. Reclaim the OLDEST such ghost.
	var ghostIP string
	var ghostAge time.Duration
	for _, ip := range candidates {
		if liveStatus[ip] {
			continue // a genuinely connected device — never a ghost
		}
		if age, leased := leaseAge[ip]; leased && age > ovpnLeaseReclaimGrace && age > ghostAge {
			ghostIP, ghostAge = ip, age
		}
	}
	if ghostIP != "" {
		ovpnWriteLease(leaseDir, ghostIP, sessionKey)
		ovpnClearRelease(dir, proto, ghostIP)
		return ghostIP, mask, false
	}

	// Past that, the block really is held by live devices. "accept": evict the account's
	// oldest device and take its address. "reject" (default): refuse.
	if ovpnReadStrategy(dir, proto) == "accept" {
		// A real device-cap hit: evict the oldest LIVE device and reuse its IP. The kill
		// MUST happen AFTER this hook returns — client-connect runs synchronously and
		// blocks OpenVPN's management loop — so hand it to the detached openvpn-evict
		// helper. Killing by the pre-captured real address hits the OLD device.
		victimIP, victimRAddr := ovpnOldestFromStatus(statusPath, candidates)
		if victimIP == "" {
			// The block is full by leases, but no device is in the (up to 5s-stale)
			// status file yet, so it can't name a victim. Fall back to the OLDEST
			// gap-lease and let the detached evictor kill whoever holds that IP via the
			// LIVE management socket (openvpn-evict queries `status 3` when given no real
			// address). WITHOUT this, "accept" wrongly behaved like "reject" for any
			// device dialing within ~5s of the incumbents (the status hadn't flushed, so
			// the eviction never fired) — the "accept always rejects" bug.
			victimIP = oldestLeasedIP(leaseAge)
			if victimIP == "" {
				return "", "", true // genuinely nothing leased to reuse — refuse
			}
		}
		ovpnSpawnEvict(inboundId, proto, victimIP, victimRAddr)
		ovpnWriteLease(leaseDir, victimIP, sessionKey)
		ovpnClearRelease(dir, proto, victimIP)
		return victimIP, mask, false
	}
	return "", "", true // reject the new device
}

// oldestLeasedIP returns the block IP holding the oldest gap-lease (the account's
// longest-connected device — the "accept" eviction victim when the status file is too
// stale to name one), or "" when there are no leases.
func oldestLeasedIP(leaseAge map[string]time.Duration) string {
	var ip string
	oldest := time.Duration(-1)
	for k, age := range leaseAge {
		if age > oldest {
			oldest, ip = age, k
		}
	}
	return ip
}

// ovpnWriteLease records a gap-lease file named by the leased block IP, storing the
// device's pool IP as content so the disconnect hook can find and free it by pool IP.
func ovpnWriteLease(leaseDir, blockIP, sessionKey string) {
	_ = os.WriteFile(filepath.Join(leaseDir, blockIP), []byte(sessionKey), 0o644)
}

// ovpnSessionKey identifies ONE device session, for matching a lease at disconnect back
// to the connect that wrote it.
//
// It must not be ifconfig_pool_remote_ip, which is what this used to be: every device on
// an inbound gets pushed a block address instead of the pool address, so openvpn keeps
// handing the SAME first pool address (the block's .2) to every client, and every lease
// file ended up holding that one value. Removal then matched the first lease in directory
// order rather than the disconnecting device's, which
//   - left the departing device's own lease behind, so on a "reject" inbound its redial
//     was refused as if its User Limit were full,
//   - freed a still-live device's lease, letting the account exceed its User Limit, and
//   - rebuilt the Acct-Stop session id from another device's address, so usage landed on
//     the wrong session ("acct-stop stale — ip=… reassigned to a live session").
//
// trusted_ip:trusted_port is the client's real transport address, unique per session and
// reported identically to the connect and disconnect hooks.
func ovpnSessionKey() string {
	ip, port := os.Getenv("trusted_ip"), os.Getenv("trusted_port")
	if ip == "" {
		ip = os.Getenv("trusted_ip6")
	}
	if ip == "" {
		// No real address in the environment: fall back to the pool address, which is
		// what the old scheme used. Still better than an empty key.
		return os.Getenv("ifconfig_pool_remote_ip")
	}
	if port == "" {
		return ip
	}
	return ip + ":" + port
}

// ovpnLeasedIPs returns the set of block IPs currently gap-leased in a transport's
// lease dir (fresh leases only; entries past the 30s TTL are ignored). Used to count
// the other transport's occupancy toward the shared per-account K budget.
func ovpnLeasedIPs(leaseDir string) map[string]bool {
	set := map[string]bool{}
	entries, err := os.ReadDir(leaseDir)
	if err != nil {
		return set
	}
	now := time.Now()
	for _, ent := range entries {
		fi, e := os.Stat(filepath.Join(leaseDir, ent.Name()))
		if e != nil || now.Sub(fi.ModTime()) > 30*time.Second {
			continue
		}
		set[ent.Name()] = true
	}
	return set
}

// ovpnRemoveLeaseBySession removes the gap-lease this device session holds (leases are
// named by block IP and hold the session key, see ovpnSessionKey) and returns the leased
// block IP, or "" if none matches. Called on client-disconnect so the slot frees
// immediately instead of lingering until the lease TTL, and so the Acct-Stop can be
// keyed by the same leased IP the connect hook used. A lease written by an older build
// holds a pool address instead and simply will not match: it ages out on the TTL.
func ovpnRemoveLeaseBySession(leaseDir, sessionKey string) string {
	entries, err := os.ReadDir(leaseDir)
	if err != nil {
		return ""
	}
	for _, ent := range entries {
		p := filepath.Join(leaseDir, ent.Name())
		content, e := os.ReadFile(p)
		if e == nil && sessionKey != "" && strings.TrimSpace(string(content)) == sessionKey {
			_ = os.Remove(p)
			return ent.Name()
		}
	}
	return ""
}

// ovpnReleaseTTL is how long a release marker counts. It only has to outlive the status
// file's write interval (status ... 5), with room for a slow rewrite.
const ovpnReleaseTTL = 15 * time.Second

// ovpnWriteRelease records that openvpn just told us a device left this block address.
// The status file is rewritten every 5s, so for a few seconds after a disconnect the
// departed device is still listed as connected, and a block whose addresses all look
// occupied is refused: an account that dropped and redialled straight away was answered
// with AUTH_FAILED although its User Limit was not reached. The management socket would
// give the live table, but client-connect runs INSIDE openvpn's event loop (which is why
// the evictor is a detached helper), so asking it from the hook would deadlock until the
// timeout. The disconnect hook already knows exactly which address was freed, so it says
// so here and the connect hook believes it over the stale file.
func ovpnWriteRelease(dir, proto, blockIP string) {
	if blockIP == "" {
		return
	}
	relDir := filepath.Join(dir, "released-"+proto)
	if err := os.MkdirAll(relDir, 0o755); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(relDir, blockIP), nil, 0o644)
}

// ovpnReleasedIPs returns the block IPs released within the TTL, expiring older markers.
func ovpnReleasedIPs(dir, proto string) map[string]bool {
	set := map[string]bool{}
	relDir := filepath.Join(dir, "released-"+proto)
	entries, err := os.ReadDir(relDir)
	if err != nil {
		return set
	}
	now := time.Now()
	for _, ent := range entries {
		p := filepath.Join(relDir, ent.Name())
		fi, serr := os.Stat(p)
		if serr != nil {
			continue
		}
		if now.Sub(fi.ModTime()) > ovpnReleaseTTL {
			os.Remove(p)
			continue
		}
		set[ent.Name()] = true
	}
	return set
}

// ovpnClearRelease drops a release marker once the address is handed out again.
func ovpnClearRelease(dir, proto, blockIP string) {
	os.Remove(filepath.Join(dir, "released-"+proto, blockIP))
}

// ovpnReadStrategy returns the inbound's User Limit Strategy ("accept", else the
// default "reject") from the panel-published strategy-<proto> file.
func ovpnReadStrategy(dir, proto string) string {
	data, err := os.ReadFile(filepath.Join(dir, "strategy-"+proto))
	if err != nil {
		return "reject"
	}
	if strings.TrimSpace(string(data)) == "accept" {
		return "accept"
	}
	return "reject"
}

// ovpnOldestFromStatus reads the OpenVPN status-version 3 FILE and returns the
// virtual IP and client-ID (among ips) of the client connected longest, or ("","")
// if none appear yet. The connect hook uses the file (not the live management
// socket) to pick the eviction victim, because while the hook runs OpenVPN's
// management loop is blocked (see Evict).
func ovpnOldestFromStatus(statusPath string, ips []string) (ip, raddr string) {
	want := make(map[string]bool, len(ips))
	for _, w := range ips {
		want[w] = true
	}
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return "", ""
	}
	bestSince := int64(1) << 62
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CLIENT_LIST\t") {
			continue
		}
		// status v3: [2]RealAddr [3]VirtualAddr [8]ConnectedSince(time_t)
		f := strings.Split(line, "\t")
		if len(f) <= 8 || !want[f[3]] {
			continue
		}
		if since, perr := strconv.ParseInt(strings.TrimSpace(f[8]), 10, 64); perr == nil && since < bestSince {
			bestSince, ip, raddr = since, f[3], strings.TrimSpace(f[2])
		}
	}
	return ip, raddr
}

// ovpnSpawnEvict launches a detached `openvpn-evict` helper that disconnects the
// victim client once OpenVPN is servicing its management socket again. Fire-and-
// forget: the connect hook must not wait on it. raddr is the victim's real address
// (IP:port — the unambiguous per-client kill key); ip is the fallback when the
// status file had no entry yet.
func ovpnSpawnEvict(inboundId int, proto, ip, raddr string) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.CommandContext(context.Background(), exe, "openvpn-evict", strconv.Itoa(inboundId), proto, ip, raddr)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // survive the hook exiting
	_ = cmd.Start()                                      // no Wait: detached
}

// ovpnStatusIPs parses an OpenVPN status-version 3 file and returns the set of
// virtual (tunnel) IPs currently held by connected clients.
func ovpnStatusIPs(statusPath string) map[string]bool {
	set := map[string]bool{}
	// OpenVPN rewrites this file IN PLACE every few seconds; a read that lands mid-
	// rewrite sees a truncated file (missing CLIENT_LIST rows). Under User Limit
	// "reject" that makes a live device look absent and wrongly admits an extra one.
	// A complete status ends with an "END" line — read a few times until we see one,
	// and union every read's rows so a partial snapshot can only ADD, never drop, a
	// device (a more-complete "used" set is always the safe direction).
	for attempt := 0; attempt < 8; attempt++ {
		data, err := os.ReadFile(statusPath)
		if err != nil {
			break
		}
		complete := false
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == "END" {
				complete = true
			}
			// CLIENT_LIST<TAB>CommonName<TAB>RealAddr<TAB>VirtualAddr<TAB>...
			if !strings.HasPrefix(line, "CLIENT_LIST\t") {
				continue
			}
			f := strings.Split(line, "\t")
			if len(f) > 3 && f[3] != "" {
				set[f[3]] = true
			}
		}
		if complete {
			break // got a whole snapshot — trustworthy
		}
		time.Sleep(10 * time.Millisecond) // landed mid-rewrite; let it finish, retry
	}
	return set
}
