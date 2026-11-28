package l2tp

// Shared-daemon config conflicts — the L2TP half of vpn-ui
// web/service/sharedconfig.go (the ikev2 half registers from its own wave
// through CheckSharedDaemonConflicts' extension hook below).
//
// L2TP runs ONE daemon for the whole panel, so some settings are physically
// per-protocol rather than per-inbound:
//
//   - L2TP/PPTP link options (DNS, MTU) are one options file for the shared LNS.
//   - The L2TP/IPsec pre-shared key is one PSK PER IKE LISTEN ADDRESS. This one is a
//     protocol constraint, not an implementation shortcut: IKEv1 Main Mode derives
//     SKEYID from the PSK at messages 3/4, and the peer's ID payload only arrives in
//     message 5 already encrypted under those keys, so the responder must pick the key
//     knowing nothing but the IP address pair. Two inbounds answering on the SAME local
//     address are therefore cryptographically indistinguishable and must agree on the
//     key; two inbounds bound to DIFFERENT local addresses can each have their own,
//     because the address is the only thing that can select it.
//
// The generators resolve these by taking the first enabled inbound's value and
// ignoring the rest. That silently lied: a second inbound's PSK would be accepted,
// displayed as saved, and never used, so its clients shipped a profile that could
// not authenticate. Rejecting the save instead surfaces the constraint at the point
// of the mistake, which is the only place it can be acted on.
//
// This is enforced on save rather than at generation time because by then the value
// is already stored and the operator has already been told it worked.
//
// TODO(ikev2 wave): register its DNS conflict check (vpn-ui
// checkIkev2SharedConflicts) through RegisterSharedConflictChecker.
// TODO(controllers/inbound wave): call CheckSharedDaemonConflicts(inbound,
// excludeId) in AddInbound/UpdateInbound exactly where vpn-ui's inbound.go:1326
// and inbound.go:1594 did.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
)

// sharedConflict names a setting whose value is dictated panel-wide.
type sharedConflict struct {
	Field string
	// Protocol is the protocol whose shared daemon dictates the value, spelled the way
	// the operator sees it in the UI. Was hardcoded to "L2TP", which would have lied the
	// first time any other protocol reported through this struct.
	Protocol string
	// Scope says WHO shares the value. Empty means the whole panel, which is the case
	// for every setting a single daemon reads once.
	Scope string
	Mine  string
	Other string
	// OtherRemark identifies the inbound that already owns the value, so the
	// operator can find it. Deliberately included even across admins: the value is
	// shared whether or not they can see the inbound, and an unexplained rejection
	// would be worse than naming it.
	OtherRemark string
	OtherId     int
	// Remedy is the second way out, for a conflict that has one: a change elsewhere in
	// the form that makes the two values stop being the same setting. Without it the
	// only advice the message can give is "type what the other inbound typed".
	Remedy string
}

func (c sharedConflict) Error() string {
	scope := c.Scope
	if scope == "" {
		scope = "on this server (one daemon serves them all)"
	}
	msg := fmt.Sprintf(
		"%s is shared by every %s inbound %s, "+
			"and inbound #%d (%q) already set it to %q. Use that value, or change it there.",
		c.Field, c.Protocol, scope, c.OtherId, c.OtherRemark, c.Other)
	if c.Remedy != "" {
		msg += " " + c.Remedy
	}
	return msg
}

// l2tpPskRemedy is the way out of a PSK conflict that does not mean giving up the key
// you wanted. It is spelled out rather than left as "not supported" because the
// constraint is real but narrow, and an operator who knows where the escape hatch is
// can take it in one edit.
const l2tpPskRemedy = "To give this inbound its OWN key, set a different Listen IP on " +
	"each L2TP inbound (the field above the port; blank means every address): IKEv1 Main " +
	"Mode has to pick the key from the IP addresses alone, before the client has said who " +
	"it is, so the address they answer on is the only thing that can tell two L2TP " +
	"inbounds apart."

// l2tpSharedSettings is the subset of an l2tp inbound's settings that the shared
// daemon can only honour one of.
type l2tpSharedSettings struct {
	IpsecEnable bool   `json:"ipsecEnable"`
	IpsecPsk    string `json:"ipsecPsk"`
	Dns1        string `json:"dns1"`
	Dns2        string `json:"dns2"`
	Mtu         int    `json:"mtu"`
}

// checkL2tpSharedConflicts reports a setting that the incoming l2tp inbound would
// lose to another enabled l2tp inbound. excludeId skips the row being edited.
func checkL2tpSharedConflicts(inbound *model.Inbound, excludeId int) error {
	if inbound == nil || inbound.Protocol != defaults.ProtoL2TP || !inbound.Enable {
		return nil
	}
	var mine l2tpSharedSettings
	if err := json.Unmarshal([]byte(inbound.Settings), &mine); err != nil {
		return nil // malformed settings fail elsewhere with a better message
	}

	others, err := enabledInboundsOfProtocol(defaults.ProtoL2TP, excludeId)
	if err != nil {
		return nil // never block a save because the conflict check itself failed
	}
	label := protocolLabel(inbound.Protocol)
	for _, other := range others {
		var theirs l2tpSharedSettings
		if json.Unmarshal([]byte(other.Settings), &theirs) != nil {
			continue
		}
		// The PSK is the damaging one: a mismatch means clients get a profile that
		// cannot authenticate, with nothing in the UI to explain why.
		//
		// It is only shared with the inbounds this one shares an IKE RESPONDER with,
		// which is the inbounds whose listen address overlaps: a wildcard on either
		// side answers on every address, and two concrete addresses that differ are two
		// separate responders that can each hold their own key. See the file header for
		// why the address is the only discriminator available in IKEv1 Main Mode.
		if mine.IpsecEnable && theirs.IpsecEnable &&
			mine.IpsecPsk != "" && theirs.IpsecPsk != "" && mine.IpsecPsk != theirs.IpsecPsk &&
			listenOverlaps(inbound.Listen, other.Listen) {
			return sharedConflict{
				Field: "The IPsec pre-shared key", Protocol: label,
				Scope: "that answers on the same listen address (one IKE responder serves them all)",
				Mine:  mine.IpsecPsk, Other: theirs.IpsecPsk,
				OtherRemark: other.Remark, OtherId: other.Id,
				Remedy: l2tpPskRemedy,
			}
		}
		// DNS and MTU are NOT address-scoped: they are the one shared pppd options file
		// the single xl2tpd LNS reads, which no amount of listen-address separation
		// splits up. Left exactly as they were.
		if mine.Dns1 != "" && theirs.Dns1 != "" && mine.Dns1 != theirs.Dns1 {
			return sharedConflict{
				Field: "The primary DNS server", Protocol: label, Mine: mine.Dns1, Other: theirs.Dns1,
				OtherRemark: other.Remark, OtherId: other.Id,
			}
		}
		if mine.Mtu != 0 && theirs.Mtu != 0 && mine.Mtu != theirs.Mtu {
			return sharedConflict{
				Field: "The MTU", Protocol: label, Mine: fmt.Sprint(mine.Mtu), Other: fmt.Sprint(theirs.Mtu),
				OtherRemark: other.Remark, OtherId: other.Id,
			}
		}
	}
	return nil
}

// protocolLabel spells a protocol the way the panel's UI does, for a message the
// operator reads.
func protocolLabel(protocol model.Protocol) string {
	return strings.ToUpper(string(protocol))
}

// listenOverlaps reports whether two listen addresses cover at least one common
// local address, i.e. the two inbounds share an IKE responder (vpn-ui
// web/service/inboundport.go listenOverlaps — the save-path half lives with the
// inbound wave; this package needs only the predicate).
func listenOverlaps(a, b string) bool {
	if listenIsWildcard(a) || listenIsWildcard(b) {
		return true
	}
	return strings.TrimSpace(a) == strings.TrimSpace(b)
}

// sharedConflictCheckers are the other protocols' halves of the shared-daemon
// check (ikev2's DNS pair today). Each returns nil unless the inbound it is
// handed conflicts with one of its own protocol's already-stored rows.
var sharedConflictCheckers []func(inbound *model.Inbound, excludeId int) error

// RegisterSharedConflictChecker attaches one protocol wave's half of the
// shared-daemon save check.
//
// TODO(ikev2 wave): register vpn-ui sharedconfig.go's checkIkev2SharedConflicts
// here.
func RegisterSharedConflictChecker(f func(inbound *model.Inbound, excludeId int) error) {
	sharedConflictCheckers = append(sharedConflictCheckers, f)
}

// CheckSharedDaemonConflicts is the entry point called before an inbound is saved.
func CheckSharedDaemonConflicts(inbound *model.Inbound, excludeId int) error {
	if err := checkL2tpSharedConflicts(inbound, excludeId); err != nil {
		return err
	}
	for _, check := range sharedConflictCheckers {
		if err := check(inbound, excludeId); err != nil {
			return err
		}
	}
	return nil
}

func enabledInboundsOfProtocol(protocol model.Protocol, excludeId int) ([]*model.Inbound, error) {
	db := vpn.DB()
	if db == nil {
		return nil, fmt.Errorf("no database")
	}
	var out []*model.Inbound
	q := db.Model(model.Inbound{}).Where("protocol = ? AND enable = ?", protocol, true).Order("id")
	if excludeId > 0 {
		q = q.Where("id != ?", excludeId)
	}
	err := q.Find(&out).Error
	return out, err
}

// SharedL2tpIpsecPsk returns the IPsec pre-shared key an enabled L2TP inbound already
// uses, or "" when there is none (no l2tp inbound yet, or no DB).
//
// This exists because minting a random key for a second L2TP inbound is a GUARANTEED
// rejection, not a risk of one: the save-time check above refuses two different keys on
// one IKE listen address, and a new inbound's listen address is blank (= every address)
// by default. Inheriting is therefore the only default that can be saved, and it is also
// the honest one — until the operator gives the inbound its own address, that IS the key
// their clients will authenticate with.
//
// The lowest id wins, matching the inbound the generators already treat as the owner of
// every other shared L2TP value.
//
// PORT NOTE: defaults.SharedL2tpIpsecPsk (internal/vpn/defaults) is the landed copy the
// defaults wave made of vpn-ui sharedconfig.go's sharedL2tpIpsecPsk; the l2tp package
// re-exports nothing — callers use the defaults one. This comment marks the provenance.
