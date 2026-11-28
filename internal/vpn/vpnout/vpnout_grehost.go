package vpnout

// Local GRE support the client driver (vpnout_gre.go) carries: vpn-ui's
// vpnout_gre.go read these off GreService in the single `service` package
// (gre.go); here the inbound side lives in internal/vpn/gre with everything
// unexported, so the client side carries the identical functions with a
// greOutHost receiver instead. Manifest ownership uses the SAME kinds and core
// tags as the inbound side (manifest.KindIface / KindFouPort, core "gre"), so
// uninstall and the operator-facing report treat client and server artifacts
// as one family.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"

	vpn "github.com/ImSoheilPx/pxpanel/internal/vpn"
	vpnlog "github.com/ImSoheilPx/pxpanel/internal/vpn/log"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// greModule is the in-kernel GRE data plane (vpn-ui gre.go).
	greModule = "ip_gre"
	// greFouModule backs UDP-encapsulated GRE (FOU).
	greFouModule = "fou"
	// greKernelMtuIpsec is the MTU a GRE tunnel wrapped in IPsec transport-mode
	// ESP needs (vpn-ui gre.go, shared with the GRE-over-IPsec outbound).
	greKernelMtuIpsec = 1428
	// greKernelMtuRaw is the MTU of a plain GRE tunnel on a 1500 WAN:
	// 1500 - 20 (outer IP) - 4 (GRE).
	greKernelMtuRaw = 1476
	// greKernelMtuFou is greKernelMtuRaw minus 8 more for the UDP header.
	greKernelMtuFou = 1464
	// greDefaultTTL is the outer header TTL vpn-ui's GRE devices use.
	greDefaultTTL = 64
	// greDefaultFouPort is the FOU receive port vpn-ui's GRE-over-UDP uses.
	greDefaultFouPort = 15547
)

// greOutHost is the client-side stand-in for the inbound GreService: the four
// members vpnout_gre.go actually reaches (vpn-ui called them on &GreService{}).
type greOutHost struct{}

// greOutGreAvailable reports whether the in-kernel GRE data plane is usable.
// Verbatim from vpn-ui gre.go GreAvailable.
func (greOutHost) GreAvailable() bool {
	if moduleAvailable(greModule) {
		return true
	}
	// ip_gre is frequently built straight into the kernel rather than as a module, in which
	// case there is no /sys/module entry to find but GRE works fine. The fallback device the
	// module registers is the reliable tell.
	_, err := netlink.LinkByName("gre0")
	return err == nil
}

// greOutFouAvailable reports whether UDP-encapsulated GRE is usable on this host.
func (greOutHost) FouAvailable() bool { return moduleAvailable(greFouModule) }

// runCmd runs one command, logging combined output on failure (vpn-ui gre.go runCmd).
func (greOutHost) runCmd(name string, args ...string) error {
	cmd := exec.CommandContext(context.Background(), name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		vpnlog.Debugf("GRE: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}

// ensureGretun is the idempotent create-or-replace for a GRE netdev. Verbatim
// from vpn-ui gre.go (GreService).ensureGretun, with the manifest calls going
// through the target's exported manifest package.
func (greOutHost) ensureGretun(name string, want *netlink.Gretun, mtu int) error {
	la := netlink.NewLinkAttrs()
	la.Name = name
	if mtu > 0 {
		la.MTU = mtu
	}
	want.LinkAttrs = la

	if existing, err := netlink.LinkByName(name); err == nil {
		// A device wearing one of our generated names that the manifest says was here
		// before us is the operator's, however improbable the collision. Refuse rather
		// than recreate it: the recreate path below is a LinkDel.
		if manifest.ForbidsDelete(manifest.KindIface, name) {
			return fmt.Errorf("%s already exists and was not created by the panel; not touching it", name)
		}
		// Recreate only when an addressing-relevant attribute actually changed, so an
		// unrelated edit never drops a live tunnel.
		if g, ok := existing.(*netlink.Gretun); ok && greTunEquivalent(g, want) {
			if mtu > 0 && existing.Attrs().MTU != mtu {
				_ = netlink.LinkSetMTU(existing, mtu)
			}
			return netlink.LinkSetUp(existing)
		}
		_ = netlink.LinkDel(existing)
	} else {
		// First sighting of this name: nothing there, so whatever we create next is
		// unambiguously ours. Recorded BEFORE the LinkAdd so a crash between the two
		// leaves an entry that says "ours" for a device that does not exist, which the
		// next sweep simply drops, rather than the reverse.
		manifest.IfaceCreated(name, "gre")
	}

	if err := netlink.LinkAdd(want); err != nil {
		if vpn.ErrNotSupported(err) {
			return fmt.Errorf("GRE kernel module unavailable (ip_gre): %w", err)
		}
		return err
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

// greTunEquivalent compares the attributes that define a tunnel's identity and data path.
func greTunEquivalent(a, b *netlink.Gretun) bool {
	return greIPEqual(a.Local, b.Local) &&
		greIPEqual(a.Remote, b.Remote) &&
		a.Ttl == b.Ttl &&
		a.IKey == b.IKey && a.OKey == b.OKey &&
		a.EncapType == b.EncapType && a.EncapDport == b.EncapDport
}

// greIPEqual compares two tunnel endpoints treating "absent" and "unspecified" as the same
// thing (vpn-ui gre.go greIPEqual — the catch-all's `remote any` round-trips as 0.0.0.0).
func greIPEqual(a, b net.IP) bool {
	aAny := a == nil || a.IsUnspecified()
	bAny := b == nil || b.IsUnspecified()
	if aAny || bAny {
		return aAny && bAny
	}
	return a.Equal(b)
}

// errIsExist folds EEXIST and EADDRINUSE together (vpn-ui gre.go errIsExist).
// FouAdd reports an existing port as EADDRINUSE, not EEXIST, which is why both
// are here: the EEXIST-only version logged a spurious warning on every tick
// once FOU was enabled.
func errIsExist(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, unix.EEXIST) || errors.Is(err, unix.EADDRINUSE) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "exists") || strings.Contains(s, "address already in use")
}

// ensureFouPort registers a FOU receive port for GRE. Idempotent: an existing
// port comes back as EEXIST, which is success. Verbatim from vpn-ui gre.go
// ensureFouPort, with ownership through the manifest package (core "gre", the
// same tag the inbound side claims under).
func ensureFouPort(port int) error {
	id := fouPortID(port)
	err := netlink.FouAdd(netlink.Fou{
		Port:     port,
		Protocol: unix.IPPROTO_GRE,
		Family:   unix.AF_INET,
		// EncapType is REQUIRED; omitting it sends FOU_ENCAP_UNSPEC and fails EINVAL.
		EncapType: netlink.FOU_ENCAP_DIRECT,
	})
	if err == nil {
		manifest.Claim(manifest.KindFouPort, id, "gre")
		return nil
	}
	if errIsExist(err) {
		manifest.Note(manifest.KindFouPort, id, "gre", "a FOU listener was already registered on this port")
		return nil
	}
	return err
}

// fouPortID is the manifest key for a FOU receive port.
func fouPortID(port int) string { return fmt.Sprintf("%d/gre", port) }

// primaryV4Addr asks the routing table which source address egresses to the internet
// (vpn-ui gre.go primaryV4Addr).
func primaryV4Addr() net.IP {
	routes, err := netlink.RouteGet(net.IPv4(1, 1, 1, 1))
	if err != nil || len(routes) == 0 {
		return nil
	}
	for _, r := range routes {
		if r.Src != nil && r.Src.To4() != nil {
			return r.Src.To4()
		}
	}
	return nil
}

// greWanIface returns the interface the default route uses, i.e. the one FOU packets
// arrive on (vpn-ui gre.go greWanIface).
func greWanIface() (string, error) {
	routes, err := netlink.RouteGet(net.IPv4(1, 1, 1, 1))
	if err != nil || len(routes) == 0 {
		return "", fmt.Errorf("no route to the internet: %w", err)
	}
	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return "", err
	}
	return link.Attrs().Name, nil
}

// ovpnOutHost is the client-side stand-in for the inbound OpenVpnService member
// vpnout_openvpn.go reaches (vpn-ui called (&OpenVpnService{}).runCmd): the one
// modprobe helper, with the same log prefix as the inbound copy.
type ovpnOutHost struct{}

// runCmd runs one command, logging combined output on failure (vpn-ui openvpn.go runCmd).
func (ovpnOutHost) runCmd(name string, args ...string) error {
	cmd := exec.CommandContext(context.Background(), name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		vpnlog.Debugf("OpenVPN: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}

// vpnOutCarrier ownership (vpn-ui ifaceown.go): the carrier tun is the one device
// the panel creates that a person might plausibly also create, so the name shape
// carries the identity and the kind check stops a bridge or a dummy wearing the
// name from being deleted.

// vpnOutCarrierNameRe matches vpnOutCarrierDev's normal form: xcar<8 hex>.
var vpnOutCarrierNameRe = regexp.MustCompile(`^xcar[0-9a-f]{8}$`)

// vpnOutCarrierOwnedName reports whether a device name is a carrier tun's.
func vpnOutCarrierOwnedName(name string) bool { return vpnOutCarrierNameRe.MatchString(name) }

// vpnOutCarrierOwnsLink is the full ownership test for a carrier tun.
func vpnOutCarrierOwnsLink(l netlink.Link) bool {
	name := l.Attrs().Name
	if !vpnOutCarrierOwnedName(name) {
		return false
	}
	if _, ok := l.(*netlink.Tuntap); !ok {
		return false
	}
	return !manifest.ForbidsDelete(manifest.KindIface, name)
}
