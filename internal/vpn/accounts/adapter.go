// Adapter seams: the touchpoints where the vpn-ui accounts layer reached into
// 3x-ui's web/service (InboundService, AdminService, ResellerService,
// SettingService) or expects User role columns pxpanel does not have yet.
//
// Nothing here imports the target's web/service — that is the import-cycle
// risk this package exists to avoid. Every seam is a small interface or func
// var with a MINIMAL, honest implementation over vpn.DB() and a TODO
// naming exactly what the owning wave replaces it with.
package accounts

import (
	"errors"

	"gorm.io/gorm"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
)

// accountsMigratedKey is the settings-table flag the vpn-ui backfill stamped
// once the accounts layer was authoritative. Reads gate on it: before it is
// set, settings.clients is the only truth and the accounts tables may be empty
// or partial. (vpn-ui migrationaccounts.go:accountsMigratedKey.)
const accountsMigratedKey = "accountsMigratedAt"

// InboundIdsServingEmailsTx is the one InboundService behaviour the mirror
// needs: which inbounds' settings.clients carry any of these emails. Implemented
// here as a panel-wide scan of the settings blobs — which is exactly what the
// vpn-ui inbound service did, minus its caching.
//
// TODO(inbound wave): if the inbound service grows a richer scan (per-protocol
// identity resolution, caching), re-point this var at it.
func InboundIdsServingEmailsTx(tx *gorm.DB, emails []string) ([]int, error) {
	if len(emails) == 0 {
		return nil, nil
	}
	keys := map[string]bool{}
	for _, e := range emails {
		if k := AccountKeyOf(e); k != "" {
			keys[k] = true
		}
	}
	if len(keys) == 0 {
		return nil, nil
	}
	var inbounds []model.Inbound
	if err := tx.Model(&model.Inbound{}).Select("id", "settings").Find(&inbounds).Error; err != nil {
		return nil, err
	}
	var out []int
	for i := range inbounds {
		clients, ok := parseSettingsClients(inbounds[i].Settings)
		if !ok {
			continue
		}
		for _, entry := range clients {
			email, _ := entry["email"].(string)
			if keys[AccountKeyOf(email)] {
				out = append(out, inbounds[i].Id)
				break
			}
		}
	}
	return out, nil
}

// AccessibleInboundIds is AdminService.AccessibleInboundIds: the inbound ids one
// admin is ASSIGNED to (model.InboundAccess rows).
//
// WIRED (admins wave): internal/vpn/adminaccess owns the access machinery and
// registers its implementation from init() (RegisterAccessibleInboundIds). The
// direct query below stays as the default for builds that do not link
// adminaccess — it is the same table and the same WHERE, so the two agree.
func AccessibleInboundIds(userId int) ([]int, error) {
	if accessibleInboundIds != nil {
		return accessibleInboundIds(userId)
	}
	db := vpn.DB()
	if db == nil {
		return nil, nil
	}
	var ids []int
	err := db.Model(&model.InboundAccess{}).Where("user_id = ?", userId).Pluck("inbound_id", &ids).Error
	return ids, err
}

// accessibleInboundIds is filled by adminaccess's init(); nil keeps the minimal
// query above.
var accessibleInboundIds func(userId int) ([]int, error)

// RegisterAccessibleInboundIds attaches the admins wave's access reader. One
// call, from that package's init only.
func RegisterAccessibleInboundIds(fn func(userId int) ([]int, error)) {
	accessibleInboundIds = fn
}

// OwnedResellerEmails is ResellerService.OwnedEmails: the panel-wide emails one
// reseller owns (model.ResellerClient rows). ABSENCE of a row means house-owned,
// so the set is exactly the ledger.
//
// WIRED (reseller wave): internal/vpn/reseller owns the ledger and registers its
// implementation from init() (RegisterOwnedResellerEmails). The direct query
// below stays as the default for builds that do not link the reseller package —
// note the reseller one additionally LOWER-CASES its keys, matching how every
// consumer compares them (accountKey), so prefer it whenever it is linked.
func OwnedResellerEmails(userId int) (map[string]bool, error) {
	if ownedResellerEmails != nil {
		return ownedResellerEmails(userId)
	}
	db := vpn.DB()
	if db == nil {
		return nil, nil
	}
	var emails []string
	err := db.Model(&model.ResellerClient{}).Where("user_id = ?", userId).Pluck("email", &emails).Error
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(emails))
	for _, e := range emails {
		out[e] = true
	}
	return out, nil
}

// ownedResellerEmails is filled by the reseller package's init(); nil keeps the
// minimal query above.
var ownedResellerEmails func(userId int) (map[string]bool, error)

// RegisterOwnedResellerEmails attaches the reseller ledger's ownership reader.
// One call, from that package's init only.
func RegisterOwnedResellerEmails(fn func(userId int) (map[string]bool, error)) {
	ownedResellerEmails = fn
}

// OnlineClientEmails is InboundService.GetOnlineClients: the identities the
// RUNNING core currently holds sessions for. It only feeds the "online" sort of
// the Clients list, so the default is "none online" — every account sorts as
// offline rather than the call failing.
//
// The core's session list is registered by the xray plane wave
// (xrayplane.SetOnlineClientsSource, which forwards here); unwired, this stays
// "none online".
var onlineClientEmails func() []string

// RegisterOnlineClientEmails attaches the running core's online-identity reader.
func RegisterOnlineClientEmails(fn func() []string) { onlineClientEmails = fn }

func OnlineClientEmails() []string {
	if onlineClientEmails == nil {
		return nil
	}
	return onlineClientEmails()
}

// SettingsGet returns one row from the settings KV table (or nil). The minimal
// replacement for the SettingService.getSetting call AccountsMigrated makes.
//
// TODO(settings wave): re-point at the settings service so the read shares its
// caching and error paths.
func SettingsGet(tx *gorm.DB, key string) (*model.Setting, error) {
	if tx == nil {
		tx = vpn.DB()
	}
	if tx == nil {
		return nil, nil
	}
	var setting model.Setting
	err := tx.Where("key = ?", key).First(&setting).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &setting, nil
}

// Viewer is the caller identity the list/picker scoping decides on. pxpanel's
// model.User predates the IsSuperAdmin/IsReseller role columns (see
// model.AdminFlags), so the controller maps its session user into this struct —
// with reseller-hood derived from a ResellerProfile row's existence, exactly as
// vpn-ui derived it.
type Viewer struct {
	Id           int
	IsSuperAdmin bool
	IsReseller   bool
}

// ViewerForUser maps a model.User to a Viewer.
//
// WIRED (admins/reseller wave): the role derivation now lives in
// adminaccess.FlagsFor (super admin = lowest-id rule; reseller = profile row,
// which clears the super-admin bit — the same rules as before, centralized so
// the columns wave changes ONE function) and is registered here via
// RegisterRoleFlags. The inline probes below stay as the default for builds
// that do not link adminaccess; they implement exactly those two rules.
func ViewerForUser(u *model.User) Viewer {
	if u == nil {
		return Viewer{}
	}
	v := Viewer{Id: u.Id}
	if superAdminFlag != nil && resellerFlag != nil {
		v.IsSuperAdmin = superAdminFlag(u.Id)
		isReseller, err := resellerFlag(u.Id)
		if err == nil && isReseller {
			v.IsReseller = true
			v.IsSuperAdmin = false // never both (vpn-ui ResellerService enforces it)
		}
		return v
	}
	db := vpn.DB()
	if db != nil {
		// First seeded user is the super admin (vpn-ui migrateSuperAdmin rule).
		var lowestId int
		if err := db.Model(&model.User{}).Select("MIN(id)").Scan(&lowestId).Error; err == nil {
			v.IsSuperAdmin = lowestId == u.Id
		}
		var count int64
		if err := db.Model(&model.ResellerProfile{}).Where("user_id = ?", u.Id).Count(&count).Error; err == nil && count > 0 {
			v.IsReseller = true
			v.IsSuperAdmin = false // never both (vpn-ui ResellerService enforces it)
		}
	}
	return v
}

// Role flag resolvers, filled by adminaccess's init() (RegisterRoleFlags); nil
// keeps the inline derivations above.
var (
	superAdminFlag func(userId int) bool
	resellerFlag   func(userId int) (bool, error)
)

// RegisterRoleFlags attaches the admins wave's role resolvers. One call, from
// that package's init only.
func RegisterRoleFlags(superAdmin func(userId int) bool, reseller func(userId int) (bool, error)) {
	superAdminFlag = superAdmin
	resellerFlag = reseller
}
