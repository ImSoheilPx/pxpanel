// The ChargeTicket path: price an account mutation, RESERVE it against the
// balance, hand the caller a ticket whose client write can be rolled back.
// Ported from vpn-ui web/service/reseller.go.
//
// Call-shape adaptation: vpn-ui passed *model.User (whose row carried
// IsReseller); the ported functions take accounts.Viewer — the same role
// snapshot the accounts list/picker already decides on. An inactive viewer
// (an admin) gets an inactive ticket and every function below is a no-op,
// exactly as in the source.
package reseller

import (
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/util/common"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/accounts"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

// ChargeTicket is a reservation taken against a reseller's balance, held while
// the client write it paid for is attempted.
type ChargeTicket struct {
	// Active is false for an admin or super admin: they have no balance, so
	// there is nothing to reserve and nothing to roll back.
	Active    bool
	UserId    int
	Email     string
	InboundId int
	Quote     ChargeQuote
	Create    bool
	// PrevCharged is what to restore on rollback.
	PrevCharged int64
}

// postedClient pulls the single client out of a client-mutating request body.
//
// Exactly one, always: every one of those routes posts one, and more than one
// would let a single reservation pay for several accounts.
func postedClient(data *model.Inbound) (map[string]any, map[string]any, []any, error) {
	settings := map[string]any{}
	if err := json.Unmarshal([]byte(data.Settings), &settings); err != nil {
		return nil, nil, nil, err
	}
	clients, _ := settings["clients"].([]any)
	if len(clients) != 1 {
		return nil, nil, nil, errors.New("expected exactly one client in the request")
	}
	cm, ok := clients[0].(map[string]any)
	if !ok {
		return nil, nil, nil, errors.New("malformed client in the request")
	}
	return cm, settings, clients, nil
}

// applyToSettings writes the priced decisions back into the request body.
//
// The blob has to be patched before the inbound layer parses it, and doing the
// surgery in one place beats repeating it at every call site.
func applyToSettings(data *model.Inbound, profile *model.ResellerProfile, q ChargeQuote,
	cm map[string]any, settings map[string]any, clients []any,
) error {
	// Overwrite rather than validate: the form is the reseller's, and a posted
	// expiry that disagrees with the factor is not an error to report back, it is
	// a field they should never have had.
	if q.ForceExpiry {
		cm["expiryTime"] = q.ExpiryTime
	}
	if !profile.AllowExternalProxy {
		delete(cm, "externalProxy")
	}
	// SECURITY: strip the auto-renew period. `reset` is a number of DAYS after
	// which the auto-renew job zeroes an account's up and down counters,
	// re-enables it, and pushes its deadline forward, on a timer, forever.
	// Nothing in that job consults a balance.
	//
	// Left settable, it is an unlimited-traffic switch: a reseller sells one
	// gigabyte, sets reset=1, and the account is handed a fresh gigabyte every
	// day for as long as it exists, charged once. Every other way of giving an
	// account more traffic goes through Quote; this one bypassed it entirely.
	//
	// Resellers top up manually instead, which IS priced, and a reset they ask
	// for by hand is priced too (PrepareClientReset).
	delete(cm, "reset")
	clients[0] = cm
	settings["clients"] = clients
	patched, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	data.Settings = string(patched)
	return nil
}

// checkEmailFree refuses an email that already names an account ANYWHERE, before
// a reservation is taken against it.
//
// (vpn-ui PrepareClientCreate's call to InboundService.checkEmailsExistForClients
// + duplicateEmailError + emailHolders, re-pointed at the accounts layer: the
// settings.clients scan is the same check the create path itself uses, so the
// two cannot disagree about what "taken" means. The parked-account case — an
// accounts row holding the email on no inbound — is answered from the accounts
// table, which is where that row lives now.)
func checkEmailFree(email string) error {
	db := vpn.DB()
	ids, err := accounts.InboundIdsServingEmailsTx(db, []string{email})
	if err != nil {
		return err
	}
	if len(ids) > 0 {
		return duplicateEmailError(email, inboundHolders(db, ids)...)
	}
	if acct, err := accountSvc.GetAccountByEmail(email); err == nil && acct != nil {
		return duplicateEmailError(email, holderIsParkedAccount)
	}
	return nil
}

// inboundHolders names the inbounds already serving an email, for the rejection
// above. Best effort on purpose: it runs while the caller is already returning
// an error, so a failure here drops the detail and must never turn a duplicate
// the operator can fix into an opaque database error.
func inboundHolders(db *gorm.DB, ids []int) []string {
	if len(ids) == 0 {
		return nil
	}
	var rows []model.Inbound
	if err := db.Model(&model.Inbound{}).Select("id", "remark").
		Where("id IN (?)", ids).Find(&rows).Error; err != nil {
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		remark := row.Remark
		if remark == "" {
			remark = "#<id>" // vpn-ui printed the id for a nameless inbound
		}
		out = append(out, remark)
	}
	return out
}

// holderIsParkedAccount stands in for "the holder is an account on no inbound",
// which has no inbound name to print and so cannot go through the "on inbound
// %s" wording.
const holderIsParkedAccount = "\x00parked"

// duplicateEmailError is shared so the mutation paths cannot drift into wording
// the UI shows differently for the same rejection.
//
// holders names the inbound(s) whose settings already carry the email, and is
// the whole point of it. The check reads settings.clients and nothing else, so
// the rejection is always TRUTHFUL, but with no WHERE in it an operator who has
// just deleted that customer reads it as the panel remembering a phantom, and
// goes looking for a leftover row that does not exist. Naming the inbound turns
// the same rejection into something they can act on: the entry is right there.
//
// Variadic and not required, because a caller without a usable DB handle should
// still get the plain sentence rather than no rejection at all.
func duplicateEmailError(email string, holders ...string) error {
	if len(holders) == 1 && holders[0] == holderIsParkedAccount {
		return common.NewErrorf("Duplicate email: %q already belongs to a client that is not "+
			"attached to any inbound. Open that client and attach this inbound to it, or pick "+
			"another email.", email)
	}
	switch len(holders) {
	case 0:
		return common.NewErrorf("Duplicate email: %q is already used by another client. Emails must be unique across all inbounds.", email)
	case 1:
		return common.NewErrorf("Duplicate email: %q is already used by another client, on inbound %s. Emails must be unique across all inbounds.", email, holders[0])
	default:
		return common.NewErrorf("Duplicate email: %q is already used by another client, on inbounds %s. Emails must be unique across all inbounds.", email, joinHolders(holders))
	}
}

func joinHolders(holders []string) string {
	out := ""
	for i, h := range holders {
		if i > 0 {
			out += ", "
		}
		out += h
	}
	return out
}

// PrepareClientCreate prices a new account, rewrites the posted client to match
// the reseller's limits, and RESERVES the balance.
//
// The reservation happens before the client is written on purpose. A crash
// between the two loses the reseller balance an admin can recharge; the reverse
// order loses the panel real traffic with no record of it. Both directions of
// failure exist, and this is the one an operator can fix.
//
// Returns an inactive ticket for an admin or super admin: they have no balance,
// so there is nothing to price and nothing to roll back.
func PrepareClientCreate(user accounts.Viewer, data *model.Inbound) (ChargeTicket, error) {
	if !user.IsReseller {
		return ChargeTicket{}, nil
	}
	profile, err := ProfileFor(user.Id)
	if err != nil {
		return ChargeTicket{}, err
	}
	cm, settings, clients, err := postedClient(data)
	if err != nil {
		return ChargeTicket{}, err
	}
	email, _ := cm["email"].(string)
	if email == "" {
		return ChargeTicket{}, errors.New("client email is required")
	}

	// SECURITY: refuse an email that already belongs to someone, BEFORE reserving.
	//
	// The create path rejects duplicate emails too, but it runs after this, and
	// the reservation writes a ResellerClient row keyed on the email in between.
	// That row is what OwnsClientEmail answers from, so for the width of the
	// failed create the reseller genuinely owned an ADMIN's account: long enough
	// for a second, concurrent request to edit or delete it. Rollback closes the
	// window afterwards, and "afterwards" is not a security boundary.
	if err := checkEmailFree(email); err != nil {
		return ChargeTicket{}, err
	}

	q, err := Quote(QuoteInput{
		Profile:   *profile,
		Create:    true,
		NewTotal:  jsonInt64(cm["totalGB"]),
		NowMillis: time.Now().UnixMilli(),
	})
	if err != nil {
		return ChargeTicket{}, err
	}
	if err := applyToSettings(data, profile, q, cm, settings, clients); err != nil {
		return ChargeTicket{}, err
	}

	ticket := ChargeTicket{
		Active: true, UserId: user.Id, Email: email,
		InboundId: data.Id, Quote: q, Create: true,
	}
	if err := reserve(ticket); err != nil {
		return ChargeTicket{}, err
	}
	return ticket, nil
}

// PrepareClientUpdate prices an edit of an existing account.
//
// Keyed on clientId, the route's path parameter, NOT on the posted email: the
// panel lets an account be renamed, so the email in the body may be one the
// ledger has never seen. Resolving the stored client first is what makes a
// rename priceable at all, and the caller finishes the job with RenameClient
// once the write has landed.
func PrepareClientUpdate(user accounts.Viewer, data *model.Inbound, clientId string) (ChargeTicket, error) {
	if !user.IsReseller {
		return ChargeTicket{}, nil
	}
	profile, err := ProfileFor(user.Id)
	if err != nil {
		return ChargeTicket{}, err
	}
	cm, settings, clients, err := postedClient(data)
	if err != nil {
		return ChargeTicket{}, err
	}

	oldEmail, err := storedClientEmail(data.Id, clientId)
	if err != nil {
		return ChargeTicket{}, err
	}
	// The account being edited must already be theirs. The route middleware only
	// proves they can reach the INBOUND, which they share with admins, so it
	// cannot answer this.
	owner, err := ClientOwner(oldEmail)
	if err != nil {
		return ChargeTicket{}, err
	}
	if owner == nil || owner.UserId != user.Id {
		return ChargeTicket{}, ErrClientNotOwned
	}

	ct := &xray.ClientTraffic{}
	err = vpn.DB().Model(&xray.ClientTraffic{}).Where("email = ?", oldEmail).First(ct).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return ChargeTicket{}, err
	}
	lifetime, _, err := lifetimeUsage(vpn.DB(), []string{oldEmail})
	if err != nil {
		return ChargeTicket{}, err
	}
	in := QuoteInput{
		Profile:       *profile,
		NewTotal:      jsonInt64(cm["totalGB"]),
		OldTotal:      ct.Total,
		OldCharged:    owner.ChargedBytes,
		CurrentExpiry: ct.ExpiryTime,
		NowMillis:     time.Now().UnixMilli(),
	}
	if consumed := lifetime[emailKey(oldEmail)] - owner.AllTimeBase; consumed > 0 {
		in.Consumed = consumed
	}

	q, err := Quote(in)
	if err != nil {
		return ChargeTicket{}, err
	}
	// SECURITY: a reseller cannot switch a depleted account back on without
	// paying for the traffic that would let it run.
	//
	// The depletion sweep turns depleted accounts off, but it is a cron job on a
	// 10 second tick, so a manual re-enable buys 10 seconds of unmetered
	// traffic and a script that re-enables on a loop keeps a paid-out account
	// alive indefinitely. The ledger stays perfectly correct while the customer
	// keeps browsing, which is the worst shape a bypass can take.
	//
	// Forced off rather than refused: the job would reach the same state within
	// the tick, so this only stops the window being useful, and it leaves a
	// legitimate edit (raising the quota, which lands above) working normally.
	if enable, _ := cm["enable"].(bool); enable && depletedAfter(ct, in.NewTotal) {
		cm["enable"] = false
	}
	if err := applyToSettings(data, profile, q, cm, settings, clients); err != nil {
		return ChargeTicket{}, err
	}

	ticket := ChargeTicket{
		Active: true, UserId: user.Id, Email: oldEmail, InboundId: data.Id,
		Quote: q, Create: false, PrevCharged: owner.ChargedBytes,
	}
	if err := reserve(ticket); err != nil {
		return ChargeTicket{}, err
	}
	return ticket, nil
}

// PrepareClientReset prices a traffic-counter reset and reserves the balance it
// costs. Inactive for an admin, whose resets are free.
//
// Allowed for a reseller, not refused, but never free: see QuoteInput.Reset for
// why zeroing the counters is a purchase.
func PrepareClientReset(user accounts.Viewer, email string) (ChargeTicket, error) {
	if !user.IsReseller {
		return ChargeTicket{}, nil
	}
	profile, err := ProfileFor(user.Id)
	if err != nil {
		return ChargeTicket{}, err
	}
	owner, err := ClientOwner(email)
	if err != nil {
		return ChargeTicket{}, err
	}
	if owner == nil || owner.UserId != user.Id {
		return ChargeTicket{}, ErrResetNotOwned
	}

	ct := &xray.ClientTraffic{}
	err = vpn.DB().Model(&xray.ClientTraffic{}).Where("email = ?", email).First(ct).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return ChargeTicket{}, err
	}

	q, err := Quote(QuoteInput{
		Profile:       *profile,
		Reset:         true,
		ClearedBytes:  ct.Up + ct.Down,
		OldCharged:    owner.ChargedBytes,
		NewTotal:      ct.Total,
		CurrentExpiry: ct.ExpiryTime,
		NowMillis:     time.Now().UnixMilli(),
	})
	if err != nil {
		return ChargeTicket{}, err
	}

	ticket := ChargeTicket{
		Active: true, UserId: user.Id, Email: email, InboundId: owner.InboundId,
		Quote: q, Create: false, PrevCharged: owner.ChargedBytes,
	}
	if err := reserve(ticket); err != nil {
		return ChargeTicket{}, err
	}
	return ticket, nil
}

// Balance is a reseller's own standing, for the chip on their inbounds page.
type Balance struct {
	IsReseller     bool  `json:"isReseller"`
	Unlimited      bool  `json:"unlimited"`
	AllowanceBytes int64 `json:"allowanceBytes"`
	SpentBytes     int64 `json:"spentBytes"`
	AvailableBytes int64 `json:"availableBytes"`
}

// BalanceFor reports what this caller has left. Not a reseller reports
// IsReseller false and zeroes, so the endpoint is safe to call from every page
// without the frontend branching first.
func BalanceFor(user accounts.Viewer) Balance {
	if !user.IsReseller {
		return Balance{}
	}
	p, err := ProfileFor(user.Id)
	if err != nil {
		return Balance{IsReseller: true}
	}
	return Balance{
		IsReseller:     true,
		Unlimited:      p.Unlimited,
		AllowanceBytes: p.AllowanceBytes,
		SpentBytes:     p.SpentBytes,
		AvailableBytes: AvailableBytes(*p),
	}
}

// storedClientEmail resolves a route's :clientId back to the email the ledger
// keys on, using the same protocol-dependent identity field the inbound layer
// matches with (accounts.ClientIdentityKey — the accounts wave's port of
// vpn-ui's clientIdentityKey).
func storedClientEmail(inboundId int, clientId string) (string, error) {
	if clientId == "" {
		return "", ErrClientNotOwned
	}
	inbound := &model.Inbound{}
	err := vpn.DB().Model(&model.Inbound{}).First(inbound, inboundId).Error
	if err != nil || inbound == nil {
		return "", ErrClientNotOwned
	}
	clients, ok := settingsClients(inbound.Settings)
	if !ok {
		return "", ErrClientNotOwned
	}
	idKey := accounts.ClientIdentityKey(inbound.Protocol)
	for _, entry := range clients {
		identity, _ := entry[idKey].(string)
		if identity == clientId {
			email, _ := entry["email"].(string)
			return email, nil
		}
	}
	return "", ErrClientNotOwned
}

// settingsClients parses a settings blob's clients array as raw entries.
func settingsClients(settings string) ([]map[string]any, bool) {
	root := map[string]any{}
	if err := json.Unmarshal([]byte(settings), &root); err != nil {
		return nil, false
	}
	raw, _ := root["clients"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		entry, ok := r.(map[string]any)
		if ok {
			out = append(out, entry)
		}
	}
	return out, len(out) > 0
}

// reserve applies the quote: the balance move and the ownership row, in one
// transaction so no state exists where one landed and the other did not.
func reserve(t ChargeTicket) error {
	if !t.Active {
		return nil
	}
	return vpn.DB().Transaction(func(tx *gorm.DB) error {
		if err := addSpent(tx, t.UserId, t.Quote.DeltaSpent); err != nil {
			return err
		}
		if t.Create {
			// A same-email account may have existed before and been deleted; its
			// lifetime counter is what AllTimeBase must start from, so consumption
			// is never counted twice.
			var base int64
			lifetime, _, err := lifetimeUsage(tx, []string{t.Email})
			if err == nil {
				base = lifetime[emailKey(t.Email)]
			}
			return tx.Create(&model.ResellerClient{
				Email:        t.Email,
				InboundId:    t.InboundId,
				UserId:       t.UserId,
				ChargedBytes: t.Quote.NewCharged,
				AllTimeBase:  base,
			}).Error
		}
		// charged_bytes alone, and InboundId deliberately left where the create put
		// it: it is the HOME inbound, a display value, and an edit does not move an
		// account's home. There is nothing to keep in step here because nothing
		// decides by that column any more; the questions it used to answer ("which
		// inbound is this on") are resolved from the memberships instead, since one
		// account is served on N of them and this row can only hold one. Writing the
		// edited inbound here would be strictly worse than leaving it: the value
		// would swing to whichever membership was edited last while still describing
		// only one of them.
		return tx.Model(&model.ResellerClient{}).Where("email = ?", t.Email).
			Update("charged_bytes", t.Quote.NewCharged).Error
	})
}

// Rollback undoes a reservation whose client write failed.
func Rollback(t ChargeTicket) error {
	if !t.Active {
		return nil
	}
	return vpn.DB().Transaction(func(tx *gorm.DB) error {
		if err := restoreSpent(tx, t.UserId, -t.Quote.DeltaSpent); err != nil {
			return err
		}
		if t.Create {
			return tx.Where("email = ?", t.Email).Delete(&model.ResellerClient{}).Error
		}
		return tx.Model(&model.ResellerClient{}).Where("email = ?", t.Email).
			Update("charged_bytes", t.PrevCharged).Error
	})
}
