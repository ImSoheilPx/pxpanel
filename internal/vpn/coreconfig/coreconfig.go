// Package coreconfig is the ONE home of vpn-ui's advanced core config editor
// backend (web/service/coreconfig.go): the storage + merge + apply half every
// generator merges through, plus the editor-adjacent halves that do not need
// the whole protocol-service set (the editable-file catalog SEAM, the save
// storage, the offline validators, and the per-core override clear that
// uninstall calls).
//
// WHY THE OPERATOR TEXT LIVES IN THE DATABASE AND NOT IN THE FILE (vpn-ui
// coreconfig.go, kept): nothing on disk survives normal panel operation —
// startup regenerates every core (Init<Core> → GenerateAllConfigs +
// RestartServices), every inbound/client save of a protocol regenerates its
// core, and the traffic job regenerates some every 10s. So the operator's text
// is stored in the settings KV (key "coreConfigOverrides") and merged back in
// at the TAIL of every generator via ApplyCoreConfigOverride. That makes the
// stored text the SOURCE and the file on disk a pure render of "generated body
// + override".
//
// CONSOLIDATION (core wave): this package used to hold only the apply half
// while internal/vpn/configedit (P1) held a second copy of the same storage +
// merge machinery with a SECOND cache over the same settings row — a write
// through one left the other stale until restart. configedit is now a thin
// alias delegating here, and openvpn's package-local copy (openvpn/
// coreconfig.go) is a shim over ApplyCoreConfigOverride. There is exactly one
// cache and one merge.
//
// TODO(controllers wave): the endpoint half — CoreService.CoreConfigTargets /
// SaveCoreConfigOverride / ApplyCoreConfig / the health-check restart flow
// (vpn-ui coreconfig.go:196-891) — needs the whole protocol-service set. It
// should register its per-core catalog providers via RegisterTargets and store
// through StoreOverride/ClearCoreConfigOverrides rather than re-invent the
// storage format. (ocserv/coreconfig.go still carries its own package-local
// copy of the apply half; migrating it onto this package is the ocserv wave's
// edit, not this package's.)
package coreconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/log"
)

// Override modes (vpn-ui coreconfig.go:37-53).
const (
	// ModeAppend puts the override after the generated body. It survives
	// inbound and client churn, because everything the generator knows how to
	// write is still written. It is what a POST with no mode at all gets, being
	// the conservative one of the two.
	//
	// NO UI OFFERS THIS ANY MORE, and that is deliberate rather than an
	// oversight: the editor shows one pane holding the WHOLE file, and a mode
	// selector on top of that is a second mental model for the operator to
	// hold. The mode is still stored, still merged and still accepted by the
	// endpoint, so an override written through the API keeps working. Do not
	// delete it as dead code.
	ModeAppend = "append"
	// ModeReplace makes the override the whole file. Total control, at the
	// cost of freezing out every inbound and client added after it was
	// written. This is what the editor posts, always.
	ModeReplace = "replace"
)

// Banner marks where the panel's render stops and the operator's text starts.
// Every format the panel writes here takes `#` as a line comment.
const Banner = "# ---- pxpanel: operator override (Core Settings -> Edit config) ----"

// coreConfigBanner is this file's historical (P3-wave) name for Banner, kept
// for the in-package call sites.
const coreConfigBanner = Banner

// CoreConfigOverride is one stored edit.
type CoreConfigOverride struct {
	Mode string `json:"mode"`
	Text string `json:"text"`
}

// coreConfigCache memoizes the parsed override map.
//
// Not a micro-optimisation: ApplyCoreConfigOverride sits inside the generators,
// and the traffic job drives some generators every 10 seconds for every
// inbound, so an uncached read would put a settings SELECT on that path
// forever. Every write goes through SetOverrides, which is the only
// invalidation point. (Consolidation: this is now the ONLY cache over the
// overrides row — the former configedit and openvpn copies delegate here.)
var coreConfigCache struct {
	sync.RWMutex
	loaded bool
	m      map[string]CoreConfigOverride
}

// settingsKey is the settings-KV row the override map is stored under (the
// vpn-ui key, kept so a migrated DB keeps working).
const settingsKey = "coreConfigOverrides"

// Key is the key one override is stored under: the core, the owning inbound
// (0 for a file the whole protocol shares), and a file discriminator.
//
// The file part is not redundant with the inbound: OpenVPN writes TWO configs
// for one inbound (server-udp.conf and server-tcp.conf), and l2tp and pptp each
// write a daemon config plus a pppd options file with no inbound of their own.
func Key(core string, inboundId int, file string) string {
	return fmt.Sprintf("%s:%d:%s", core, inboundId, file)
}

// Overrides returns every stored override (vpn-ui: getCoreConfigOverrides).
//
// A corrupt blob degrades to "no overrides" rather than an error. The
// generators call this on every run, so failing here would leave the panel
// unable to write ANY config until the row was fixed by hand, and overrides
// are an opt-in extra.
func Overrides() map[string]CoreConfigOverride {
	coreConfigCache.RLock()
	if coreConfigCache.loaded {
		m := coreConfigCache.m
		coreConfigCache.RUnlock()
		return m
	}
	coreConfigCache.RUnlock()

	coreConfigCache.Lock()
	defer coreConfigCache.Unlock()
	coreConfigCache.m = map[string]CoreConfigOverride{}
	coreConfigCache.loaded = true

	db := vpn.DB()
	if db == nil {
		return coreConfigCache.m
	}
	var row model.Setting
	if err := db.Where("key = ?", settingsKey).First(&row).Error; err != nil {
		return coreConfigCache.m // unset: no overrides
	}
	if strings.TrimSpace(row.Value) == "" {
		return coreConfigCache.m
	}
	parsed := map[string]CoreConfigOverride{}
	if err := json.Unmarshal([]byte(row.Value), &parsed); err != nil {
		log.Warning("core config: coreConfigOverrides is not valid JSON, ignoring it:", err)
		return coreConfigCache.m
	}
	coreConfigCache.m = parsed
	return coreConfigCache.m
}

// SetOverrides stores the whole map and refreshes the cache (vpn-ui:
// setCoreConfigOverrides — the only invalidation point).
//
// TODO(settings wave): route through the settings service's setString (the
// vpn-ui shape) instead of a direct KV row write, so caching/invalidation and
// any future settings eventing stay in one place.
func SetOverrides(m map[string]CoreConfigOverride) error {
	if m == nil {
		m = map[string]CoreConfigOverride{}
	}
	blob, err := json.Marshal(m)
	if err != nil {
		return err
	}
	db := vpn.DB()
	if db == nil {
		return fmt.Errorf("no database")
	}
	// model.Setting.key carries a PLAIN index (idx_settings_key), not a unique
	// one, so an ON CONFLICT upsert has no target — do the read-then-write
	// manually. (vpn-ui went through SettingService.setString, same semantics.)
	setting := model.Setting{Key: settingsKey, Value: string(blob)}
	var existing model.Setting
	if err := db.Where(model.Setting{Key: settingsKey}).First(&existing).Error; err == nil {
		if err := db.Model(&model.Setting{}).Where("id = ?", existing.Id).Update("value", setting.Value).Error; err != nil {
			return err
		}
	} else if err := db.Create(&setting).Error; err != nil {
		return err
	}
	coreConfigCache.Lock()
	coreConfigCache.m = m
	coreConfigCache.loaded = true
	coreConfigCache.Unlock()
	return nil
}

// CopyOverrides returns a map a caller may mutate without racing the cache
// (vpn-ui: copyCoreConfigOverrides).
func CopyOverrides() map[string]CoreConfigOverride {
	src := Overrides()
	coreConfigCache.RLock()
	defer coreConfigCache.RUnlock()
	out := make(map[string]CoreConfigOverride, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// StoreOverride validates the mode and stores one override. This is the
// storage half of vpn-ui's SaveCoreConfigOverride; the endpoint's
// apply+restart+health-check flow around it is the controllers wave's.
func StoreOverride(core string, inboundId int, file, mode, text string) error {
	switch mode {
	case ModeAppend, ModeReplace:
	default:
		return fmt.Errorf("unknown override mode %q", mode)
	}
	overrides := CopyOverrides()
	key := Key(core, inboundId, file)
	if strings.TrimSpace(text) == "" {
		delete(overrides, key)
	} else {
		overrides[key] = CoreConfigOverride{Mode: mode, Text: text}
	}
	return SetOverrides(overrides)
}

// ClearCoreConfigOverrides drops every override belonging to one core
// (vpn-ui coreconfig.go:875). Uninstalling a core has to call this: keeping
// the overrides would silently re-apply an edit written against this install's
// inbound ids to whatever inbound reuses an id after a reinstall.
func ClearCoreConfigOverrides(core string) {
	overrides := CopyOverrides()
	prefix := core + ":"
	changed := false
	for key := range overrides {
		if strings.HasPrefix(key, prefix) {
			delete(overrides, key)
			changed = true
		}
	}
	if !changed {
		return
	}
	if err := SetOverrides(overrides); err != nil {
		log.Warning("core config: could not clear the overrides for", core, err)
	}
}

// ApplyCoreConfigOverride merges the stored override into the body a generator
// just rendered (vpn-ui coreconfig.go:applyCoreConfigOverride). This is THE
// apply point: every hooked generator calls it as the last thing before
// writing, so the set of files an operator can override is the set of call
// sites of this function and nothing else.
//
// APPEND SEMANTICS ARE NOT UNIFORM ACROSS DAEMONS, so append mode cannot be
// promised to override an already-rendered directive (vpn-ui coreconfig.go
// keeps the full per-daemon rationale). OpenVPN keeps the FIRST occurrence of
// a directive and ignores later ones, so an appended line there can only ADD
// an option the generated body never sets. pppd, xl2tpd, pptpd, ocserv and
// accel-ppp keep the last, so an appended line does win. TOML and swanctl are
// neither: an appended fragment joins whichever table or section the generated
// body ended in unless it opens its own. An API caller asking for append takes
// all of that on; the editor posts replace over the whole file, so what the
// operator sees is what lands.
func ApplyCoreConfigOverride(core string, inboundId int, file, rendered string) string {
	ov, ok := Overrides()[Key(core, inboundId, file)]
	if !ok {
		return rendered
	}
	return MergeCoreConfig(rendered, ov.Mode, ov.Text)
}

// MergeCoreConfig is the merge itself, with the values passed in rather than
// read from the database, so a save can check the exact bytes BEFORE storing
// them (vpn-ui coreconfig.go:mergeCoreConfig).
func MergeCoreConfig(rendered, mode, text string) string {
	if strings.TrimSpace(text) == "" {
		return rendered
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	if mode == ModeReplace {
		return text
	}
	// Exactly one blank line between the render and the banner, always. An
	// unstable render would defeat mtproto's write-only-on-change guard and
	// make telemt hot-reload on every 10s tick.
	return strings.TrimRight(rendered, "\n") + "\n\n" + coreConfigBanner + "\n" + text
}

// --------------------------------------------------------------------------- //
//  The catalog of editable files (vpn-ui coreconfig.go:196-304, seam shape)
// --------------------------------------------------------------------------- //

// Target is one editable generated file (vpn-ui: coreConfigTarget, exported so
// the package that owns the render funcs can hand catalog rows in through
// RegisterTargets without coreconfig importing it).
type Target struct {
	Core      string
	InboundId int
	// File is the discriminator inside the storage key and the on-disk basename.
	File string
	// Label is the short name shown in the file picker.
	Label string
	// Remark is the owning inbound's name, so a per-inbound entry says which one.
	Remark string
	// Path is the absolute file the merged text is written to.
	Path string
	// Format picks the editor's syntax mode: "toml", or anything else for the
	// key/value-with-#-comments family (ini, pppd options, openvpn, swanctl).
	Format string

	// Render produces the generated body with NO override applied. It is both
	// what "reset to default" goes back to and, with any override merged into
	// it, the text the editor is filled with.
	Render func() (string, error)
	// Validate is the pre-save check on the merged text, nil when the daemon
	// offers no way to check a config without running it.
	Validate func(content string) error
}

// targetProviders registers one catalog provider per core. The controllers
// wave (or a protocol wave volunteering early) fills it from init(); a core
// with no provider honestly has no editable files yet.
var (
	targetsMu       sync.RWMutex
	targetProviders = map[string]func() []Target{}
)

// RegisterTargets attaches one core's editable-file provider. Call from init()
// of the package that owns the render funcs (vpn-ui kept these as
// CoreService.<core>ConfigTargets methods; here the lists are data, so the
// provider needs no service object).
func RegisterTargets(core string, provider func() []Target) {
	targetsMu.Lock()
	defer targetsMu.Unlock()
	targetProviders[core] = provider
}

// TargetsFor returns every editable file for a core (vpn-ui:
// CoreService.coreConfigTargets' dispatch half).
//
// An empty slice is an honest answer, not a failure: wg-c, AmneziaWG, the GRE
// tunnel itself, SSH and RADIUS have no config file anywhere (the first three
// are programmed through kernel netlink, the last two run inside the panel
// binary), and a core with no inbound has nothing to generate a config for yet.
func TargetsFor(core string) []Target {
	targetsMu.RLock()
	provider := targetProviders[core]
	targetsMu.RUnlock()
	if provider == nil {
		return nil
	}
	return provider()
}

// HasTargets reports whether a core owns any editable file right now (vpn-ui:
// CoreService.CoreHasConfigTargets).
func HasTargets(core string) bool {
	return len(TargetsFor(core)) > 0
}

// --------------------------------------------------------------------------- //
//  Validation (vpn-ui coreconfig.go:582-649)
// --------------------------------------------------------------------------- //

// ValidateSwanctlBraces is the only offline check a swanctl-style config can
// get (vpn-ui: validateSwanctlBraces). strongSwan has no mode that parses a
// file outside /etc/swanctl, so the real verdict comes from the reload the
// apply performs. Catching an unbalanced brace here still spares the operator
// a restart round trip for the commonest typo.
func ValidateSwanctlBraces(content string) error {
	depth, line := 0, 0
	for _, raw := range strings.Split(content, "\n") {
		line++
		text := raw
		if i := strings.Index(text, "#"); i >= 0 {
			text = text[:i]
		}
		for _, r := range text {
			switch r {
			case '{':
				depth++
			case '}':
				depth--
				if depth < 0 {
					return fmt.Errorf("line %d: a closing brace with no matching opening brace", line)
				}
			}
		}
	}
	if depth > 0 {
		return fmt.Errorf("%d section(s) are never closed", depth)
	}
	return nil
}

// ValidateWithDaemon runs a daemon's own config check over the would-be file,
// written to a temp path so a rejected config never touches the live one
// (vpn-ui: validateWithDaemon).
//
// A missing binary is NOT an error. The core may simply not be installed on
// this host, and refusing the save over that would be a check that can only
// ever block.
func ValidateWithDaemon(bin, name, content string, args func(tmp string) []string) error {
	if bin == "" {
		return nil
	}
	if _, err := os.Stat(bin); err != nil {
		if _, err := exec.LookPath(bin); err != nil {
			log.Debug("core config: skipping the config check, no binary at", bin)
			return nil
		}
	}
	dir, err := os.MkdirTemp("", "pxpanel-cfgcheck-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	tmp := dir + "/" + name
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	out, err := exec.CommandContext(context.Background(), bin, args(tmp)...).CombinedOutput()
	if err == nil {
		return nil
	}
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		msg = err.Error()
	}
	return fmt.Errorf("%s", msg)
}

// CoreConfigHealth is what a save reports back about the core it just
// restarted (vpn-ui coreconfig.go:655). The controllers-wave endpoint fills
// the Reverted/Logs halves after its apply+watch flow.
type CoreConfigHealth struct {
	OK bool `json:"ok"`
	// Reverted records that the override was rolled back because the core
	// would not stay up with it, so the UI does not tell the operator their
	// text was kept.
	Reverted bool   `json:"reverted"`
	Logs     string `json:"logs"`
}

// CoreConfigWatch* are how long a core is watched after an apply, and how long
// it is given to settle first (vpn-ui coreconfig.go:830). Exported so the
// controllers wave reuses the exact windows rather than inventing its own.
const (
	CoreConfigWatchWindow = 10 * time.Second
	CoreConfigWatchSettle = 2 * time.Second
	CoreConfigWatchTick   = 500 * time.Millisecond
)
