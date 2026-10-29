package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strconv"
	"time"

	"pi-fortress/internal/audit"
	"pi-fortress/internal/base"
)

const actionTimeout = 5 * time.Minute

type Role uint8

const (
	RoleOperator Role = 1 << iota
	RoleAdmin
	roleAll = RoleOperator | RoleAdmin
)

var (
	ErrDenied  = errors.New("role may not run this verb")
	ErrNoVerb  = errors.New("unknown verb")
	ErrConfirm = errors.New("verb needs Confirm")
	errNoWrite = errors.New("verb needs an output writer")
)

// Args carries the parameters of each verb. Unused fields stay zero.
// reboot and poweroff require Confirm, so no client reaches them by
// accident.
type Args struct {
	Name, Value, List, MAC, IP, Key string
	// Env is a set of configuration keys that change as one edit. The DoT
	// provider is the reason. pf render refuses a name without its addresses.
	// Thus the two must arrive together, or the change could never occur.
	Env            map[string]string
	Local, Confirm bool
	N              int
	Log            LogKind
	Out            io.Writer
	// Secret is the one field that fields() must never copy into an audit
	// entry. It gives a verb that needs a passphrase a location that is not
	// Value. Without it, each future caller would have to remember which of
	// the general-purpose string fields is safe. The audit log records that
	// an unlock attempt occurred, by whom, and whether it worked. That is the
	// valuable line. The log never records what the operator typed.
	Secret string
}

type Verb struct {
	Name  string
	Roles Role
	// Mutates marks a verb that changes state. The audit log records these
	// verbs. The other verbs are reads and would be noise in the log. It is a
	// field, not a list in a different location, so the two cannot drift.
	// Also, the table then shows quickly that reserve, unreserve and
	// dns.reload change things, although all roles can use them.
	Mutates bool
	Run     func(c *Config, ctx context.Context, a Args) (any, error)
}

type Status struct {
	Device         Device
	ApplyRunning   bool
	RebootRequired bool
	Kernel         KernelLock
}

func ok(err error) (any, error) { return nil, err }

func exists(path string) bool {
	_, err := os.Stat(path)
	return path != "" && err == nil
}

var Verbs = []Verb{
	{"status", roleAll, false, func(c *Config, _ context.Context, _ Args) (any, error) {
		return Status{Device: c.Device(), ApplyRunning: Held(c.LockPath), RebootRequired: exists(c.RebootFlag), Kernel: c.KernelLock()}, nil
	}},
	{"units", roleAll, false, func(c *Config, _ context.Context, _ Args) (any, error) { return c.UnitsHealth(), nil }},
	{"ifaces", roleAll, false, func(c *Config, _ context.Context, _ Args) (any, error) { return c.Interfaces(), nil }},
	{"sample", roleAll, false, func(c *Config, _ context.Context, _ Args) (any, error) { return c.LastSample(), nil }},
	{"enroll.stats", roleAll, false, func(c *Config, _ context.Context, _ Args) (any, error) { return c.EnrollStats() }},
	{"leases", roleAll, false, func(c *Config, _ context.Context, _ Args) (any, error) { return c.Hosts(), nil }},
	{"stats", roleAll, false, func(c *Config, _ context.Context, _ Args) (any, error) { return c.Stats(), nil }},
	{"reserve", roleAll, true, func(c *Config, _ context.Context, a Args) (any, error) { return c.Reserve(a.MAC, a.IP, a.Name) }},
	{"unreserve", roleAll, true, func(c *Config, _ context.Context, a Args) (any, error) { return ok(c.Unreserve(a.MAC)) }},
	{"house.list", roleAll, false, listVerb(HouseLists, "list")},
	{"house.add", roleAll, true, listVerb(HouseLists, "add")},
	{"house.del", roleAll, true, listVerb(HouseLists, "del")},
	{"agent.list", roleAll, false, listVerb(AgentLists, "list")},
	{"agent.add", RoleAdmin, true, listVerb(AgentLists, "add")},
	{"agent.del", RoleAdmin, true, listVerb(AgentLists, "del")},
	{"feeds", roleAll, false, func(c *Config, _ context.Context, _ Args) (any, error) { return c.Feeds() }},
	{"feed.enable", RoleAdmin, true, func(c *Config, _ context.Context, a Args) (any, error) {
		return ok(c.SetFeedEnabled(a.Name, a.Value != "false"))
	}},
	{"slots", roleAll, false, func(c *Config, _ context.Context, _ Args) (any, error) { return c.Slots() }},
	{"secrets.state", roleAll, false, func(c *Config, ctx context.Context, _ Args) (any, error) { return c.SecretsState(ctx) }},
	{"secrets.unlock", RoleAdmin, true, func(c *Config, ctx context.Context, a Args) (any, error) {
		return ok(c.UnlockSecrets(ctx, a.Secret))
	}},
	{"secrets.lock", RoleAdmin, true, func(c *Config, ctx context.Context, _ Args) (any, error) {
		return ok(c.LockSecrets(ctx))
	}},
	{"slot.delete", RoleAdmin, true, func(c *Config, _ context.Context, a Args) (any, error) { return c.DeleteSlot(a.Name) }},
	{"slot.disable", roleAll, true, func(c *Config, _ context.Context, a Args) (any, error) { return ok(c.DisableSlot(a.Name)) }},
	{"slot.restore", RoleAdmin, true, func(c *Config, _ context.Context, a Args) (any, error) { return ok(c.RestoreSlot(a.Name)) }},
	{"slot.purge", RoleAdmin, true, func(c *Config, _ context.Context, a Args) (any, error) { return c.PurgeSlot(a.Name) }},
	{"claim.issue", roleAll, true, func(c *Config, _ context.Context, a Args) (any, error) { return c.IssueClaim(a.Name) }},
	{"logs.list", roleAll, false, func(c *Config, _ context.Context, _ Args) (any, error) { return c.LogList(), nil }},
	{"logs", roleAll, false, func(c *Config, _ context.Context, a Args) (any, error) {
		if a.Log == LogFirstSeen && a.Name != "" {
			return c.SegmentFirstSeen(a.Name, a.N), nil
		}
		return c.Log(a.Log, a.N)
	}},
	{"segments", roleAll, false, func(c *Config, _ context.Context, _ Args) (any, error) { return c.Segments(), nil }},
	{"segment.env", roleAll, false, func(c *Config, _ context.Context, a Args) (any, error) { return c.SegmentEnv(a.Name) }},
	{"segment.set", RoleAdmin, true, func(c *Config, _ context.Context, a Args) (any, error) {
		if len(a.Env) > 0 {
			return c.SetSegmentEnvKeys(a.Name, a.Env)
		}
		return c.SetSegmentEnvKeys(a.Name, map[string]string{a.Key: a.Value})
	}},
	{"net.env.get", roleAll, false, func(c *Config, _ context.Context, _ Args) (any, error) { return c.NetEnv(), nil }},
	{"net.env.set", RoleAdmin, true, func(c *Config, _ context.Context, a Args) (any, error) { return c.SetNetEnv(a.Env) }},
	{"house.env.get", roleAll, false, func(c *Config, _ context.Context, _ Args) (any, error) { return base.LoadEnv(c.HouseEnv), nil }},
	{"house.env.set", RoleAdmin, true, func(c *Config, _ context.Context, a Args) (any, error) {
		if len(a.Env) > 0 {
			return c.SetHouseEnvKeys(a.Env)
		}
		return ok(c.SetHouseEnv(a.Key, a.Value))
	}},
	// apply has no deadline of its own. A SIGTERM part way through apply.sh
	// leaves a half-applied box (ruleset loaded, resolver not restarted, or
	// the reverse). That is worse than an apply that ran long. The context of
	// the caller, when the operator quits, is the only stop.
	{"apply", RoleAdmin, true, func(c *Config, ctx context.Context, a Args) (any, error) {
		if a.Out == nil {
			return nil, errNoWrite
		}
		return ok(c.Apply(ctx, a.Local, a.Out))
	}},
	{"fetch", RoleAdmin, true, func(c *Config, ctx context.Context, a Args) (any, error) {
		if a.Out == nil {
			return nil, errNoWrite
		}
		ctx, cancel := context.WithTimeout(ctx, actionTimeout)
		defer cancel()
		return ok(c.Fetch(ctx, a.Out))
	}},
	{"dns.restart", RoleAdmin, true, func(c *Config, _ context.Context, _ Args) (any, error) { return ok(c.RestartHouseDNS()) }},
	{"dns.reload", roleAll, true, func(c *Config, _ context.Context, _ Args) (any, error) { return ok(c.ReloadHouseDNS()) }},
	{"reboot", RoleAdmin, true, confirmVerb((*Config).Reboot)},
	{"poweroff", RoleAdmin, true, confirmVerb((*Config).Shutdown)},
}

// confirmVerb puts an irreversible action behind Args.Confirm, so no
// client reaches it by accident.
func confirmVerb(fn func(*Config) error) func(*Config, context.Context, Args) (any, error) {
	return func(c *Config, _ context.Context, a Args) (any, error) {
		if !a.Confirm {
			return nil, ErrConfirm
		}
		return ok(fn(c))
	}
}

// listVerb binds one operation to one family of lists so a house verb
// can never touch an agent overlay and vice versa.
func listVerb(family []string, op string) func(*Config, context.Context, Args) (any, error) {
	return func(c *Config, _ context.Context, a Args) (any, error) {
		if !slices.Contains(family, a.List) {
			return nil, errList
		}
		switch op {
		case "add":
			return ok(c.ListAdd(a.List, a.Value))
		case "del":
			return ok(c.ListRemove(a.List, a.Value))
		}
		return c.List(a.List)
	}
}

func Lookup(name string) (Verb, bool) {
	for _, v := range Verbs {
		if v.Name == name {
			return v, true
		}
	}
	return Verb{}, false
}

// Call is the one entry point for a front end. It checks the role before
// it looks at an argument.
func (c *Config) Call(role Role, name string, a Args) (any, error) {
	return c.CallCtx(context.Background(), role, name, a)
}

func (c *Config) CallCtx(ctx context.Context, role Role, name string, a Args) (any, error) {
	v, found := Lookup(name)
	if !found {
		return nil, ErrNoVerb
	}
	// The code also records a refused verb, before the role check can hide
	// it. An attempt that should not have occurred is the most valuable entry.
	if v.Roles&role == 0 {
		c.audit(v, role, a, 0, ErrDenied)
		return nil, ErrDenied
	}
	start := time.Now()
	out, err := v.Run(c, ctx, a)
	c.audit(v, role, a, time.Since(start), err)
	return out, err
}

// audit records a state change. It skips reads: they are most of the
// traffic and none of the record.
func (c *Config) audit(v Verb, role Role, a Args, took time.Duration, err error) {
	if c.Audit == nil || !v.Mutates {
		return
	}
	e := audit.Entry{
		Verb:  v.Name,
		Role:  role.String(),
		Actor: c.actor(),
		Args:  a.fields(),
		OK:    err == nil,
		MS:    took.Milliseconds(),
	}
	if err != nil {
		e.Err = err.Error()
	}
	// apply replaces this process with apply.sh through syscall.Exec. Thus no
	// Go code stays to say what changed or whether it worked. The entry says
	// that the operator requested the action, and claims nothing more.
	if v.Name == "apply" && err == nil {
		e.Ev = "requested"
	}
	_ = c.Audit.Append(e)
}

func (c *Config) actor() string {
	if c.Actor != "" {
		return c.Actor
	}
	return audit.Actor(os.Getenv, os.Getuid())
}

func (r Role) String() string {
	switch r {
	case RoleAdmin:
		return "admin"
	case RoleOperator:
		return "operator"
	}
	return "role" + strconv.Itoa(int(r))
}

// fields is the audit payload: all fields in Args that name what changed.
// Out is a writer and N is the line count of a read, so neither belongs.
// This is an allow-list intentionally, and it must stay one. Secret carries
// the store passphrase for secrets.unlock. It stays out of the audit
// record because this list does not name it, not because of a check.
func (a Args) fields() map[string]string {
	m := map[string]string{}
	for k, v := range map[string]string{
		"name": a.Name, "value": a.Value, "list": a.List,
		"mac": a.MAC, "ip": a.IP, "key": a.Key,
	} {
		if v != "" {
			m[k] = v
		}
	}
	if a.Local {
		m["local"] = "true"
	}
	// Config values, not secrets: here, the audit log must say to which
	// provider the box pointed, and when.
	for k, v := range a.Env {
		m["env."+k] = v
	}
	if len(m) == 0 {
		return nil
	}
	return m
}
