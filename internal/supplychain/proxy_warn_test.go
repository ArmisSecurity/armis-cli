package supplychain

import (
	"testing"
	"time"
)

// warnProxy builds a Proxy in warn mode with an explicit direct set. directDeps
// nil means "undeterminable" (the proxy must then fail safe and block).
func warnProxy(directDeps []string) *Proxy {
	p, err := NewProxy(ProxyConfig{
		Policy:     Policy{MinReleaseAge: 72 * time.Hour, TransitivePolicy: TransitivePolicyWarn},
		Mode:       ModeNPM,
		DirectDeps: directDeps,
	})
	if err != nil {
		panic(err)
	}
	return p
}

func TestWarnPolicy_TransitiveAllowedThrough(t *testing.T) {
	// debug is NOT in the direct set → transitive. Under warn, its young 4.4.0
	// must NOT be filtered (so a parent's ^4.4.0 stays satisfiable), and it must
	// be recorded as warned-through.
	p := warnProxy([]string{"express"}) // express is direct; debug is transitive

	body := npmMetadata(
		map[string]time.Duration{"4.3.9": 100 * 24 * time.Hour, "4.4.0": time.Hour},
		nil,
	)
	_, blocked := p.filterMetadata(body, "debug")

	if len(blocked) != 0 {
		t.Errorf("a young transitive must not be blocked under warn; got blocked=%#v", blocked)
	}
	warned := p.Warned()
	if len(warned) != 1 || warned[0].Name != "debug" || warned[0].Version != "4.4.0" {
		t.Errorf("expected debug@4.4.0 recorded as warned-through; got %#v", warned)
	}
}

func TestWarnPolicy_DirectStillBlocked(t *testing.T) {
	// express IS in the direct set. Even under warn, a young direct dep must be
	// blocked — that is where the developer has control and risk concentrates.
	p := warnProxy([]string{"express"})

	body := npmMetadata(
		map[string]time.Duration{"4.18.0": 100 * 24 * time.Hour, "4.19.0": time.Hour},
		nil,
	)
	_, blocked := p.filterMetadata(body, "express")

	if len(blocked) != 1 || blocked[0].Version != "4.19.0" {
		t.Errorf("a young DIRECT dep must still be blocked under warn; got blocked=%#v", blocked)
	}
	if w := p.Warned(); len(w) != 0 {
		t.Errorf("a direct dep must never be warned-through; got %#v", w)
	}
}

func TestWarnPolicy_UndeterminableDirectSetFailsSafe(t *testing.T) {
	// directDeps nil → the direct set is undeterminable, so the proxy must treat
	// every package as direct and BLOCK young versions (fail safe), even though
	// the policy is warn.
	p := warnProxy(nil)

	body := npmMetadata(
		map[string]time.Duration{"1.0.0": 100 * 24 * time.Hour, "2.0.0": time.Hour},
		nil,
	)
	_, blocked := p.filterMetadata(body, "anything")

	if len(blocked) != 1 {
		t.Errorf("undeterminable direct set must fail safe → block; got blocked=%#v", blocked)
	}
	if w := p.Warned(); len(w) != 0 {
		t.Errorf("nothing may be warned-through when the direct set is undeterminable; got %#v", w)
	}
}

func TestBlockPolicy_NoWarnThrough(t *testing.T) {
	// Default block policy: a transitive young dep is blocked, never warned —
	// the no-opt-in guarantee.
	p, err := NewProxy(ProxyConfig{
		Policy:     Policy{MinReleaseAge: 72 * time.Hour, TransitivePolicy: TransitivePolicyBlock},
		Mode:       ModeNPM,
		DirectDeps: []string{"express"}, // debug is transitive
	})
	if err != nil {
		t.Fatal(err)
	}

	body := npmMetadata(
		map[string]time.Duration{"4.3.9": 100 * 24 * time.Hour, "4.4.0": time.Hour},
		nil,
	)
	_, blocked := p.filterMetadata(body, "debug")

	if len(blocked) != 1 {
		t.Errorf("block policy must filter a young transitive; got blocked=%#v", blocked)
	}
	if w := p.Warned(); len(w) != 0 {
		t.Errorf("block policy must never warn-through; got %#v", w)
	}
}
