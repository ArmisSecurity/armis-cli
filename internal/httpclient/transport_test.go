package httpclient

import (
	"net/http"
	"reflect"
	"testing"
)

func TestProxyAwareTransport(t *testing.T) {
	t.Run("returns a transport with a proxy resolver set", func(t *testing.T) {
		transport := ProxyAwareTransport()
		if transport == nil {
			t.Fatal("expected non-nil transport")
		}
		if transport.Proxy == nil {
			t.Fatal("expected Proxy func to be set so the OS proxy configuration is honored")
		}
	})

	t.Run("does not mutate http.DefaultTransport", func(t *testing.T) {
		def, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			t.Skip("DefaultTransport is not *http.Transport on this platform")
		}
		// The clone must be a distinct instance; mutating it must not affect the
		// shared default transport used by the rest of the program.
		transport := ProxyAwareTransport()
		if transport == def {
			t.Fatal("ProxyAwareTransport must return a clone, not the shared DefaultTransport")
		}
	})

	t.Run("proxy resolver is memoized across calls", func(t *testing.T) {
		// systemProxyFunc memoizes the resolver via sync.Once; two transports must
		// share the *same* underlying func value rather than re-reading OS settings
		// each time. Func values aren't comparable with ==, so compare the code
		// pointers: a recomputed resolver would yield a distinct closure here.
		a := ProxyAwareTransport()
		b := ProxyAwareTransport()
		if a.Proxy == nil || b.Proxy == nil {
			t.Fatal("expected both transports to carry a proxy resolver")
		}
		pa := reflect.ValueOf(a.Proxy).Pointer()
		pb := reflect.ValueOf(b.Proxy).Pointer()
		if pa != pb {
			t.Errorf("expected the memoized resolver to be reused across calls; got distinct func values (%x vs %x)", pa, pb)
		}
	})
}
