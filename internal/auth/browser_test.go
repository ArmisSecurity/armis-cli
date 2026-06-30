package auth

import "testing"

func TestOpenBrowserRejectsNonHTTP(t *testing.T) {
	restore := SetBrowserOpener(func(string) error {
		t.Error("opener should not be called for a rejected scheme")
		return nil
	})
	defer restore()

	for _, bad := range []string{"file:///etc/passwd", "javascript:alert(1)", "ftp://host/x", "not a url"} {
		if err := OpenBrowser(bad); err == nil {
			t.Errorf("OpenBrowser(%q) = nil, want error", bad)
		}
	}
}

func TestOpenBrowserAllowsHTTPS(t *testing.T) {
	var got string
	restore := SetBrowserOpener(func(u string) error { got = u; return nil })
	defer restore()

	const url = "https://moose.armis.com/oauth2/device/verify?user_code=ABCD-EFGH"
	if err := OpenBrowser(url); err != nil {
		t.Fatalf("OpenBrowser: %v", err)
	}
	if got != url {
		t.Errorf("opener got %q, want %q", got, url)
	}
}
