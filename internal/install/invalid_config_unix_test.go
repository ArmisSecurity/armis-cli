//go:build !windows

package install

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestRegisterRefusesFIFO uses a FIFO because os.ReadFile on one blocks
// forever; the guard must reject it before opening.
func TestRegisterRefusesFIFO(t *testing.T) {
	for _, k := range configKinds {
		t.Run(string(k.id), func(t *testing.T) {
			isolateHome(t)
			path := filepath.Join(t.TempDir(), k.file)
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Skipf("mkfifo unavailable: %v", err)
			}
			overrideConfigPaths(t, map[EditorID]string{k.id: path})

			done := make(chan error, 1)
			go func() {
				e, _ := EditorByID(k.id)
				done <- e.Register(filepath.Join(t.TempDir(), "plugin"))
			}()

			select {
			case err := <-done:
				assertRefusal(t, err, path)
			case <-time.After(5 * time.Second):
				t.Fatal("Register() blocked on a FIFO")
			}
			if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
				t.Errorf("FIFO was replaced (err %v)", err)
			}
		})
	}
}
