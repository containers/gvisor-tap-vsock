package utils

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFileWatcher(t *testing.T) {
	if testing.Short() {
		// we can't really speed up the test as we need to wait for the
		// inode cache to expire so that we can read the latest
		// file's modtime.
		t.Skip("skipping test in short mode.")
	}
	t.Parallel()

	assertSpec := func(t *testing.T, watchedPath, filePath string) {
		t.Helper()

		fw := NewFileWatcher(watchedPath)

		var numTriggered atomic.Int64
		assertNumTriggered := func(expected int) {
			time.Sleep(fw.pollInterval + 200*time.Millisecond)
			assert.Equal(t, int64(expected), numTriggered.Load())
		}

		fw.Start(func() {
			numTriggered.Add(1)
		})

		// important: adding a random sleep here so that the next fw's poll
		// results in inode cache miss, hence calling stat will return the latest
		// modtime.
		time.Sleep(1 * time.Second)

		// CASE: can detect changes to the file.
		if err := os.WriteFile(filePath, []byte("2"), 0o600); err != nil {
			panic(err)
		}
		assertNumTriggered(1)

		// CASE: can detect "swap"-based file modification.
		tmpFile := filepath.Join(filepath.Dir(filePath), "tmp.txt")
		if err := os.WriteFile(tmpFile, []byte("lol"), 0o600); err != nil {
			panic(err)
		}
		if err := os.Rename(tmpFile, filePath); err != nil {
			panic(err)
		}
		assertNumTriggered(2)

		// CASE: combine multiple partial writes into single event.
		fd, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			panic(err)
		}
		// we assume these writes happens in less than 50ms.
		_, _ = fd.Write([]byte("a"))
		_ = fd.Sync()
		_, _ = fd.Write([]byte("b"))
		fd.Close()
		assertNumTriggered(3)

		// CASE: closed file watcher should not call the callback after Stop() is called.
		fw.Stop()
		if err := os.WriteFile(filePath, []byte("2"), 0o600); err != nil {
			panic(err)
		}
		assertNumTriggered(3) // does not change.

	}

	t.Run("normal file", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		path := filepath.Join(dir, "file.txt")
		_ = os.WriteFile(path, []byte("1"), 0o600)

		assertSpec(t, path, path)
	})

	t.Run("symlink", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		path := filepath.Join(dir, "file.txt")
		_ = os.WriteFile(path, []byte("1"), 0o600)

		symlinkPath := filepath.Join(dir, "symlink.txt")
		_ = os.Symlink(path, symlinkPath)

		assertSpec(t, symlinkPath, path)
	})
}
