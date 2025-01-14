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
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	_ = os.WriteFile(path, []byte("1"), 0o600)

	fw, err := NewFileWatcher(path)
	fw.writeGracePeriod = 50 * time.Millisecond // reduce the delay to make the test runs faster.
	assert.NoError(t, err)
	_ = fw.w.Add(path)

	var numTriggered atomic.Int64
	assertNumTriggered := func(expected int) {
		time.Sleep(fw.writeGracePeriod + 50*time.Millisecond)
		assert.Equal(t, int64(expected), numTriggered.Load())
	}

	_ = fw.Start(func() {
		numTriggered.Add(1)
	})

	// CASE: can detect changes to the file.
	if err := os.WriteFile(path, []byte("2"), 0o600); err != nil {
		panic(err)
	}
	assertNumTriggered(1)

	// CASE: can detect "swap"-based file modification.
	tmpFile := filepath.Join(dir, "tmp.txt")
	if err := os.WriteFile(tmpFile, []byte("lol"), 0o600); err != nil {
		panic(err)
	}
	if err := os.Rename(tmpFile, path); err != nil {
		panic(err)
	}
	assertNumTriggered(2)

	// CASE: combine multiple partial writes into single event.
	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
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
	assert.NoError(t, fw.Stop())
	if err := os.WriteFile(path, []byte("2"), 0o600); err != nil {
		panic(err)
	}
	assertNumTriggered(3) // does not change.
}
