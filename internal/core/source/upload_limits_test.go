package source

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trypando/pando/internal/errs"
)

// entry is one file in a test archive.
type entry struct {
	header tar.Header
	body   string
}

func tarball(t *testing.T, entries ...entry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := e.header
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Size == 0 {
			h.Size = int64(len(e.body))
		}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		require.NoError(t, tw.WriteHeader(&h))
		_, err := tw.Write([]byte(e.body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return &buf
}

func file(name, body string) entry { return entry{header: tar.Header{Name: name}, body: body} }

// TestR410_AnUploadIsBoundedWhenUnpacked asserts R-410 for uploaded source:
// an archive is refused, with the reason, when it holds too many entries,
// when one file or all of them unpack past their limit, or when it holds a
// sparse file. A file over a limit is never written cut short.
func TestR410_AnUploadIsBoundedWhenUnpacked(t *testing.T) {
	limits := unpackLimits{file: 10, total: 15, entries: 3}
	refused := func(t *testing.T, archive *bytes.Buffer, says string) string {
		t.Helper()
		dir := t.TempDir()
		err := extractWithin(archive, dir, limits)
		require.Error(t, err)
		require.Equal(t, errs.ValidInvalid, errs.CodeOf(err))
		require.Contains(t, err.Error(), says)
		return dir
	}

	t.Run("within every limit", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, extractWithin(tarball(t, file("a", "0123456789"), file("b/c", "01234")), dir, limits))
		got, err := os.ReadFile(filepath.Join(dir, "b", "c"))
		require.NoError(t, err)
		require.Equal(t, "01234", string(got))
	})

	t.Run("too many entries", func(t *testing.T) {
		refused(t, tarball(t, file("a", ""), file("b", ""), file("c", ""), file("d", "")), "more than 3 files and directories")
	})

	t.Run("one file too large", func(t *testing.T) {
		refused(t, tarball(t, file("big", "01234567890")), "big, which is larger than 10 bytes")
	})

	t.Run("all of them too large", func(t *testing.T) {
		dir := refused(t, tarball(t, file("a", "0123456789"), file("b", "0123456789")), "unpacks to more than 15 bytes")
		_, err := os.Stat(filepath.Join(dir, "b"))
		require.True(t, os.IsNotExist(err), "refused before it was written")
	})

	t.Run("a sparse file", func(t *testing.T) {
		// The old GNU format, as an archive carries it.
		sparse := entry{header: tar.Header{Name: "holes", Typeflag: tar.TypeGNUSparse, Format: tar.FormatGNU}, body: "x"}
		refused(t, tarball(t, sparse), "holes as a sparse file")

		// The PAX format, which Go's writer will not produce, as the
		// reader reports it.
		require.True(t, isSparse(&tar.Header{PAXRecords: map[string]string{"GNU.sparse.major": "1"}}))
		require.False(t, isSparse(&tar.Header{Typeflag: tar.TypeReg, PAXRecords: map[string]string{"mtime": "1"}}))
	})
}

// TestR410_AFileLongerThanItsHeaderIsNotCutShort asserts the per-file limit
// is enforced on what is read, not on what the header claims, and a file over
// it fails rather than being truncated.
func TestR410_AFileLongerThanItsHeaderIsNotCutShort(t *testing.T) {
	dir := t.TempDir()
	tr := strings.NewReader(strings.Repeat("x", 20))
	n, err := extractFile(tr, &tar.Header{Name: "lying", Size: 1}, filepath.Join(dir, "lying"),
		unpackLimits{file: 10, total: 100, entries: 10}, 100)
	require.Error(t, err)
	require.Contains(t, err.Error(), "larger than 10 bytes")
	require.EqualValues(t, 11, n)
}

// TestR410_LimitsAreSaidInWholeUnits asserts how a refusal names a limit.
func TestR410_LimitsAreSaidInWholeUnits(t *testing.T) {
	require.Equal(t, "4 GB", sizeWords(4<<30))
	require.Equal(t, "256 MB", sizeWords(256<<20))
	require.Equal(t, "15 bytes", sizeWords(15))
}
