package source

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/trypando/pando/internal/core/spec"
	"github.com/trypando/pando/internal/errs"
)

// Uploaded source (R-262).
//
// `pando deploy ./` is a [D] in design 04 §4, and the reason is specific: an
// agent that just generated an app cannot commit it and push, but it can run a
// command. Without this, the agent workflow R-262 describes starts by asking a
// person to make a repository.
//
// An upload is stored as a gzipped tar under a directory Pando owns, keyed by
// the app. It is the source of record for that app's next deploy, so it is kept
// rather than streamed: R-020 says nothing is read from the repository at
// deploy time, and the same logic applies here — the deploy reads what was
// uploaded, not whatever is on somebody's laptop now.

// DefaultUploadDir is where a server keeps uploaded sources.
const DefaultUploadDir = "/var/lib/pando/uploads"

// uploadPath is where an app's uploaded archive is kept.
//
// An empty UploadDir is refused rather than joined, which would put every
// upload in whatever the working directory happens to be.
func (s Sources) uploadPath(appID string) (string, error) {
	if s.UploadDir == "" {
		return "", errs.New(errs.Internal, "Pando has no directory configured for uploaded source.")
	}
	return filepath.Join(s.UploadDir, appID+".tar.gz"), nil
}

// StoreUpload writes an uploaded archive for an app and returns its path.
func (s Sources) StoreUpload(appID string, r io.Reader) (string, error) {
	final, err := s.uploadPath(appID)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(s.UploadDir, 0o700); err != nil {
		return "", errs.Wrap(errs.Internal, "Pando could not store the upload.", err)
	}

	// Written to a temporary name and renamed, so a deploy that runs while an
	// upload is in flight reads the previous archive rather than half of the
	// new one.
	tmp := final + ".partial"

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", errs.Wrap(errs.Internal, "Pando could not store the upload.", err)
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", errs.Wrap(errs.Internal, "Pando could not store the upload.", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", errs.Wrap(errs.Internal, "Pando could not store the upload.", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", errs.Wrap(errs.Internal, "Pando could not store the upload.", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return "", errs.Wrap(errs.Internal, "Pando could not store the upload.", err)
	}
	return final, nil
}

// DiscardUpload removes a deleted app's stored upload.
//
// The archive is kept for the app's next deploy, and a deleted app has none:
// a restore goes to an app created again, with an upload of its own (R-206).
// It had been kept forever (issue #55). A missing archive is not an error — an
// app built from git never had one.
func (s Sources) DiscardUpload(appID string) error {
	if appID == "" || strings.ContainsAny(appID, `/\`) || strings.HasPrefix(appID, ".") {
		return errs.Newf(errs.ValidInvalid, "%q does not name an app.", appID)
	}
	final, err := s.uploadPath(appID)
	if err != nil {
		return err
	}
	for _, p := range []string{final, final + ".partial"} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return errs.Wrap(errs.Internal, "Pando could not remove the app's uploaded source.", err)
		}
	}
	return nil
}

// fetchUpload expands a stored upload into a checkout.
func (s Sources) fetchUpload(_ context.Context, src spec.Source) (*Checkout, error) {
	archive, err := s.uploadPath(src.UploadID)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(archive)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errs.New(errs.ValidInvalid,
			"This app's uploaded source is no longer on the server.").
			WithRemedy("Run `pando deploy .` from the app's directory again.")
	}
	if err != nil {
		return nil, errs.Wrap(errs.Internal, "Pando could not read the uploaded source.", err)
	}
	defer func() { _ = f.Close() }()

	dir, err := s.tempDir("pando-upload-")
	if err != nil {
		return nil, errs.Wrap(errs.Internal, "Pando could not unpack the uploaded source.", err)
	}

	// Hashed while it is read rather than in a second pass: the digest is of
	// the bytes that were unpacked, which a second read of a file the next
	// upload may replace could not promise.
	sum := sha256.New()
	if err := extract(io.TeeReader(f, sum), dir); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	// The rest of the file, if the archive ended before it did: a digest of
	// part of an archive names nothing.
	if _, err := io.Copy(sum, f); err != nil {
		_ = os.RemoveAll(dir)
		return nil, errs.Wrap(errs.Internal, "Pando could not read the uploaded source.", err)
	}
	// No commit: an upload has no revision. The deploy records the archive it
	// came from instead, which is the honest answer to "what was deployed",
	// and the archive's digest is what a scan of it is known by.
	//
	// With the same cleanup a clone has. Without it every detection and every
	// deploy of an uploaded app left a full copy of its source in the
	// temporary directory for as long as the server ran (issue #55).
	return &Checkout{
		Dir: dir, Commit: "", Digest: "sha256:" + hex.EncodeToString(sum.Sum(nil)),
		cleanup: func() { _ = os.RemoveAll(dir) },
	}, nil
}

// extract unpacks a gzipped tar, refusing anything that escapes the directory.
//
// Path traversal in a tar is the oldest trick there is, and this archive comes
// from whatever a user or an agent chose to send. The check is on the resolved
// path rather than the name, because ../ is not the only way to leave a
// directory — a symlink pointing out of it and a later entry written through
// that symlink is the other, which is why symlinks are dropped entirely.
func extract(r io.Reader, dir string) error {
	return extractWithin(r, dir, uploadLimits)
}

// unpackLimits bound what an archive may unpack to.
type unpackLimits struct {
	file, total int64
	entries     int
}

var uploadLimits = unpackLimits{file: maxUploadFileBytes, total: maxUnpackedBytes, entries: maxUploadEntries}

func extractWithin(r io.Reader, dir string, limits unpackLimits) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return errs.Wrap(errs.ValidInvalid, "That upload is not a gzipped tar archive.", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	var unpacked int64
	for entries := 1; ; entries++ {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return errs.Wrap(errs.ValidInvalid, "That upload could not be read.", err)
		}
		if entries > limits.entries {
			return errs.Newf(errs.ValidInvalid,
				"That upload holds more than %d files and directories, which is more than Pando unpacks.", limits.entries).
				WithRemedy(uploadTooBigRemedy)
		}

		target := filepath.Join(dir, filepath.Clean("/"+header.Name))
		if !strings.HasPrefix(target, filepath.Clean(dir)+string(os.PathSeparator)) && target != dir {
			return errs.Newf(errs.ValidInvalid,
				"That upload contains a path that would write outside the app's directory: %s", header.Name)
		}

		// A sparse entry is a few bytes in the archive standing for a file of
		// any size, mostly zeros. No source tree needs one, and pando deploy
		// never writes one.
		if isSparse(header) {
			return errs.Newf(errs.ValidInvalid,
				"That upload contains %s as a sparse file, which Pando does not unpack.", header.Name).
				WithRemedy("Upload the directory with pando deploy, which archives every file whole.")
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return errs.Wrap(errs.Internal, "Pando could not unpack the upload.", err)
			}

		case tar.TypeReg:
			n, err := extractFile(tr, header, target, limits, limits.total-unpacked)
			if err != nil {
				return err
			}
			unpacked += n

		default:
			// Symlinks, devices, fifos: skipped, not an error. A source tree
			// with a symlink in it is normal and should still deploy; a symlink
			// that Pando followed while unpacking is how an archive writes
			// outside its directory.
		}
	}
}

// Limits on what an upload may unpack to (R-410): far above a large source tree
// (the deploy QA's largest upload is under 1 MB in 23 files; Pando's own
// tree, without .git and node_modules as pando deploy sends it, is 18 MB in
// about 2,100 files), and low enough that an archive compressed to almost
// nothing cannot fill the disk or keep the unpacking busy. Each is refused
// when reached, never truncated: a source tree with part of a file missing
// builds into something nobody wrote.
const (
	maxUploadFileBytes = 1 << 30 // 1 GiB per file
	maxUnpackedBytes   = 4 << 30 // 4 GiB in all
	maxUploadEntries   = 200_000
)

const uploadTooBigRemedy = "Check for build output, dependencies or a .git directory being included, or deploy from a repository instead."

// extractFile writes one regular file of an upload, refusing it when it is
// larger than one file may be or than what is left of the whole upload's
// allowance. It returns how many bytes it wrote.
func extractFile(tr io.Reader, header *tar.Header, target string, limits unpackLimits, left int64) (int64, error) {
	limit := min(limits.file, left)
	tooBig := func() error {
		if limit < limits.file {
			return errs.Newf(errs.ValidInvalid,
				"That upload unpacks to more than %s, which is more than Pando unpacks.", sizeWords(limits.total)).
				WithRemedy(uploadTooBigRemedy)
		}
		return errs.Newf(errs.ValidInvalid,
			"That upload contains %s, which is larger than %s, the most Pando unpacks for one file.",
			header.Name, sizeWords(limits.file)).
			WithRemedy(uploadTooBigRemedy)
	}
	if header.Size > limit {
		return 0, tooBig()
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return 0, errs.Wrap(errs.Internal, "Pando could not unpack the upload.", err)
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fileMode(header.Mode))
	if err != nil {
		return 0, errs.Wrap(errs.Internal, "Pando could not unpack the upload.", err)
	}
	// Read one byte past the limit, so a file over it is refused rather than
	// cut short: the header's size is the archive's word, not a promise.
	n, err := io.Copy(out, io.LimitReader(tr, limit+1))
	if err != nil {
		_ = out.Close()
		return n, errs.Wrap(errs.Internal, "Pando could not unpack the upload.", err)
	}
	if err := out.Close(); err != nil {
		return n, errs.Wrap(errs.Internal, "Pando could not unpack the upload.", err)
	}
	if n > limit {
		return n, tooBig()
	}
	return n, nil
}

// sizeWords says a limit in the largest whole unit that fits it.
func sizeWords(n int64) string {
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return fmt.Sprintf("%d GB", n>>30)
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MB", n>>20)
	}
	return fmt.Sprintf("%d bytes", n)
}

// isSparse reports whether an entry is a sparse file, in the old GNU format or
// the PAX one.
func isSparse(header *tar.Header) bool {
	if header.Typeflag == tar.TypeGNUSparse {
		return true
	}
	for key := range header.PAXRecords {
		if strings.HasPrefix(key, "GNU.sparse.") {
			return true
		}
	}
	return false
}

// fileMode takes the archive's permissions, within limits.
//
// Honoring the mode matters more than it looks: extracting everything 0600
// produces a source tree only root can read, and a build that then runs as a
// different user — nginx serving static files, say — answers 403 for every file
// in the app. That failure appears at runtime, in the app, looking like the
// app's fault.
//
// Only the permission bits, so setuid and setgid cannot arrive in an upload.
// An executable bit is kept, because a repository with a build script in it
// needs one.
func fileMode(mode int64) os.FileMode {
	// G115: Perm masks to the low nine bits after the conversion, so a mode
	// that overflows uint32 cannot produce a permission this function did not
	// intend. The mask is also what drops setuid and setgid.
	perm := os.FileMode(mode).Perm() //nolint:gosec
	if perm == 0 {
		return 0o644
	}
	// Always readable and writable by the owner: Pando has to be able to read
	// back what it just wrote, whatever the archive claimed.
	return perm | 0o600
}
