package ship

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"pi-fortress/internal/backup"
)

// policyRel is where the lists of the operator are in a tree. PI_SEED of
// the Makefile is PI_OWNED under vm/policy/. A bundle carries those
// paths from the live tree into the new one.
const policyRel = "vm/policy"

// mirrorLists makes the operator-owned lists (backup.PiOwned) in prev
// the same as in the live tree, before prev is exchanged back in. A
// list that the live tree has is copied over the list of prev. A list
// that it does not have is removed from prev. A rollback then keeps the
// lists the same way as an upgrade.
func mirrorLists(live, prev string) error {
	if st, err := os.Lstat(live); err != nil {
		return err
	} else if !st.IsDir() {
		return fmt.Errorf("%s is not a directory", live)
	}
	for _, name := range backup.PiOwned() {
		rel := policyRel + "/" + name
		if err := mirrorList(live, prev, rel); err != nil {
			return fmt.Errorf("keep %s across the rollback: %w", rel, err)
		}
	}
	return nil
}

func mirrorList(live, prev, rel string) error {
	lr, err := os.OpenRoot(live)
	if err != nil {
		return err
	}
	defer lr.Close()
	src, st, err := openListIn(lr, live, rel)
	if err != nil {
		return err
	}
	if src != nil {
		defer src.Close()
	}
	pr, err := os.OpenRoot(prev)
	if err != nil {
		return err
	}
	defer pr.Close()
	dir, name := path.Split(rel)
	dir = strings.TrimSuffix(dir, "/")
	if src == nil {
		return removeListIn(pr, prev, dir, name)
	}
	d, err := restoreDirs(pr, prev, dir, 0755)
	if err != nil {
		return err
	}
	if d != pr {
		defer d.Close()
	}
	return mirrorFile(d, src, st, filepath.Join(prev, filepath.FromSlash(dir)), name)
}

// openListIn opens rel under r for reading. It follows no symlink at
// any point on the path, and reaches each directory from the one above
// it (walkDirs). A nil file means that the list is not there. base only
// names paths in errors.
func openListIn(r *os.Root, base, rel string) (*os.File, fs.FileInfo, error) {
	dir, name := path.Split(rel)
	d, err := walkDirs(r, base, strings.TrimSuffix(dir, "/"), false, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if d != r {
		defer d.Close()
	}
	p := filepath.Join(base, filepath.FromSlash(rel))
	lst, err := d.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if lst.Mode()&fs.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%s is a symlink", p)
	}
	if !lst.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is not a regular file", p)
	}
	f, err := d.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err == nil && !os.SameFile(lst, st) {
		err = fmt.Errorf("%s changed while it was being read", p)
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, st, nil
}

// removeListIn removes dir/name under r. It refuses a symlinked directory
// on the path to it. A link at name itself is removed, not followed.
func removeListIn(r *os.Root, base, dir, name string) error {
	d, err := walkDirs(r, base, dir, false, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if d != r {
		defer d.Close()
	}
	st, err := d.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("%s is a directory", filepath.Join(base, filepath.FromSlash(dir), name))
	}
	if err := d.Remove(name); err != nil {
		return err
	}
	return syncRoot(d)
}

// mirrorFile stages src beside name in d with the mode of src, and its
// owner the same way that carry keeps one. Then it renames the stage
// over the target (stageOver). dir only names paths in errors.
func mirrorFile(d *os.Root, src *os.File, st fs.FileInfo, dir, name string) error {
	return stageOver(d, dir, name, ".pf-mirror-", func(fs.FileInfo) (os.FileMode, int, int) {
		uid, gid := fileOwner(st)
		if uid >= 1000 {
			uid, gid = 0, 0
		}
		return st.Mode().Perm(), uid, gid
	}, func(f *os.File) error {
		_, err := io.Copy(f, src)
		return err
	})
}
