package opa

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
	"path/filepath"
)

var ErrBootstrapBundleNotSupported = errors.New("unsupported operation during bootstrapping")

// BootstrapBundle implements the Client interface and produces an archive known as a management bundle:
//
//	https://www.openpolicyagent.org/docs/latest/management-bundles/
//	https://www.openpolicyagent.org/docs/latest/management-bundles/#bundle-file-format
//
// When OPA boots, it will load up this bundle containing the policies to apply.
type BootstrapBundle struct {
	file *os.File
	tar  *tar.Writer
	gzip *gzip.Writer
}

func (b *BootstrapBundle) DeletePolicy(id string) error {
	logrus.Errorf("Not deleting %s, not supported during bootstrapping", id)
	return fmt.Errorf("%w: DeletePolicy", ErrBootstrapBundleNotSupported)
}

func (b *BootstrapBundle) Prefix(string) Data {
	panic("prefix should not have been called during bootstrapping (we should have returned)")
}

func (b *BootstrapBundle) PatchData(path string, op string, value *interface{}) error {
	logrus.Errorf("Not patching %s with %s, not supported during bootstrapping", path, op)
	return fmt.Errorf("%w: PatchData", ErrBootstrapBundleNotSupported)
}

func (b *BootstrapBundle) PutData(path string, value interface{}) error {
	logrus.Debugf("BootstrapBundle.PutData(%v, %v)", path, value)
	return nil
}

func (b *BootstrapBundle) PostData(path string, value interface{}) (json.RawMessage, error) {
	logrus.Debugf("BootstrapBundle.PostData(%v, %v)", path, value)
	return nil, nil
}

func (b *BootstrapBundle) InsertPolicy(id string, bs []byte) error {
	logrus.Debugf("BootstrapBundle.InsertPolicy(%v, %v)", id, string(bs))

	header := &tar.Header{
		Name: id,
		Size: int64(len(bs)),
		Mode: 0600,
	}

	if err := b.tar.WriteHeader(header); err != nil {
		logrus.WithError(err).Errorf("Failed to write tar header")
		return err
	}

	if _, err := b.tar.Write(bs); err != nil {
		logrus.WithError(err).Errorf("Failed to write data to tar archive")
		return err
	}

	return nil
}

func (b *BootstrapBundle) Close() error {
	logrus.Debugf("Closing %s", b.file.Name())

	if err := b.tar.Close(); err != nil {
		logrus.WithError(err).Error("Failed to close tar archive")
		return err
	}

	if err := b.gzip.Close(); err != nil {
		logrus.WithError(err).Error("Failed to close gzip archive")
		return err
	}

	if err := b.file.Close(); err != nil {
		logrus.WithError(err).Error("Failed to close file")
		return err
	}

	logrus.Debugf("Closed %s", b.file.Name())
	return nil
}

func NewBootstrapBundle(path string) (*BootstrapBundle, error) {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		logrus.WithError(err).Errorf("Failed to create parent directory %s", parent)
		return nil, err
	}

	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	zipped := gzip.NewWriter(file)

	return &BootstrapBundle{
		file: file,
		gzip: zipped,
		tar:  tar.NewWriter(zipped),
	}, nil
}
