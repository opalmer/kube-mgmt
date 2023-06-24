package opa

import (
	"encoding/json"

	"github.com/sirupsen/logrus"
)

type Bundle struct {
	Path string
}

func (b *Bundle) DeletePolicy(id string) error {
	logrus.Warnf("Not deleting %s, not supported during bootstrapping", id)
	return nil
}

func (b *Bundle) Prefix(path string) Data {
	panic("prefix should not have been called during bootstrapping (we should have returned)")
}

func (b *Bundle) PatchData(path string, op string, value *interface{}) error {
	logrus.Warnf("Not patching %s with %s, not supported during bootstrapping", path, op)

	return nil
}

func (b *Bundle) PutData(path string, value interface{}) error {
	logrus.Infof("Boostrapping PutData(%s(", path)
	return nil
}

func (b *Bundle) PostData(path string, value interface{}) (json.RawMessage, error) {
	logrus.Infof("Boostrapping PostData(%s)", path)
	return nil, nil
}

func (b *Bundle) InsertPolicy(id string, bs []byte) error {
	logrus.Infof("Inserting policy %s ", id)
	return nil
}
