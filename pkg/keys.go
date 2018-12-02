package uniris

import (
	"math/rand"
	"sort"
)

//SharedKeys represents the shared keys listing
type SharedKeys struct {
	Emitter []KeyPair `yaml:"emKeys"`
	Robot   string    `yaml:"robotPub"`
}

//KeyPair represents a keypair
type KeyPair struct {
	PrivateKey string `yaml:"priv"`
	PublicKey  string `yaml:"pub"`
}

//SortEmitterKeys sorts the emitter shared keys by their public key
func (sh *SharedKeys) SortEmitterKeys() {
	sort.Slice(sh.Emitter, func(i, j int) bool {
		return sh.Emitter[i].PublicKey < sh.Emitter[j].PublicKey
	})
}

//RandomEmitterKey gets a random shared emitter key
func (sh SharedKeys) RandomEmitterKey() KeyPair {
	randIdx := rand.Intn(len(sh.Emitter))
	return sh.Emitter[randIdx]
}

//RequestEmitterKey gets the shared emitter keys to sign/verify request
func (sh SharedKeys) RequestEmitterKey() KeyPair {
	return sh.Emitter[0]
}
