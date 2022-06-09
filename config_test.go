package bdls

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestVerifyConfig(t *testing.T) {
	config := new(Config)

	err := VerifyConfig(config)
	assert.Equal(t, ErrConfigEpoch, err)

	config.Epoch = time.Now()
	err = VerifyConfig(config)
	assert.Equal(t, ErrConfigStateCompare, err)

	config.StateCompare = func(State, State) int { return 0 }
	err = VerifyConfig(config)
	assert.Equal(t, ErrConfigStateValidate, err)

	config.StateValidate = func(State) bool { return true }
	err = VerifyConfig(config)
	assert.Equal(t, ErrConfigPrivateKey, err)

	randKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)

	config.PrivateKey = randKey
	err = VerifyConfig(config)
	assert.Equal(t, ErrConfigParticipants, err)

	for i := 0; i < ConfigMinimumParticipants; i++ {
		randKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
		assert.Nil(t, err)
		config.Participants = append(config.Participants, DefaultPubKeyToIdentity(&randKey.PublicKey))
	}

	err = VerifyConfig(config)
	assert.Nil(t, err)
}
