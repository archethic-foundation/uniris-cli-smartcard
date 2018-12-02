package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

/*
Scenario: Generate AES key
	Given a secret
	When I want to generate a AES key
	Then I get this key
*/
func TestGenerateAESKey(t *testing.T) {
	k := NewKeyGenerator()

	secret := "my key"

	aesKey, err := k.NewAESKey(secret)
	assert.Nil(t, err)
	assert.NotEmpty(t, aesKey)
}

/*
Scenario: Generate a ECDSA key pair with a secret
	Given a secret
	When I want to generate a ECDSA key pair
	Then I get this keypair
*/
func TestGenerateKeyPair(t *testing.T) {
	k := NewKeyGenerator()

	secret := "6IX0GDDFGK75AEWN9MUE516QHVXN23WJZ6DDJ181HVPF67N1RJ9Z54V2ADR243FBMNRYBIQKWZRQCM1NV0UC1URJNBX4GINEBR2V6SZEVDMQLM209SCPXSUA9QNK3J41JKTI96FW4P19UMBHDBTFZDY9OFH1LYJWJJMMC6WLNUT8CWMDZIUVYSZZNN9JS73CEHRZZ95NY2EYPP3SB045VGF4EU47ZANH0G06P433JEPUI84MXOHXIBCRYLMPAML1"
	kp, err := k.NewKeyPair(secret)
	assert.Nil(t, err)
	assert.NotEmpty(t, kp.PrivateKey)
	assert.NotEmpty(t, kp.PublicKey)

	kp2, err := k.NewKeyPair(secret)
	assert.Nil(t, err)
	assert.NotEmpty(t, kp2.PrivateKey)
	assert.NotEmpty(t, kp2.PublicKey)

	assert.Equal(t, kp.PrivateKey, kp2.PrivateKey)
}

/*
Scenario: Generate two ECDSA key pair with different secret
	Given two different secret
	When I want to generate a ECDSA key pairs
	Then I get 2 different keypair
*/
func TestGenerateKeyPairNotSame(t *testing.T) {
	k := NewKeyGenerator()

	kp, err := k.NewKeyPair("hello")
	assert.Nil(t, err)
	assert.NotEmpty(t, kp.PrivateKey)
	assert.NotEmpty(t, kp.PublicKey)

	kp2, err := k.NewKeyPair("test")
	assert.Nil(t, err)
	assert.NotEmpty(t, kp2.PrivateKey)
	assert.NotEmpty(t, kp2.PublicKey)

	assert.NotEqual(t, kp.PrivateKey, kp2.PrivateKey)
}

/*
Scenario: Generate a ECDSA key pair without a secret
	Given no secret
	When I want to generate a ECDSA key pair
	Then I get this keypair
*/
func TestGenerateKeyPairWithoutSecret(t *testing.T) {
	k := NewKeyGenerator()

	kp, err := k.NewKeyPair("")
	assert.Nil(t, err)
	assert.NotEmpty(t, kp.PrivateKey)
	assert.NotEmpty(t, kp.PublicKey)

	kp2, err := k.NewKeyPair("")
	assert.Nil(t, err)
	assert.NotEmpty(t, kp2.PrivateKey)
	assert.NotEmpty(t, kp2.PublicKey)

	assert.NotEqual(t, kp.PrivateKey, kp2.PrivateKey)
}
