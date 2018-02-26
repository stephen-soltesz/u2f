// Go FIDO U2F Library
// Copyright 2015 The Go FIDO U2F Library Authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package u2f

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"time"

	"github.com/kr/pretty"
)

// SignRequest creates a request to initiate an authentication.
func (c *Challenge) SignRequest(regs []Registration) *WebSignRequest {
	var sr WebSignRequest
	sr.AppID = c.AppID
	sr.Challenge = encodeBase64(c.Challenge)
	for _, r := range regs {
		rk := getRegisteredKey(c.AppID, r)
		sr.RegisteredKeys = append(sr.RegisteredKeys, rk)
	}
	return &sr
}

// ErrCounterTooLow is raised when the counter value received from the device is
// lower than last stored counter value. This may indicate that the device has
// been cloned (or is malfunctioning). The application may choose to disable
// the particular device as precaution.
var ErrCounterTooLow = errors.New("u2f: counter too low")

// Authenticate validates a SignResponse authentication response.
// An error is returned if any part of the response fails to validate.
// The counter should be the counter associated with appropriate device
// (i.e. resp.KeyHandle).
// The latest counter value is returned, which the caller should store.
func (reg *Registration) Authenticate(resp SignResponse, c Challenge, counter uint32) (newCounter uint32, err error) {
	if time.Now().Sub(c.Timestamp) > timeout {
		return 0, errors.New("u2f: challenge has expired")
	}
	if resp.KeyHandle != encodeBase64(reg.KeyHandle) {
		return 0, errors.New("u2f: wrong key handle")
	}

	sigData, err := decodeBase64(resp.SignatureData)
	if err != nil {
		return 0, err
	}

	clientData, err := decodeBase64(resp.ClientData)
	if err != nil {
		return 0, err
	}

	ar, err := parseSignResponse(sigData)
	if err != nil {
		return 0, err
	}

	if ar.Counter < counter {
		return 0, ErrCounterTooLow
	}

	_, err = verifyClientData(clientData, c)
	if err != nil {
		return 0, err
	}

	pretty.Println("Authenticate:")
	if err := verifyAuthSignature(*ar, &reg.PubKey, c.AppID, clientData); err != nil {
		return 0, err
	}
	pretty.Println("u2f Signature    :", hex.EncodeToString(sigData))
	pretty.Println()

	if !ar.UserPresenceVerified {
		return 0, errors.New("u2f: user was not present")
	}

	return ar.Counter, nil
}

type ecdsaSig struct {
	R, S *big.Int
}

type authResp struct {
	UserPresenceVerified bool
	Counter              uint32
	sig                  ecdsaSig
	raw                  []byte
}

func parseSignResponse(sd []byte) (*authResp, error) {
	if len(sd) < 5 {
		return nil, errors.New("u2f: data is too short")
	}

	var ar authResp

	userPresence := sd[0]
	if userPresence|1 != 1 {
		return nil, errors.New("u2f: invalid user presence byte")
	}
	ar.UserPresenceVerified = userPresence == 1

	ar.Counter = uint32(sd[1])<<24 | uint32(sd[2])<<16 | uint32(sd[3])<<8 | uint32(sd[4])

	ar.raw = sd[:5]

	rest, err := asn1.Unmarshal(sd[5:], &ar.sig)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("u2f: trailing data")
	}

	return &ar, nil
}

func verifyAuthSignature(ar authResp, pubKey *ecdsa.PublicKey, appID string, clientData []byte) error {
	// sha256 checksum of orginal app Id,
	appSum := sha256.Sum256([]byte(appID))
	// and client data (constructed by the js api from the original WebSignRequest challenge).
	cdSum := sha256.Sum256(clientData)

	// Reconstruct the data that was signed by the u2f device:
	// https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-raw-message-formats-v1.1-id-20160915.html#authentication-response-message-success
	var buf []byte
	// appid checksum.
	buf = append(buf, appSum[:]...)
	// user presence byte and 4 byte counter.
	buf = append(buf, ar.raw...)
	// client data checksum.
	buf = append(buf, cdSum[:]...)
	hash := sha256.Sum256(buf)

	pk := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	pretty.Println("appId string     :", appID)
	pretty.Println("ClientData string:", string(clientData))
	pretty.Println("appId SHA256     :", hex.EncodeToString(appSum[:]))
	pretty.Println("User presence    :", "01")
	pretty.Println("Counter          :", hex.EncodeToString(ar.raw[1:]))
	pretty.Println("ClientData SHA256:", hex.EncodeToString(cdSum[:]))
	pretty.Println("Public key       :", hex.EncodeToString(pk))

	if !ecdsa.Verify(pubKey, hash[:], ar.sig.R, ar.sig.S) {
		return errors.New("u2f: invalid signature")
	}

	return nil
}
