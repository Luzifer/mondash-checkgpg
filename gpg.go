package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	mondash "github.com/Luzifer/mondash/client"
)

func getKeyFromKeyserver(ctx context.Context, keyID string) (*openpgp.Entity, error) {
	uri, err := url.Parse(cfg.KeyServer)
	if err != nil {
		return nil, errors.Wrap(err, "parse keyserver lookup url")
	}

	params := url.Values{
		"op":     []string{"get"},
		"search": []string{keyID},
	}

	uri.RawQuery = params.Encode()

	return getKeyFromURL(ctx, uri.String())
}

func getKeyFromURL(ctx context.Context, keyURL string) (*openpgp.Entity, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, keyURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "execute http request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("http status %d", resp.StatusCode)
	}

	block, err := armor.Decode(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "parse armored key")
	}

	ent, err := openpgp.ReadEntity(packet.NewReader(block.Body))
	if err != nil {
		return nil, errors.Wrap(err, "parse entity")
	}

	return ent, nil
}

func processKey(ctx context.Context, key string) (keyID, message string, status mondash.Status) {
	var (
		e      *openpgp.Entity
		err    error
		logger = log.WithField("key", key)
	)

	switch {
	case strings.HasPrefix(key, "0x"):
		if e, err = getKeyFromKeyserver(ctx, key); err != nil {
			return "", "Key retrieval failed", mondash.StatusUnknown
		}

	case strings.HasPrefix(key, "http"):
		if e, err = getKeyFromURL(ctx, key); err != nil {
			return "", "Key retrieval failed: " + err.Error(), mondash.StatusUnknown
		}

	default:
		return "", "Unexpected key source", mondash.StatusUnknown
	}

	keyID = fmt.Sprintf("0x%016X", e.PrimaryKey.KeyId)

	if l := len(e.Revocations); l > 0 {
		return keyID, fmt.Sprintf("Key has %d revocation signature(s)", l), mondash.StatusCritical
	}

	var expiry *time.Time
	for n, id := range e.Identities {
		logger.Debugf("%s %#v", n, id)

		var idSelfSigExpiry *time.Time
		for _, sig := range id.Signatures {
			if sig.KeyLifetimeSecs == nil || sig.IssuerKeyId != &e.PrimaryKey.KeyId {
				continue
			}

			idSigExpiry := e.PrimaryKey.CreationTime.Add(time.Duration(*sig.KeyLifetimeSecs) * time.Second)
			logger.WithField("id", n).Debugf("Sig: Identity expires: %s", idSigExpiry)

			if idSelfSigExpiry == nil || idSigExpiry.After(*idSelfSigExpiry) {
				idSelfSigExpiry = &idSigExpiry
			}
		}

		if idSelfSigExpiry == nil {
			continue
		}

		if s := checkExpiry(*idSelfSigExpiry); s != mondash.StatusOK {
			return keyID, fmt.Sprintf("Identity signature for %q has key-expiry in %dh", n, time.Until(*idSelfSigExpiry)/time.Hour), s
		}

		if expiry == nil || expiry.After(*idSelfSigExpiry) {
			expiry = idSelfSigExpiry
		}
	}

	for _, sk := range e.Subkeys {
		if sk.Sig.KeyLifetimeSecs == nil {
			// No lifetime assigned to that signature: Ignore that key
			continue
		}

		if sk.Revoked(time.Now()) {
			// Subkey has been revoked, we don't check that one
			continue
		}

		skExp := sk.PublicKey.CreationTime.Add(time.Duration(*sk.Sig.KeyLifetimeSecs) * time.Second)
		logger.Debugf("Subkey signature expires: %s", skExp)

		if s := checkExpiry(skExp); s != mondash.StatusOK {
			return keyID, fmt.Sprintf("Subkey signature has key-expiry in %dh", time.Until(skExp)/time.Hour), s
		}

		if expiry == nil || expiry.After(skExp) {
			expiry = &skExp
		}
	}

	if expiry != nil {
		return keyID, fmt.Sprintf("Key looks good (expires in %dh)", time.Until(*expiry)/time.Hour), mondash.StatusOK
	}

	return keyID, "Key looks good (does not expire)", mondash.StatusOK
}

func checkExpiry(ex time.Time) mondash.Status {
	switch {
	case time.Until(ex) < cfg.CritAt:
		return mondash.StatusCritical
	case time.Until(ex) < cfg.WarnAt:
		return mondash.StatusWarning
	default:
		return mondash.StatusOK
	}
}
