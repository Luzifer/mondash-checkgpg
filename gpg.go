package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"

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

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "execute http request")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("key not found")
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

func processKey(ctx context.Context, key string) (string, mondash.Status) {
	logger := log.WithField("key", key)

	e, err := getKeyFromKeyserver(ctx, key)
	if err != nil {
		return "Key retrieval failed", mondash.StatusUnknown
	}

	if l := len(e.Revocations); l > 0 {
		return fmt.Sprintf("Key has %d revocation signature(s)", l), mondash.StatusCritical
	}

	var expiry *time.Time
	for n, id := range e.Identities {
		logger.Debugf("%s %#v", n, id)

		if id.SelfSignature.KeyLifetimeSecs != nil {
			idSelfSigExpiry := e.PrimaryKey.CreationTime.Add(time.Duration(*id.SelfSignature.KeyLifetimeSecs) * time.Second)
			logger.WithField("id", n).Debugf("Selfsig: Identity expires: %s", idSelfSigExpiry)

			if s := checkExpiry(idSelfSigExpiry); s != mondash.StatusOK {
				return fmt.Sprintf("Identity self-signature for %q has key-expiry in %dh", n, time.Until(idSelfSigExpiry)/time.Hour), s
			}

			if expiry == nil || expiry.After(idSelfSigExpiry) {
				expiry = &idSelfSigExpiry
			}
		}

		for _, sig := range id.Signatures {
			if sig.KeyLifetimeSecs == nil {
				continue
			}

			idSigExpiry := e.PrimaryKey.CreationTime.Add(time.Duration(*sig.KeyLifetimeSecs) * time.Second)
			logger.WithField("id", n).Debugf("Sig: Identity expires: %s", idSigExpiry)

			if s := checkExpiry(idSigExpiry); s != mondash.StatusOK {
				return fmt.Sprintf("Identity signature for %q has key-expiry in %dh", n, time.Until(idSigExpiry)/time.Hour), s
			}

			if expiry == nil || expiry.After(idSigExpiry) {
				expiry = &idSigExpiry
			}
		}
	}

	for _, sk := range e.Subkeys {
		if sk.Sig.KeyLifetimeSecs == nil {
			continue
		}

		skExp := sk.PublicKey.CreationTime.Add(time.Duration(*sk.Sig.KeyLifetimeSecs) * time.Second)
		logger.Debugf("Subkey signature expires: %s", skExp)

		if s := checkExpiry(skExp); s != mondash.StatusOK {
			return fmt.Sprintf("Subkey signature has key-expiry in %dh", time.Until(skExp)/time.Hour), s
		}

		if expiry == nil || expiry.After(skExp) {
			expiry = &skExp
		}
	}

	if expiry != nil {
		return fmt.Sprintf("Key looks good (expires in %dh)", time.Until(*expiry)/time.Hour), mondash.StatusOK
	}

	return "Key looks good (does not expire)", mondash.StatusOK
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
