package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	mondash "github.com/Luzifer/mondash/client"
	"github.com/Luzifer/rconfig/v2"
)

var (
	cfg = struct {
		CritAt                 time.Duration `flag:"crit-at,c" default:"168h" description:"Switch state to critical if key expires within X"`
		Keys                   []string      `flag:"key,k" description:"List of keys to check"`
		KeyServer              string        `flag:"key-server" default:"http://keyserver.ubuntu.com/pks/lookup" description:"Lookup path to retrieve the key from"`
		LogLevel               string        `flag:"log-level" default:"info" description:"Log level (debug, info, warn, error, fatal)"`
		MondashBoard           string        `flag:"mondash-board" default:"" description:"ID of the Mondash board to send to" validate:"nonzero"`
		MondashMetric          string        `flag:"mondash-metric" default:"checkgpg" description:"ID of the metric to submit to"`
		MondashMetricExpiry    time.Duration `flag:"mondash-metric-expiry" default:"168h" description:"Time in seconds when to remove the metric if there is no update"`
		MondashMetricFreshness time.Duration `flag:"mondash-metric-freshness" default:"168h" description:"Time in seconds when to switch to stale state of there is no update"`
		MondashToken           string        `flag:"mondash-token" default:"" description:"Token with write access to the board" validate:"nonzero"`
		VersionAndExit         bool          `flag:"version" default:"false" description:"Prints current version and exits"`
		WarnAt                 time.Duration `flag:"warn-at,w" default:"336h" description:"Switch state to warning if key expires within X"`
	}{}

	version = "dev"
)

func init() {
	rconfig.AutoEnv(true)
	if err := rconfig.ParseAndValidate(&cfg); err != nil {
		log.Fatalf("Unable to parse commandline options: %s", err)
	}

	if cfg.VersionAndExit {
		fmt.Printf("mondash-checkgpg %s\n", version)
		os.Exit(0)
	}

	if l, err := log.ParseLevel(cfg.LogLevel); err != nil {
		log.WithError(err).Fatal("Unable to parse log level")
	} else {
		log.SetLevel(l)
	}
}

func main() {
	var (
		overallStatus  = mondash.StatusUnknown
		statusMessages []string
	)

	for _, key := range cfg.Keys {
		msg, state := processKey(context.Background(), key)
		overallStatus = calcStatus(overallStatus, state)
		statusMessages = append(statusMessages, fmt.Sprintf("0x%s: %s",
			key[len(key)-8:],
			msg,
		))
	}

	if err := mondash.New(cfg.MondashBoard, cfg.MondashToken).
		PostMetric(&mondash.PostMetricInput{
			MetricID:    cfg.MondashMetric,
			Title:       "GPG Key Status",
			Description: strings.Join(statusMessages, "\n"),
			Status:      overallStatus,
			Expires:     int64(cfg.MondashMetricExpiry / time.Second),
			Freshness:   int64(cfg.MondashMetricFreshness / time.Second),
			IgnoreMAD:   true,
			HideMAD:     true,
			HideValue:   true,
		}); err != nil {
		log.WithError(err).Fatal("Unable to submit metric")
	}
}

func calcStatus(o, n mondash.Status) mondash.Status {
	scores := map[mondash.Status]int{
		mondash.StatusUnknown:  0,
		mondash.StatusOK:       1,
		mondash.StatusWarning:  2, //nolint: gomnd // Makes no sense to extract to a constant
		mondash.StatusCritical: 3, //nolint: gomnd // Makes no sense to extract to a constant
	}

	switch {
	case o == n:
		return o
	case scores[o] < scores[n]:
		return n
	default:
		return o
	}
}
