[![Go Report Card](https://goreportcard.com/badge/github.com/Luzifer/mondash-checkgpg)](https://goreportcard.com/report/github.com/Luzifer/mondash-checkgpg)
![](https://badges.fyi/github/license/Luzifer/mondash-checkgpg)
![](https://badges.fyi/github/downloads/Luzifer/mondash-checkgpg)
![](https://badges.fyi/github/latest-release/Luzifer/mondash-checkgpg)
![](https://knut.in/project-status/mondash-checkgpg)

# Luzifer / mondash-checkgpg

`mondash-checkgpg` is intended to watch over GPG keys uploaded to a keyserver and inform about their expiry using a [MonDash](https://mondash.org/) dashboard.

## Usage

```console
# ./mondash-checkgpg --help
Usage of ./mondash-checkgpg:
  -c, --crit-at duration                    Switch state to critical if key expires within X (default 168h0m0s)
  -k, --key strings                         List of keys to check
      --key-server string                   Lookup path to retrieve the key from (default "http://keyserver.ubuntu.com/pks/lookup")
      --log-level string                    Log level (debug, info, warn, error, fatal) (default "info")
      --mondash-board string                ID of the Mondash board to send to
      --mondash-metric string               ID of the metric to submit to (default "checkgpg")
      --mondash-metric-expiry duration      Time in seconds when to remove the metric if there is no update (default 168h0m0s)
      --mondash-metric-freshness duration   Time in seconds when to switch to stale state of there is no update (default 168h0m0s)
      --mondash-token string                Token with write access to the board
      --version                             Prints current version and exits
  -w, --warn-at duration                    Switch state to warning if key expires within X (default 336h0m0s)

# ./mondash-checkgpg --mondash-board <boardid> --mondash-token <token> --key 0x43A4CD1C19DAE8558D40088E0066F03ED215AD7D
```
