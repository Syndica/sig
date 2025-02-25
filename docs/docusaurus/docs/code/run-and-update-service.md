Install sig as a long running service on a linux system, and periodically have it self-update based on the latest code in the configured branch and restart. This exists to maintain CI test environments.

## Install

```bash
git clone https://github.com/Syndica/sig.git
cd sig/ci/run-and-update-service

sudo make install      # install update script and systemd units to the system
sudo vim /etc/sig.conf # optionally edit file to specify custom configuration
sudo make start        # start sig, metrics, and the timer to periodically update sig
```

## Uninstall

```bash
sudo make uninstall
```

## Configuration

These options may be configured in /etc/sig.conf

- `CLI_ARGS`: The command line options that will be passed to sig. Default: '--log-file /home/sig/sig/logs/sig.log'
- `BRANCH`: The branch that will be checked periodically and rebuilt when it changes. Default: 'main'
- `SLACK_WEBHOOK_URL` (optional): Enable slack web hooks. Only used if non-empty. Default: ''

## Design

The service is installed to the system in `/usr/local` using make. A new user called `sig` is added to the system and is used to build and run the sig binary.

The service is orchestrated using systemd with two services and one timer. `sig-update.timer` periodically runs the `sig-update` binary as root. This script de-escalates to the sig user to check if there are new commits on `BRANCH`, and if so, it builds a new sig binary. Then as root, it restarts `sig.service` and starts sig's metrics with docker-compose. As the sig user, `sig.service` runs the sig binary that was built in the sig user's home folder, passing the configured `CLI_ARGS`.
