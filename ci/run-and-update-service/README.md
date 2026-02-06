Install sig as a long running service on a linux system, and periodically have it self-update based on the latest code in the configured branch and restart. This exists to maintain CI test environments.

## Install

Dependencies:
- docker
- docker-compose
- zig 0.14.1
- zstd
- aws-cli

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
- `S3_BUCKET`: Bucket to upload validator state for debugging crashes.

## Design

The service is installed to the system in `/usr/local` using make. A new user called `sig` is added to the system and is used to build and run the sig binary.

The service is orchestrated by systemd, using two services and one timer.

> *Note:* **Systemd** is the most common init system for linux. It can run processes, daemons, and schedules. A *service* is a short- or long-running process that's run by systemd, and a *timer* is used to start services on a schedule, similar to a cron job.

Call graph: `sig-update.timer` -> `sig-update.service` -> `sig-update` -> `sig.service` -> `sig`

`sig-update.timer` periodically runs the `sig-update` binary as root on a schedule. This script de-escalates to the sig user to check if there are new commits on `BRANCH`, and if so, it builds a new sig binary. Then as root, it restarts `sig.service` and starts sig's metrics with docker-compose. As the sig user, `sig.service` runs the sig binary that was built in the sig user's home folder, passing the configured `CLI_ARGS`.

### Config

The configuration file `/etc/sig.conf` is used by both systemd and the `sig-update` binary. systemd reads the file when running `sig.service` in order to pass the correct `CLI_ARGS` to sig. `sig-update` reads the file when it's checking the `BRANCH` for new commits, and when setting the `SLACK_WEBHOOK_URL` for sig's metrics.

## Root privileges

All of the systemd units are system-level units, with some root privileges, because we want the service to start reliably when the system boots. If these three units were instead user-level units, they would only run after the user logs in. Automating startup on boot would require additional system-level units to log in the user, which would increase the complexity. Minimal root privileges were integrated into the existing units to keep this both simple and reliable.
