Install sig as a long running service on a linux system, and periodically have it self-update based on the latest code in main and restart. This exists to maintain CI test environments.

## Install

```bash
git clone https://github.com/Syndica/sig.git
cd sig/ci/run-and-update-service

sudo make install      # install update script and systemd units to the system
sudo vim /etc/sig.conf # edit file to specify the desired CLI args for sig
sudo make start        # start sig and the timer to periodically update sig
```

## Uninstall

```bash
sudo make uninstall
```
