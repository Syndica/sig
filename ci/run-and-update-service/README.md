Install sig as a long running service on a linux system, and periodically have it self-update based on the latest code in main and restart. This exists to maintain CI test environments.

## Installation

```bash
git clone https://github.com/Syndica/sig.git
cd sig/scripts/ci-run-rebuild
sudo make install      # install update script and systemd units to the system
sudo vim /etc/sig.conf # edit file to specify the desired CLI args for sig
sudo make start        # start sig and the timer to periodically update sig
```
