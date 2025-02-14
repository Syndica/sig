---
sidebar_position: 9
title: FAQ Help
---

This file contains general help with problems that may arise during building/development.

## Open file limits on macOS

accounts-db opens many account files which requires admin changes to the machine - these are some resources to help:
- https://superuser.com/questions/433746/is-there-a-fix-for-the-too-many-open-files-in-system-error-on-os-x-10-7-1/443168#443168
- https://gist.github.com/qileq/49fbeff99def200179001d551c0a7036

Based on the above resources and individual testing, we concluded that to increase the number of open file descriptors and vnodes until next reboot, one must run:
1. `ulimit -Sn 100100100`
2. `sudo sysctl kern.maxvnodes=100100100`: warning, this has been known to crash when the SystemFdQuotaExceeded error would have been issues otherwise
3. `sudo sysctl -w kern.maxfiles=100100100`
4. `sudo sysctl -w kern.maxfilesperproc=100100100`
