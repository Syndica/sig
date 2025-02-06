---
sidebar_position: 6
title: Debugging
---

# Debugging

## Using vscode with sig unit tests

move the two files in (`docs/files/`) to the `.vscode` folder in root:
- `launch.json`
- `tasks.json`
add breakpoints and everything should work as normal in vscode

## Open file limits on macOS

accounts-db opens many account files which requires admin changes to the machine - these are some resources to help:
- https://superuser.com/questions/433746/is-there-a-fix-for-the-too-many-open-files-in-system-error-on-os-x-10-7-1/443168#443168
- https://gist.github.com/qileq/49fbeff99def200179001d551c0a7036

Based on the above resources and individual testing, we concluded that to increase the number of open file descriptors and vnodes until next reboot, one must run:
1. `ulimit -Sn 100100100`
2. `sudo sysctl kern.maxvnodes=100100100`: warning, this has been known to crash when the SystemFdQuotaExceeded error would have been issues otherwise
3. `sudo sysctl -w kern.maxfiles=100100100`
4. `sudo sysctl -w kern.maxfilesperproc=100100100`
