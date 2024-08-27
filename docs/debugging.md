# using vscode with sig unit tests 

move the two files in (`docs/files/`) to the `.vscode` folder in root: 
- `launch.json`
- `tasks.json`
add breakpoints and everything should work as normal in vscode

# open file limits on macOS

accounts-db opens many account files which requires admin changes to the machine - these are some resources to help: 
- https://superuser.com/questions/433746/is-there-a-fix-for-the-too-many-open-files-in-system-error-on-os-x-10-7-1/443168#443168
- https://gist.github.com/qileq/49fbeff99def200179001d551c0a7036

Based on the above resources and individual testing, we concluded that to increase the number of open file descriptors and vnodes until next reboot, one must run:
1. `ulimit -Sn 100100100`
2. `sudo sysctl kern.maxvnodes=100100100`: warning, this has been known to crash when the SystemFdQuotaExceeded error would have been issues otherwise
3. `sudo sysctl -w kern.maxfiles=100100100`
4. `sudo sysctl -w kern.maxfilesperproc=100100100`

## Persistent changes
The following details how to make the changes described above persistent, although it is not recommended, especially not in the second case.

* To increase the number of open file descriptors persistently, create/edit `/Library/LaunchDaemons/limit.maxfiles.plist` with root access & executable
persmission, and at least these contents:
```diff
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>limit.maxfiles</string>
    <key>ProgramArguments</key>
    <array>
      <string>launchctl</string>
      <string>limit</string>
      <string>maxfiles</string>
+     <string>100100100</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>ServiceIPC</key>
    <false/>
  </dict>
</plist>
```

* To increase the number of vnodes persistently, create/edit `/Library/LaunchDaemons/com.startup.sysctl.plist` with root access & executable permission,
and at least these contents:
```diff
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <key>Label</key>
    <string>com.startup.sysctl</string>
    <key>LaunchOnlyOnce</key>
    <true/>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/sbin/sysctl</string>
+       <string>kern.maxvnodes=100100100</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</plist>
```
WARNING: not recommended for reasons listed before.
