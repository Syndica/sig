# open file limits 

accounts-db opens many account files which requires admin changes to the machine - these are some resources to help: 
- https://superuser.com/questions/433746/is-there-a-fix-for-the-too-many-open-files-in-system-error-on-os-x-10-7-1/443168#443168
- https://gist.github.com/qileq/49fbeff99def200179001d551c0a7036
- also need to increase the os max number of vsnodes: `sudo sysctl kern.maxvnodes=100100100`

# using vscode with sig unit tests 

move the two files in (`docs/files/`) to the `.vscode` folder in root: 
- `launch.json`
- `tasks.json`

add breakpoints and everything should work as normal in vscode