# simple-ipblock
A simple bash script that creates basic IP blocking with `iptables`

This script can be used on a router based with tomato / asus-merlin firmware.


## Quickstart

```
cd /opt/usr/bin

curl -L https://github.com/codekow/simple-ipblock/raw/main/ipblock.sh -o ipblock.sh
chmod +x ipblock.sh
```

- Put [ipblock.sh](ipblock.sh) into path (ex: /opt/usr/bin/ipblock.sh).

- Modify `BLOCKLIST_DIR` in [ipblock.sh](ipblock.sh) to specfy config files location. Default is `BLOCKLIST_DIR=/opt/etc/ipblock`.
