# zabbix-kernel

Zabbix monitoring of the Linux kernel: which kernel is running, which kernel is
installed, and how many CVEs a pending reboot would fix. Includes an optional
rEFInd boot-order check and an optional CVSS enrichment for the alert text.

The template (`Template OS Linux kernel`) is self-contained; the two optional
features can be enabled independently and are off by default.

## Contents

| Path | Purpose |
|---|---|
| `template/template_os_linux_kernel.xml` | Zabbix template (Zabbix 7.4 export format) |
| `agent/kernel.conf` | Zabbix agent `UserParameter` definitions |
| `agent/kernel-cve-count` | helper that counts/prints the CVEs fixed by a reboot |
| `cvss/kernel-cve-cvss-push` | optional: maintain the CVSS suffix used by the High alert |
| `cvss/kernel-cve-cvss.conf.example` | configuration example for the CVSS add-on |
| `LICENSE` | MIT license |

## What the template monitors

| Item | Key | Meaning |
|---|---|---|
| Kernel active | `kernel.active` | running kernel (`uname -r`) |
| Kernel available | `kernel.avail` | newest `/boot/vmlinuz-*` by version |
| Kernel to boot (newest timestamp) | `kernel.boot` | `/boot/vmlinuz-*` with the newest mtime (what rEFInd boots) |
| Kernel boot state | `kernel.boot.state` | `ok`, or the kernel rEFInd would boot, or empty when rEFInd is absent |
| Kernel cves | `kernel.cves` | number of CVEs a reboot to the newest kernel would fix |
| Kernel cves list | `kernel.cves.list` | the same CVEs, one per line with the fixing version |

Triggers:

| Severity | Name | Condition |
|---|---|---|
| Info | `Kernel update available` | a newer kernel is installed and it fixes no known CVEs |
| High | `Kernel update available ({ITEM.VALUE} cve's{$KERNEL_CVE_CVSS})` | a newer kernel is installed and fixes one or more CVEs |
| Disaster | `Newest kernel is not the one rEFInd will boot` | the newest installed kernel is not the one with the newest boot file mtime (opt-in) |

`kernel.cves` is derived from the kernel package changelogs shipped on the host
(Debian/Ubuntu/Proxmox `changelog.Debian.gz`, or `rpm -q --changelog` on the
RHEL family). It needs no network access and no external data source: a CVE is
counted when its earliest fixing version lies strictly between the running and
the newest installed kernel.

## Requirements

* Zabbix 7.4 or newer (the template is a 7.4 export).
* Zabbix agent 2 on the monitored host.
* `/boot` readable by the `zabbix` user, and kernel packages that ship a
  changelog. Containers and hosts without kernel packages in `/boot` are not
  suitable targets for this template.

## Agent installation

On each monitored host:

```sh
install -m 0640 -o zabbix -g zabbix agent/kernel.conf /etc/zabbix/zabbix_agent2.d/kernel.conf
install -m 0750 -o zabbix -g zabbix agent/kernel-cve-count /usr/local/bin/kernel-cve-count
zabbix_agent2 -R userparameter_reload
```

`kernel-cve-count` must be executable and readable by the `zabbix` user, and
that user must be able to read `/boot` and the kernel changelogs. Verify:

```sh
sudo -u zabbix /usr/local/bin/kernel-cve-count
sudo -u zabbix zabbix_agent2 -t kernel.avail
sudo -u zabbix zabbix_agent2 -t kernel.boot.state
```

The script exits non-zero (making the item unsupported) when there is no
`/boot/vmlinuz-*`; this is intentional, so hosts that do not fit the template
show up rather than silently reporting zero.

## Template installation

Import `template/template_os_linux_kernel.xml` (Data collection -> Templates ->
Import) and link `Template OS Linux kernel` to the hosts that run the agent
configuration above. The template group is `Templates`.

## Macros

| Macro | Default | Purpose |
|---|---|---|
| `{$KERNEL_CVE_CVSS}` | *(empty)* | optional suffix appended to the High alert name; maintained by `kernel-cve-cvss-push` |
| `{$KERNEL_CVE_CVSS_ENABLED}` | `0` | set to `1` on the hosts that should get the CVSS suffix (host-level; see the note on restricted tokens) |
| `{$KERNEL_BOOT_ENABLED}` | `0` | set to `1` to enable the rEFInd boot-order check |

Because `{$KERNEL_CVE_CVSS}` defaults to empty, the High alert reads
`Kernel update available (12 cve's)` until the CVSS add-on is set up.

## Optional: rEFInd boot-order check

rEFInd orders boot entries by file modification time. If a newly installed
kernel image has an older mtime than the previous one, rEFInd keeps booting the
old kernel, so a reboot does not bring the host onto the new kernel.

The agent keys `kernel.boot` (what rEFInd will boot) and `kernel.boot.state`
(the result of comparing the newest kernel by version with the newest by mtime)
are evaluated from a single `/boot` listing, so the two values can never be
sampled at different times. `kernel.boot.state` is `ok` when they match, the
version rEFInd would boot when they differ, and empty when the host is not using
rEFInd (detected via `/boot/refind_linux.conf`). The trigger requires
`{$KERNEL_BOOT_ENABLED}=1`; set that macro to `1` on rEFInd hosts (or the
template). No extra per-host agent configuration is needed: both keys are part
of `kernel.conf`.

The comparison is deliberately done in the agent. An earlier version of the
trigger compared `kernel.boot` (5m) with `kernel.avail` (1h) directly; because
those items are polled independently, it fired for up to an hour after every
kernel upgrade (as soon as the fast item saw the new kernel and until the slow
one caught up), even when rEFInd was fine.

Remediation when it fires: `touch /boot/vmlinuz-<newest-version>` so rEFInd sees
the newest kernel as the most recent entry, then reboot.

## Optional: highest CVSS in the alert

`kernel.cves` counts CVEs but the changelogs carry no severity. The optional
`kernel-cve-cvss-push` script fills that gap:

1. it reads every host's `kernel.cves.list` item through the Zabbix API;
2. it looks each CVE up in a local cache, filling gaps from the NVD 2.0 API;
3. it writes the highest base score into the host-level `{$KERNEL_CVE_CVSS}`
   macro as a suffix, e.g. `, highest CVSS 9.8`.

Zabbix resolves user macros in trigger names when the event is generated, so the
alert text becomes `Kernel update available (12 cve's, highest CVSS 9.8)` with no
change to the trigger expression. The script runs entirely on the Zabbix server:
hosts and proxies need no network access or extra files, and hosts behind a
proxy work the same way.

CVSS is not available for every CVE - a score is often published late or never.
When none of the pending CVEs is scored the suffix reads `, highest CVSS n/a`.
Deleting the host macro restores the plain alert name.

### Requirements

* A Zabbix API token with permission to read item values and to manage host
  macros: `item.get`, `host.get`, `usermacro.get`, `usermacro.create`,
  `usermacro.update`, `usermacro.delete`.
* Outbound HTTPS access to `services.nvd.nist.gov` from the Zabbix server (only
  while the cache is being filled; a published NVD API key raises the rate limit
  from 5 to 50 requests / 30 s).
* Zabbix server 7.4 or newer.

### Installation

On the Zabbix server:

```sh
install -m 0755 -o root -g root cvss/kernel-cve-cvss-push /usr/local/sbin/kernel-cve-cvss-push
install -m 0640 -o root -g zabbix cvss/kernel-cve-cvss.conf.example /etc/zabbix/kernel-cve-cvss.conf
# edit /etc/zabbix/kernel-cve-cvss.conf: set API_URL and API_TOKEN
```

Schedule it, for example every 30 minutes:

```cron
*/30 * * * * /usr/local/sbin/kernel-cve-cvss-push >> /var/log/kernel-cve-cvss-push.log 2>&1
```

Enable the feature by setting `{$KERNEL_CVE_CVSS_ENABLED}=1`. Run once with
`--dry-run` first to see what it would change. The cache lives at
`/var/lib/zabbix/kernel-cve-cvss-cache.json`; override the paths with the
`KERNEL_CVE_CVSS_CONF` and `KERNEL_CVE_CVSS_CACHE` environment variables.

Set the macro **per host**. A Zabbix role that is restricted to host groups
cannot read template-level user macros (`usermacro.get` returns host macros
only, and `template.get` is denied), so a value set on the template is
invisible to the script and has no effect. A host-level macro always works;
the script's fallback when no macro is visible is disabled.

### Monitoring the script (optional)

The script can heartbeat every run to a trapper item so a failure is itself
visible. Add a trapper item to the Zabbix server host:

* key `kernel.cve.cvss.push`, type of information Numeric (unsigned), 1 = last
  run succeeded, 0 = failed.

and set `HEARTBEAT_HOST` in the config to that host's technical name. A suitable
Warning trigger:

```
nodata(/<server-host>/kernel.cve.cvss.push,2h)=1 or last(/<server-host>/kernel.cve.cvss.push)=0
```

## Notes and limitations

* The CVSS figure is only as fresh as the last push run and NVD's data.
* Host macro updates are configuration changes (they appear in the audit log)
  but happen only when a value changes.
* `kernel.boot` relies on vfat/ESP mtime granularity; two kernels installed
  within the same second can tie. The verdict itself comes from
  `kernel.boot.state`, which compares one `/boot` listing atomically.
* The RHEL `rpm -q --changelog` path is implemented but not tested.
* The template ships UUIDs so it can be re-imported to update an existing copy
  in place (`updateExisting`). If you already run a template with these UUIDs
  from elsewhere, do not import this one blind.

## License

MIT. See [LICENSE](LICENSE).
