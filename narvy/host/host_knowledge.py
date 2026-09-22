"""Knowledge base for host and infrastructure audit findings.

Maps each hardening-engine test id to a control with a remediation and severity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

__all__ = ["HostControl", "HOST_CONTROLS", "lookup"]


@dataclass(frozen=True)
class HostControl:
    control_id: str
    title: str
    description: str
    remediation: str
    cis: str
    cwe: str
    location: str
    severity: str


HOST_CONTROLS: Dict[str, HostControl] = {
    "GEN-0010": HostControl(
        control_id="NARVY-HOST-OS-001",
        title="Operating system release is end-of-life and no longer receives security updates",
        description=(
            "The installed distribution release has passed its support end date. "
            "The vendor no longer publishes security patches for the kernel, "
            "OpenSSL, systemd or any packaged service on this host. Every "
            "vulnerability disclosed from the end-of-life date onward stays open "
            "permanently, including remote pre-auth flaws, and no amount of "
            "configuration hardening compensates for an unpatchable base system."
        ),
        remediation=(
            "Upgrade to a currently supported release. Check the release and its "
            "support window with `lsb_release -a` and `hwe-support-status "
            "--verbose`. Plan an in-place upgrade to the next supported release "
            "(`sudo apt update && sudo apt full-upgrade`, then `sudo do-release-upgrade`) "
            "or, preferably for a production server, rebuild on a supported LTS "
            "release and migrate. Prefer an LTS release so the next forced upgrade "
            "is years away, not months. Until the upgrade lands, treat this host "
            "as exposed: restrict inbound access to it at the network edge."
        ),
        cis="CIS 1.9 Patch Management",
        cwe="CWE-1104",
        location="/etc/os-release",
        severity="high",
    ),

    "DBS-1820": HostControl(
        control_id="NARVY-HOST-DB-001",
        title="MongoDB accepts connections without authentication",
        description=(
            "The MongoDB instance runs with access control disabled: any client "
            "that can open a TCP connection to the database port gets full "
            "administrative access, with no credentials. It can read every "
            "collection, modify or drop them, and on many builds read files or "
            "run server-side JavaScript. If the port is reachable from outside "
            "the host this is total data loss and total data disclosure. "
            "Unauthenticated MongoDB instances are found and wiped by automated "
            "ransom scanners within hours of being exposed."
        ),
        remediation=(
            "1. Bind the listener to localhost or a private interface: set "
            "`net.bindIp: 127.0.0.1` in /etc/mongod.conf. Never leave it at 0.0.0.0.\n"
            "2. Create an admin user before enabling auth: connect with `mongosh`, "
            "`use admin`, then `db.createUser({user:\"admin\", pwd:<strong>, "
            "roles:[{role:\"userAdminAnyDatabase\", db:\"admin\"}]})`.\n"
            "3. Enable access control: add `security.authorization: enabled` to "
            "/etc/mongod.conf, then `sudo systemctl restart mongod`.\n"
            "4. Create a least-privilege user per application database "
            "(`readWrite` on that database only), and do not let apps use the admin user.\n"
            "5. Verify: an unauthenticated `mongosh --eval 'db.adminCommand({listDatabases:1})'` "
            "must now fail with `Unauthorized`.\n"
            "6. Block the port at the firewall for everything except the "
            "application hosts, and assume current data is compromised if the "
            "port was ever publicly reachable: rotate secrets stored in it and "
            "review the collections for tampering."
        ),
        cis="CIS 5.x Database Authentication",
        cwe="CWE-306",
        location="/etc/mongod.conf",
        severity="high",
    ),

    "TIME-3185": HostControl(
        control_id="NARVY-HOST-TIME-001",
        title="System clock is not synchronized with a time source",
        description=(
            "The time synchronization service is running but reports that it has "
            "not reached a synchronized state, so the clock is free-running. "
            "Drift breaks certificate validity checks, time-based one-time "
            "passwords, token and session expiry, and scheduled jobs. It also "
            "makes logs from this host impossible to correlate with other hosts "
            "during an incident, which is when correlation matters most. Not "
            "directly exploitable, so this is a reliability and forensics issue "
            "rather than an open door."
        ),
        remediation=(
            "Check state with `timedatectl status` (expect `System clock "
            "synchronized: yes` and `NTP service: active`). If it is not "
            "synchronized: `sudo timedatectl set-ntp true`, confirm reachable "
            "servers in /etc/systemd/timesyncd.conf (`NTP=` / `FallbackNTP=`), "
            "then `sudo systemctl restart systemd-timesyncd` and re-check with "
            "`timedatectl show-timesync --all`. Ensure outbound UDP/123 to the "
            "configured time servers is allowed by the firewall, since a blocked "
            "port is the usual cause. On hosts that need stricter accuracy, use "
            "a full NTP daemon pointed at internal time servers."
        ),
        cis="CIS 2.1 Time Synchronization",
        cwe="",
        location="/etc/systemd/timesyncd.conf",
        severity="low",
    ),

    "BOOT-5122": HostControl(
        control_id="NARVY-HOST-BOOT-001",
        title="Bootloader is not password protected",
        description=(
            "The bootloader has no password set, so anyone at the console or "
            "with virtual-console access can edit the boot entry, append "
            "`init=/bin/bash` and get a root shell without any credential, or "
            "boot into single-user mode. This bypasses every OS-level access "
            "control. It requires physical or console access, so on a hosted "
            "virtual machine the practical risk is limited to whoever already "
            "controls the hypervisor console."
        ),
        remediation=(
            "Generate a hash with `grub-mkpasswd-pbkdf2`, then add to "
            "/etc/grub.d/40_custom:\n"
            "  set superusers=\"root\"\n"
            "  password_pbkdf2 root grub.pbkdf2.sha512....\n"
            "Apply with `sudo update-grub`. To keep unattended reboots working, "
            "add `--unrestricted` to the default menu entry so booting needs no "
            "password but editing entries does. Store the password in your secret "
            "manager: a lost bootloader password turns a recovery boot into a "
            "rescue-media job. Also restrict console/KVM access at the provider."
        ),
        cis="CIS 1.4.1 Bootloader Password",
        cwe="CWE-284",
        location="/etc/grub.d/40_custom",
        severity="low",
    ),
    "BOOT-5180": HostControl(
        control_id="NARVY-HOST-BOOT-002",
        title="Services enabled at boot have not been reviewed",
        description=(
            "The set of services started automatically at boot has not been "
            "reduced to what this host actually needs. Every enabled unit is code "
            "that runs as root at startup, often opens a socket, and must be "
            "patched forever. Unused daemons left enabled by a default install "
            "are a recurring source of exposure. They get forgotten, so they "
            "never get reviewed when a vulnerability is published."
        ),
        remediation=(
            "List what starts at boot: `systemctl list-unit-files --type=service "
            "--state=enabled`. For each unit, decide whether this host needs it. "
            "Disable what it does not: `sudo systemctl disable --now <unit>`. If "
            "the package itself is not needed, remove it (`sudo apt purge <pkg>`) "
            "rather than only disabling the unit. Pay attention to anything "
            "listening on a socket, and cross-check with `sudo ss -tulpn`. Re-run "
            "this review whenever the host's role changes."
        ),
        cis="CIS 2.x Special Purpose Services",
        cwe="CWE-1188",
        location="systemd enabled units",
        severity="low",
    ),
    "BOOT-5264": HostControl(
        control_id="NARVY-HOST-BOOT-003",
        title="Service units run without sandboxing options",
        description=(
            "Services on this host run with the default unit configuration, which "
            "grants them far more of the system than they need: full filesystem "
            "write access, all capabilities, and the ability to gain new "
            "privileges. systemd can confine each service so that a compromise of "
            "one daemon does not hand over the whole host. Without it, a single "
            "remote-code-execution bug in any service escalates directly to root-level "
            "reach across the filesystem."
        ),
        remediation=(
            "For each exposed service, add a drop-in with `sudo systemctl edit "
            "<unit>` and set the options the service can tolerate:\n"
            "  [Service]\n"
            "  NoNewPrivileges=yes\n"
            "  PrivateTmp=yes\n"
            "  ProtectSystem=strict\n"
            "  ProtectHome=yes\n"
            "  ProtectKernelTunables=yes\n"
            "  ProtectKernelModules=yes\n"
            "  ProtectControlGroups=yes\n"
            "  RestrictSUIDSGID=yes\n"
            "  ReadWritePaths=/var/lib/<service>\n"
            "Then `sudo systemctl daemon-reload && sudo systemctl restart <unit>`. "
            "Use `systemd-analyze security <unit>` to see the current exposure "
            "score before and after, and test each service after tightening, since "
            "`ProtectSystem=strict` breaks daemons that write outside their "
            "declared paths."
        ),
        cis="CIS 2.x Special Purpose Services",
        cwe="CWE-250",
        location="/etc/systemd/system/<unit>.d/override.conf",
        severity="low",
    ),

    "AUTH-9230": HostControl(
        control_id="NARVY-HOST-AUTH-001",
        title="Password hashing cost is left at the default",
        description=(
            "The number of hashing rounds used when a local password is set is "
            "not configured, so the system default applies. The cost factor is "
            "what makes an offline attack on a stolen /etc/shadow slow. A low "
            "cost means a leaked shadow file can be brute-forced far faster. This "
            "only matters once an attacker already has the hash file, which is "
            "why it is defence-in-depth rather than an open door."
        ),
        remediation=(
            "In /etc/login.defs set an explicit cost, for example:\n"
            "  SHA_CRYPT_MIN_ROUNDS 640000\n"
            "  SHA_CRYPT_MAX_ROUNDS 640000\n"
            "Better, switch to yescrypt (the modern default on current Ubuntu) "
            "and confirm `password ... pam_unix.so ... yescrypt` in "
            "/etc/pam.d/common-password. Existing hashes are NOT re-hashed by "
            "this change: they are upgraded only when each password is next "
            "changed, so force a rotation for local accounts that still have a "
            "password (`sudo passwd --expire <user>`). Verify the resulting "
            "prefix in /etc/shadow (`$y$` for yescrypt, `$6$rounds=` for SHA-512)."
        ),
        cis="CIS 5.4.1 Password Hashing Algorithm",
        cwe="CWE-916",
        location="/etc/login.defs",
        severity="low",
    ),
    "AUTH-9262": HostControl(
        control_id="NARVY-HOST-AUTH-002",
        title="No password strength enforcement on local accounts",
        description=(
            "No password quality module is active, so any local password is "
            "accepted, including a single character, the username, or a known-breached "
            "password. Nothing stops an administrator from setting a guessable "
            "password on a root-capable account. This matters as soon as any "
            "password-accepting path exists on the host (console, remote access "
            "with password auth, or privilege escalation via sudo)."
        ),
        remediation=(
            "Install the quality module: `sudo apt install libpam-pwquality`. In "
            "/etc/security/pwquality.conf set:\n"
            "  minlen = 14\n"
            "  minclass = 3\n"
            "  dcredit = 0 / ucredit = 0 / lcredit = 0 / ocredit = 0\n"
            "  maxrepeat = 3\n"
            "  dictcheck = 1\n"
            "  enforce_for_root\n"
            "Confirm /etc/pam.d/common-password contains a `pam_pwquality.so "
            "retry=3` line before `pam_unix.so`. Prefer length over character-class "
            "gymnastics, since long passphrases beat short complex ones. Test by "
            "trying to set a weak password with `passwd` on a throwaway account; "
            "it must be rejected."
        ),
        cis="CIS 5.4.1 Password Creation Requirements",
        cwe="CWE-521",
        location="/etc/security/pwquality.conf",
        severity="medium",
    ),
    "AUTH-9282": HostControl(
        control_id="NARVY-HOST-AUTH-003",
        title="Password-protected accounts have no expiration date",
        description=(
            "One or more local accounts with a password have no account "
            "expiration set. Accounts for contractors, temporary staff or "
            "one-off migrations then stay valid forever, long after the person "
            "or purpose is gone. Orphaned but still-valid credentials are a "
            "classic quiet backdoor: nobody watches them, so nobody notices them "
            "being used."
        ),
        remediation=(
            "Review accounts and their dates: `sudo chage -l <user>`, and list "
            "accounts with passwords via `sudo awk -F: '($2 !~ /^[*!]/) {print $1}' "
            "/etc/shadow`. Set an expiry on temporary accounts: `sudo chage -E "
            "$(date -d '+90 days' +%F) <user>`. Delete accounts that should no "
            "longer exist (`sudo userdel -r <user>`), and lock service accounts "
            "that must never log in (`sudo usermod -L -s /usr/sbin/nologin "
            "<user>`). Set an inactivity lock as a safety net: `sudo useradd -D "
            "-f 30` so a password stays usable for at most 30 days past expiry."
        ),
        cis="CIS 5.5.1 Account Expiration",
        cwe="CWE-1104",
        location="/etc/shadow",
        severity="low",
    ),
    "AUTH-9286": HostControl(
        control_id="NARVY-HOST-AUTH-004",
        title="Password minimum and maximum age are not configured",
        description=(
            "Neither the minimum nor the maximum password age is set, so a local "
            "password is valid indefinitely and can also be cycled instantly to "
            "defeat password-history checks. A credential leaked years ago stays "
            "valid; a user forced to change a password can loop back to the old "
            "one in seconds. These two settings are the floor and the ceiling of "
            "a password's lifetime and are normally configured together."
        ),
        remediation=(
            "In /etc/login.defs set:\n"
            "  PASS_MIN_DAYS 1     # cannot re-cycle a password the same day\n"
            "  PASS_MAX_DAYS 365   # upper bound on credential lifetime\n"
            "  PASS_WARN_AGE 7\n"
            "These apply to accounts created afterwards, so also fix existing "
            "ones: `sudo chage -m 1 -M 365 -W 7 <user>` for each local account "
            "with a password (audit with `sudo chage -l <user>`). Do not set an "
            "aggressive rotation window: forced frequent rotation pushes users to "
            "predictable variants and is no longer recommended practice. The "
            "stronger control is removing interactive passwords entirely in "
            "favour of key-based access."
        ),
        cis="CIS 5.5.1 Password Aging",
        cwe="CWE-262",
        location="/etc/login.defs",
        severity="low",
    ),
    "AUTH-9328": HostControl(
        control_id="NARVY-HOST-AUTH-005",
        title="Default file-creation mask is too permissive",
        description=(
            "The default umask is not restrictive, so newly created files and "
            "directories are readable by other local users by default. Anything "
            "an application or administrator writes without setting explicit "
            "permissions (config files, exports, logs, backups, temporary "
            "dumps) is world-readable the moment it is created. This turns any "
            "low-privilege local account or compromised service into a reader of "
            "secrets it was never meant to see."
        ),
        remediation=(
            "Set `UMASK 027` in /etc/login.defs (owner full, group read, others "
            "nothing), and confirm `session optional pam_umask.so` is present in "
            "/etc/pam.d/common-session so it is applied to login sessions. Also "
            "set `umask 027` in /etc/profile and /etc/bash.bashrc to cover "
            "non-PAM shells. Use `umask 077` on hosts where users must not read "
            "each other's files at all. Verify with `umask` in a fresh login "
            "session, where it must print 0027. Existing files keep their current "
            "permissions: fix sensitive ones explicitly with `chmod`."
        ),
        cis="CIS 5.4.4 Default User Umask",
        cwe="CWE-732",
        location="/etc/login.defs",
        severity="low",
    ),

    "FILE-6310": HostControl(
        control_id="NARVY-HOST-FS-001",
        title="/home and /var are not on separate partitions",
        description=(
            "/home and /var share the root filesystem. Two consequences: a "
            "runaway log, upload or spool file under /var can fill the root "
            "filesystem and stop the whole system, which is a trivially "
            "triggerable denial of service on any host that accepts user data; "
            "and user-writable areas cannot be given their own mount options "
            "(nodev, nosuid, noexec), so an attacker who can write a file there "
            "can also execute it or drop a setuid binary."
        ),
        remediation=(
            "Check the current layout with `findmnt` / `lsblk`. On an existing "
            "host, repartitioning means downtime, so weigh it against the value: "
            "if a rebuild is planned, define separate /home, /var, /var/log, "
            "/var/tmp and /tmp filesystems in the installer and mount user-writable "
            "ones with `nodev,nosuid` (add `noexec` on /var/tmp, /tmp and /home "
            "where applications tolerate it). Where repartitioning is not "
            "practical, get most of the benefit now: enforce disk quotas or log "
            "rotation limits on /var, and mount /tmp as tmpfs with "
            "`nodev,nosuid,noexec` via `sudo systemctl enable --now tmp.mount`. "
            "Monitor root filesystem usage with an alert well below 100%."
        ),
        cis="CIS 1.1.x Filesystem Partitions",
        cwe="CWE-400",
        location="/etc/fstab",
        severity="low",
    ),
    "FILE-7524": HostControl(
        control_id="NARVY-HOST-FS-002",
        title="Permissions on sensitive files are wider than required",
        description=(
            "One or more system files carry permissions broader than they need. "
            "On configuration and credential files this means a local account or "
            "a compromised low-privilege service can read material it should not "
            "(password hashes, keys, service credentials), or, if a file is "
            "writable, alter behaviour that runs as root. File permissions are "
            "the last barrier once an attacker has any foothold on the host."
        ),
        remediation=(
            "Restore the expected ownership and modes on the core files:\n"
            "  sudo chown root:root /etc/passwd /etc/group && sudo chmod 644 /etc/passwd /etc/group\n"
            "  sudo chown root:shadow /etc/shadow /etc/gshadow && sudo chmod 640 /etc/shadow /etc/gshadow\n"
            "  sudo chmod 600 /etc/ssh/sshd_config && sudo chmod 600 /etc/ssh/ssh_host_*_key\n"
            "  sudo chmod 700 /root\n"
            "Then hunt for the general cases: world-writable files (`sudo find / "
            "-xdev -type f -perm -0002 -not -path '/proc/*'`), files with no "
            "owner (`sudo find / -xdev -nouser -o -nogroup`), and unexpected "
            "setuid/setgid binaries (`sudo find / -xdev -type f -perm /6000 -ls`) "
            "-- review each and strip the bit where it is not needed. Check "
            "application config holding secrets is 600 and owned by its service "
            "user."
        ),
        cis="CIS 6.1.x File Permissions",
        cwe="CWE-732",
        location="filesystem permissions",
        severity="low",
    ),

    "USB-1000": HostControl(
        control_id="NARVY-HOST-USB-001",
        title="USB storage support is enabled",
        description=(
            "The kernel will load USB mass-storage drivers, so plugging in a "
            "device at the console mounts removable media. That is a path for "
            "data exfiltration and for introducing files onto the host outside "
            "any monitored channel. It requires physical access, so on a hosted "
            "virtual machine the practical risk is close to zero; it matters on "
            "bare metal, on-premise or kiosk-style servers."
        ),
        remediation=(
            "Blacklist the driver: create /etc/modprobe.d/blacklist-usb-storage.conf "
            "with:\n"
            "  install usb-storage /bin/true\n"
            "  blacklist usb-storage\n"
            "Then `sudo update-initramfs -u` and reboot. Verify with `lsmod | "
            "grep usb_storage` (no output) and by plugging a device in: it must "
            "not appear. If some peripheral legitimately needs mass storage, "
            "leave this as accepted risk and control it physically instead, and "
            "record the decision rather than silently ignoring the finding."
        ),
        cis="CIS 1.1.x Removable Media",
        cwe="CWE-1299",
        location="/etc/modprobe.d/",
        severity="low",
    ),

    "PKGS-7346": HostControl(
        control_id="NARVY-HOST-PKG-001",
        title="Removed packages still have configuration and files on disk",
        description=(
            "Packages that were removed but not purged left configuration files "
            "behind, and older versions remain on disk. Leftover config can be "
            "picked up if the package is ever reinstalled, and stale files "
            "silently misrepresent what is installed: an inventory or "
            "vulnerability scan reads them as present, or misses them. It is "
            "housekeeping, not an exposure, but it is the housekeeping that keeps "
            "patch inventories honest."
        ),
        remediation=(
            "List leftovers: `dpkg -l | awk '/^rc/ {print $2}'`. Purge them: "
            "`sudo apt purge $(dpkg -l | awk '/^rc/ {print $2}')`, but read the "
            "list before confirming. Then `sudo apt autoremove --purge` to drop "
            "orphaned dependencies and `sudo apt clean` to clear the package "
            "cache. Check for old kernels left behind (`dpkg -l | grep "
            "linux-image`) and remove all but the running one and one fallback. "
            "Make purge the default habit: use `apt purge`, not `apt remove`."
        ),
        cis="CIS 1.9 Patch Management",
        cwe="",
        location="dpkg package state",
        severity="low",
    ),
    "PKGS-7370": HostControl(
        control_id="NARVY-HOST-PKG-002",
        title="No verification of installed package file integrity",
        description=(
            "There is no way on this host to check installed files against the "
            "checksums their packages shipped with. If a system binary is "
            "replaced (by an attacker, or by a botched manual install), "
            "nothing detects the change. Package checksum verification is the "
            "cheapest available answer to 'is /usr/bin still what the "
            "distribution shipped?'"
        ),
        remediation=(
            "Install the package-checksum verification tool: `sudo apt install "
            "debsums`. Verify the system with `sudo debsums -c` (lists files "
            "whose checksum no longer matches; expect a few legitimately edited "
            "config files) and `sudo debsums -a` for a full pass. Run it on a "
            "schedule and alert on changes to binaries: `sudo debsums -c` in a "
            "weekly cron or systemd timer, output piped to your alerting. "
            "Investigate every unexpected binary mismatch as a possible "
            "compromise. Pair with file integrity monitoring for coverage of "
            "files that are not package-owned."
        ),
        cis="CIS 1.3.x File Integrity",
        cwe="CWE-354",
        location="package integrity tooling",
        severity="low",
    ),
    "PKGS-7394": HostControl(
        control_id="NARVY-HOST-PKG-003",
        title="No tooling to report available package security updates",
        description=(
            "This host has nothing installed that reports which packages have "
            "newer versions available and which of those come from the security "
            "repository. Without it, 'are we patched?' can only be answered by "
            "hand, so in practice it stops being answered. Missing security "
            "updates is the single most common way a well-configured server gets "
            "compromised."
        ),
        remediation=(
            "Install the reporting tool: `sudo apt install apt-show-versions`, "
            "then `sudo apt update && apt-show-versions -u` to list upgradable "
            "packages. `apt list --upgradable` gives a quick equivalent, and "
            "`/usr/lib/update-notifier/apt-check --human-readable` separates the "
            "security updates from the rest. Then close the loop rather than just "
            "reporting: enable automatic security patching with `sudo apt install "
            "unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades`, "
            "confirm the security origin is enabled in "
            "/etc/apt/apt.conf.d/50unattended-upgrades, and monitor "
            "/var/log/unattended-upgrades/ so silent failures do not go unnoticed."
        ),
        cis="CIS 1.9 Patch Management",
        cwe="CWE-1104",
        location="/etc/apt/apt.conf.d/50unattended-upgrades",
        severity="low",
    ),

    "NETW-3200": HostControl(
        control_id="NARVY-HOST-NET-001",
        title="Uncommon network protocols are available to the kernel",
        description=(
            "Rarely used transport protocols (DCCP, SCTP, RDS, TIPC) can be "
            "loaded by the kernel on this host. Almost no server uses them, so "
            "their kernel code is comparatively lightly reviewed and has a track "
            "record of memory-corruption bugs, several of which have been local "
            "privilege-escalation vectors. A local process can trigger the module "
            "load simply by creating a socket of that family, so leaving them "
            "available is attack surface for no benefit."
        ),
        remediation=(
            "Create /etc/modprobe.d/blacklist-rare-net.conf with:\n"
            "  install dccp /bin/true\n"
            "  install sctp /bin/true\n"
            "  install rds /bin/true\n"
            "  install tipc /bin/true\n"
            "Then `sudo update-initramfs -u`. Unload any already loaded: `sudo "
            "modprobe -r dccp sctp rds tipc`. Verify with `lsmod | grep -E "
            "'dccp|sctp|rds|tipc'` (no output) and `modprobe -n -v sctp` (must "
            "show /bin/true). Only exception: if an application genuinely uses "
            "SCTP (some telecom stacks do), keep it and blacklist the rest."
        ),
        cis="CIS 3.4.x Uncommon Network Protocols",
        cwe="CWE-1327",
        location="/etc/modprobe.d/",
        severity="low",
    ),
    "FIRE-4513": HostControl(
        control_id="NARVY-HOST-FIRE-001",
        title="Host firewall has no effective rules",
        description=(
            "The packet filter is present but its rule set is empty or unused, so "
            "the host does not filter traffic itself: every port a service binds "
            "to is reachable from anywhere the network allows. The host then "
            "depends entirely on an upstream control (a cloud security group or "
            "an edge firewall) for its perimeter. If that control is "
            "misconfigured, changed, or simply absent, a service that was never "
            "meant to be public becomes public with nothing to stop it. Default-deny "
            "on the host is the layer that survives someone else's mistake."
        ),
        remediation=(
            "Establish a default-deny inbound policy with an explicit allow list. "
            "Simplest on Ubuntu:\n"
            "  sudo ufw default deny incoming\n"
            "  sudo ufw default allow outgoing\n"
            "  sudo ufw allow 22/tcp        # do this BEFORE enabling, or you lock yourself out\n"
            "  sudo ufw allow 443/tcp\n"
            "  sudo ufw enable\n"
            "Restrict management ports to known sources rather than the world: "
            "`sudo ufw allow from <admin-net> to any port 22 proto tcp`. Never "
            "expose database ports: they should be allowed only from application "
            "hosts, or bound to localhost. Verify with `sudo ufw status numbered` "
            "and confirm from outside the host with a port scan that only the "
            "intended ports answer. Keep an out-of-band console session open the "
            "first time you enable it."
        ),
        cis="CIS 3.5.x Firewall Configuration",
        cwe="CWE-1327",
        location="host firewall rules",
        severity="medium",
    ),

    "HTTP-6710": HostControl(
        control_id="NARVY-HOST-WEB-001",
        title="Web server TLS configuration has not been hardened",
        description=(
            "The web server's TLS settings are at defaults and have not been "
            "reviewed. Defaults commonly still permit legacy protocol versions "
            "and weak cipher suites, omit HSTS so a first request can be "
            "downgraded to plaintext, and leak the exact server version in "
            "response headers, which tells an attacker which exploits to try. "
            "None of this is exploitable on its own; together it makes "
            "interception and targeting materially easier."
        ),
        remediation=(
            "For nginx, in the server block (or a shared snippet):\n"
            "  ssl_protocols TLSv1.2 TLSv1.3;\n"
            "  ssl_prefer_server_ciphers off;\n"
            "  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\n"
            "  ssl_session_tickets off;\n"
            "  add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;\n"
            "  server_tokens off;\n"
            "and redirect port 80 to 443. For Apache: `SSLProtocol -all +TLSv1.2 "
            "+TLSv1.3`, a matching `SSLCipherSuite`, `ServerTokens Prod`, "
            "`ServerSignature Off`, and the same HSTS header. Test the config "
            "(`sudo nginx -t` / `sudo apachectl configtest`), reload, then verify "
            "the negotiated protocols from outside with `openssl s_client "
            "-connect <host>:443 -tls1_1` (must fail). Automate certificate "
            "renewal and alert before expiry."
        ),
        cis="CIS 2.2.x Web Server",
        cwe="CWE-326",
        location="web server TLS configuration",
        severity="low",
    ),

    "SSH-7408": HostControl(
        control_id="NARVY-HOST-SSH-001",
        title="Remote shell service is running with unhardened settings",
        description=(
            "The remote shell daemon is at or near stock configuration. That "
            "typically leaves password authentication enabled, which exposes "
            "every account on the host to credential stuffing and brute force "
            "from the internet-wide scanners that hit any open port 22 within "
            "minutes, and allows direct root login, which removes the audit "
            "trail of who did what and turns one guessed password into full "
            "control. This is the most attacked service on a typical Linux "
            "server, so its configuration carries more weight than any other."
        ),
        remediation=(
            "Edit /etc/ssh/sshd_config (or a drop-in in /etc/ssh/sshd_config.d/) "
            "and set:\n"
            "  PermitRootLogin no              # log in as a user, then sudo\n"
            "  PasswordAuthentication no       # keys only, kills brute force outright\n"
            "  KbdInteractiveAuthentication no # closes the keyboard-interactive password path\n"
            "  PermitEmptyPasswords no\n"
            "  MaxAuthTries 3\n"
            "  MaxSessions 4\n"
            "  X11Forwarding no\n"
            "  AllowTcpForwarding no           # unless a tunnel is genuinely needed\n"
            "  ClientAliveInterval 300\n"
            "  ClientAliveCountMax 2\n"
            "  LoginGraceTime 30\n"
            "  AllowUsers <admin> [...]        # explicit allow list\n"
            "Before disabling password auth, confirm your key works in a SECOND "
            "session, otherwise you lock yourself out. Validate the file with "
            "`sudo sshd -t`, then `sudo systemctl reload ssh`. Confirm the result "
            "with `sudo sshd -T | grep -Ei "
            "'permitrootlogin|passwordauthentication|kbdinteractive|maxauthtries|x11forwarding'` "
            "since the effective config is what counts, not the file. Restrict port "
            "22 to known source addresses at the firewall as well."
        ),
        cis="CIS 5.2.x SSH Server Configuration",
        cwe="CWE-16",
        location="/etc/ssh/sshd_config",
        severity="medium",
    ),

    "LOGG-2154": HostControl(
        control_id="NARVY-HOST-LOG-001",
        title="Logs are not shipped to a remote collector",
        description=(
            "All logs live only on this host. An attacker who gains root can "
            "erase or edit them, so the record of the intrusion disappears with "
            "the intrusion, and clearing logs is a standard step in any competent "
            "compromise. Local-only logs are also lost outright if the host dies "
            "or is rebuilt. Without an off-host copy, incident response has "
            "nothing to reconstruct events from and no evidence that stands up."
        ),
        remediation=(
            "Ship logs off the host in near real time. With rsyslog, create "
            "/etc/rsyslog.d/50-remote.conf containing:\n"
            "  *.*  @@<collector-host>:6514   # @@ = TCP; use TLS for anything crossing a network you do not control\n"
            "then `sudo systemctl restart rsyslog`. Configure the receiver to "
            "make the stored copy append-only, and keep retention on the "
            "collector, not here. If the host uses the journal, forward with "
            "`ForwardToSyslog=yes` in /etc/systemd/journald.conf, and set "
            "`Storage=persistent` plus `SystemMaxUse=` so the local journal "
            "survives reboots without filling the disk. Verify end to end: "
            "`logger -t audit-test remote-log-check`, then confirm the line "
            "arrives on the collector. Alert if a host stops sending, because silence "
            "is a signal."
        ),
        cis="CIS 4.2.x Remote Logging",
        cwe="CWE-778",
        location="/etc/rsyslog.d/",
        severity="low",
    ),

    "BANN-7126": HostControl(
        control_id="NARVY-HOST-BANN-001",
        title="Local login banner contains no legal notice",
        description=(
            "The console login banner has no authorized-use notice. This has no "
            "technical effect (it stops nobody), but it has a legal one: in "
            "several jurisdictions prosecuting unauthorized access is harder when "
            "the system never stated that access was restricted. Default banners "
            "also advertise the exact distribution and kernel version to anyone "
            "at the login prompt. Compliance frameworks check for this."
        ),
        remediation=(
            "Replace /etc/issue with a notice approved by whoever owns legal "
            "wording for your company, along the lines of: 'Authorized users "
            "only. All activity may be monitored and reported.' Do NOT include "
            "the word 'welcome', the hostname, the OS version or the "
            "organization's identity, since those help an attacker and weaken the "
            "notice. Remove the escape sequences (\\S, \\r, \\m) that print "
            "system version details. Set ownership: `sudo chown root:root "
            "/etc/issue && sudo chmod 644 /etc/issue`. Note that some packages "
            "regenerate this file on upgrade, so re-check after distribution "
            "upgrades."
        ),
        cis="CIS 1.7.1 Command Line Warning Banners",
        cwe="",
        location="/etc/issue",
        severity="low",
    ),
    "BANN-7130": HostControl(
        control_id="NARVY-HOST-BANN-002",
        title="Remote login banner contains no legal notice",
        description=(
            "The banner presented to remote connections has no authorized-use "
            "notice. This is the one that faces the internet, so it is the one "
            "that matters for stating that access is restricted before a "
            "connection is authenticated. As shipped it also discloses the "
            "distribution and version to any unauthenticated client that opens a "
            "connection."
        ),
        remediation=(
            "Put the same approved authorized-use notice in /etc/issue.net, with "
            "no hostname, OS version or company identity, and no escape "
            "sequences. Make the remote shell daemon actually serve it: set "
            "`Banner /etc/issue.net` in /etc/ssh/sshd_config, validate with `sudo "
            "sshd -t`, then `sudo systemctl reload ssh`. Set `sudo chown "
            "root:root /etc/issue.net && sudo chmod 644 /etc/issue.net`. Verify "
            "from another machine: `ssh -o PreferredAuthentications=none "
            "<host>` must print the notice before any prompt."
        ),
        cis="CIS 1.7.2 Remote Login Warning Banner",
        cwe="",
        location="/etc/issue.net",
        severity="low",
    ),

    "ACCT-9622": HostControl(
        control_id="NARVY-HOST-ACCT-001",
        title="Process accounting is disabled",
        description=(
            "The host does not record which commands were executed, by which "
            "user, and when. During an investigation there is then no way to "
            "reconstruct what an attacker ran after gaining access, or to prove "
            "what an administrator did. Shell history is not a substitute: it is "
            "user-writable, trivially cleared, and absent entirely for "
            "non-interactive execution."
        ),
        remediation=(
            "Install and enable process accounting: `sudo apt install acct && "
            "sudo systemctl enable --now acct`. Read the records with `lastcomm` "
            "(commands executed), `sa` (summaries) and `ac` (connect time). "
            "Accounting files grow, so confirm rotation is in place for "
            "/var/log/account/pacct and size the filesystem accordingly. On a "
            "host that already has a full audit subsystem configured with "
            "execve rules, that provides richer coverage and this is largely "
            "redundant, so pick one and know which."
        ),
        cis="CIS 4.1.x Process Accounting",
        cwe="CWE-778",
        location="process accounting service",
        severity="low",
    ),
    "ACCT-9628": HostControl(
        control_id="NARVY-HOST-ACCT-002",
        title="Audit subsystem is not collecting security events",
        description=(
            "The kernel audit subsystem is not running or has no rules loaded, so "
            "security-relevant events are not recorded: privilege escalation, "
            "changes to /etc/passwd and /etc/shadow, loaded kernel modules, "
            "authentication file edits. These are exactly the events that reveal "
            "a compromise, and they are the ones no other log source captures. "
            "Their absence does not let an attacker in, but it means you will not "
            "be able to tell what happened, or prove it did not."
        ),
        remediation=(
            "Install and enable the audit daemon: `sudo apt install auditd "
            "audispd-plugins && sudo systemctl enable --now auditd`. Add rules in "
            "/etc/audit/rules.d/hardening.rules covering at minimum:\n"
            "  -w /etc/passwd -p wa -k identity\n"
            "  -w /etc/shadow -p wa -k identity\n"
            "  -w /etc/sudoers -p wa -k scope\n"
            "  -w /etc/sudoers.d/ -p wa -k scope\n"
            "  -w /var/log/sudo.log -p wa -k actions\n"
            "  -a always,exit -F arch=b64 -S execve -F euid=0 -k rootcmd\n"
            "  -e 2   # make the rules immutable until reboot\n"
            "Load them with `sudo augenrules --load` and check with `sudo auditctl "
            "-l`. Set `max_log_file_action = keep_logs` and size "
            "/var/log/audit appropriately; the `-e 2` line must be last. Ship the "
            "audit log off-host, since local-only audit records are erasable by the "
            "attacker they are meant to catch. Query with `ausearch -k rootcmd`."
        ),
        cis="CIS 4.1.x System Auditing",
        cwe="CWE-778",
        location="/etc/audit/rules.d/",
        severity="low",
    ),

    "FINT-4350": HostControl(
        control_id="NARVY-HOST-FINT-001",
        title="No file integrity monitoring in place",
        description=(
            "Nothing on this host detects unauthorized changes to system "
            "binaries, configuration or startup files. Persistence after a "
            "compromise almost always means writing to disk: a modified binary, "
            "a new service unit, an added cron job, an extra authorized key. "
            "Without a baseline to compare against, those changes stay invisible "
            "indefinitely. This is a detection gap, not an open door: it does not "
            "let an attacker in, it lets one stay."
        ),
        remediation=(
            "Install an integrity checker and baseline it: `sudo apt install "
            "aide aide-common`, then `sudo aideinit` (slow on first run), and "
            "move the database into place with `sudo mv "
            "/var/lib/aide/aide.db.new /var/lib/aide/aide.db`. Run checks on a "
            "schedule (`sudo aide --check`) via a systemd timer and alert on "
            "output. Two things decide whether this is useful: cover the paths "
            "that matter in /etc/aide/aide.conf (/bin, /sbin, /usr/bin, /usr/sbin, "
            "/etc, /boot, systemd unit directories, root's authorized_keys), and "
            "keep the baseline database off-host or read-only, because an "
            "attacker with root will otherwise just re-baseline it. Update the "
            "baseline deliberately after every legitimate change, or the alerts "
            "become noise and get ignored."
        ),
        cis="CIS 1.3.x Filesystem Integrity Checking",
        cwe="CWE-354",
        location="file integrity monitoring",
        severity="low",
    ),

    "TOOL-5002": HostControl(
        control_id="NARVY-HOST-TOOL-001",
        title="Host is configured manually with no automation",
        description=(
            "No configuration management tooling is present, so this host's state "
            "exists only as the accumulated result of manual changes. Nothing "
            "declares what the configuration should be, so drift is undetectable, "
            "a rebuild cannot reproduce it, and a hardening fix applied here does "
            "not reach the next server. Security-wise the consequence is "
            "practical: manually maintained hosts diverge, and the divergence is "
            "where the unpatched, misconfigured one hides."
        ),
        remediation=(
            "Put this host's configuration in version control and apply it with a "
            "configuration management tool. Ansible is the lightest starting "
            "point for a small estate since it needs nothing installed on the "
            "target beyond a remote shell and Python. Start narrow rather than "
            "boiling the ocean: codify the items in this report (firewall rules, "
            "remote shell config, package baseline, audit rules) as a playbook, "
            "run it in check mode (`ansible-playbook --check --diff`) against "
            "this host to surface drift, then run it for real. Once it is "
            "reproducible, run it on a schedule so drift is corrected rather than "
            "merely reported. Treat the repository as production: review changes, "
            "and keep secrets in a vault rather than in the playbook."
        ),
        cis="",
        cwe="",
        location="configuration management",
        severity="low",
    ),

    "KRNL-6000": HostControl(
        control_id="NARVY-HOST-KRNL-001",
        title="Kernel parameters differ from a hardened baseline",
        description=(
            "Several kernel tunables are at defaults chosen for compatibility "
            "rather than security. The gaps that matter in practice: kernel "
            "pointers and dmesg readable by unprivileged users, which hands an "
            "attacker the addresses needed to turn a memory bug into a working "
            "local privilege escalation; ptrace unrestricted, letting any process "
            "read another process of the same user, including its in-memory "
            "secrets; core dumps from setuid binaries, which can write "
            "credentials to disk; and IP redirects/source routing accepted, which "
            "allows route manipulation."
        ),
        remediation=(
            "Create /etc/sysctl.d/60-hardening.conf with:\n"
            "  kernel.kptr_restrict = 2\n"
            "  kernel.dmesg_restrict = 1\n"
            "  kernel.yama.ptrace_scope = 1\n"
            "  kernel.sysrq = 0\n"
            "  fs.suid_dumpable = 0\n"
            "  fs.protected_hardlinks = 1\n"
            "  fs.protected_symlinks = 1\n"
            "  net.ipv4.conf.all.accept_redirects = 0\n"
            "  net.ipv4.conf.all.send_redirects = 0\n"
            "  net.ipv4.conf.all.accept_source_route = 0\n"
            "  net.ipv4.conf.all.rp_filter = 1\n"
            "  net.ipv4.conf.all.log_martians = 1\n"
            "  net.ipv4.tcp_syncookies = 1\n"
            "  net.ipv6.conf.all.accept_redirects = 0\n"
            "  net.ipv6.conf.all.accept_ra = 0\n"
            "Apply with `sudo sysctl --system` and verify each with `sysctl "
            "<key>`. Two cautions: `ptrace_scope = 1` breaks debuggers and "
            "profilers attaching to already-running processes, and "
            "`accept_ra = 0` breaks IPv6 autoconfiguration, so skip those two if "
            "the host needs them. Settings applied only with `sysctl -w` are lost "
            "on reboot; the file is what makes them stick."
        ),
        cis="CIS 3.x Network and Kernel Parameters",
        cwe="CWE-1188",
        location="/etc/sysctl.d/",
        severity="low",
    ),

    "HRDN-7222": HostControl(
        control_id="NARVY-HOST-HRDN-001",
        title="Compilers are installed and usable by any local user",
        description=(
            "Compilers are present on this production host and executable by "
            "every local user. After gaining a foothold, a common next step is "
            "compiling a local privilege-escalation exploit on the target, and "
            "having a compiler already there removes the need to transfer a "
            "binary in, which is the step most likely to be noticed or blocked. "
            "A production server that only runs software built elsewhere has no "
            "reason to be able to build anything."
        ),
        remediation=(
            "Best option: remove the build toolchain from production entirely with "
            "`sudo apt purge gcc g++ make build-essential cc` (verify nothing "
            "depends on it first: some packages compile modules at install or "
            "kernel-update time, so check with `apt -s purge` before committing). "
            "Build artifacts belong in CI or a build host, not here. If a "
            "compiler must stay, restrict it to root: `sudo chmod 750 "
            "/usr/bin/gcc /usr/bin/cc /usr/bin/g++ /usr/bin/make` and `sudo chown "
            "root:root` the same paths. Sweep for what is actually installed "
            "first: `ls -l /usr/bin/{gcc*,cc,g++*,make,as,ld} 2>/dev/null`. Note "
            "this raises the bar rather than closing the door, since an interpreter, "
            "or a binary uploaded ready-made, achieves the same thing."
        ),
        cis="CIS 1.x Compiler Restriction",
        cwe="CWE-250",
        location="/usr/bin/gcc",
        severity="low",
    ),
    "HRDN-7230": HostControl(
        control_id="NARVY-HOST-HRDN-002",
        title="No malware or rootkit detection installed",
        description=(
            "Nothing on this host scans for known malicious binaries, rootkits, "
            "or the local artefacts they leave behind: hidden processes, "
            "modified system binaries, suspicious startup entries. Detection here "
            "is signature-based and will miss anything targeted, so it is not a "
            "defence. It is a cheap catch for commodity, opportunistic "
            "compromises, which is what actually hits an exposed Linux server."
        ),
        remediation=(
            "Install a rootkit checker and run it on a schedule: `sudo apt "
            "install rkhunter && sudo rkhunter --propupd && sudo rkhunter "
            "--check --skip-keypress`, wired into a weekly systemd timer with "
            "output alerted, not just written to a file nobody reads. Baseline it "
            "(`--propupd`) only on a host you believe is clean, and re-baseline "
            "after legitimate package updates or the report fills with false "
            "positives and stops being read. Add `chkrootkit` for a second "
            "opinion, and `clamav` if this host stores or relays user-supplied "
            "files. Do not treat any of this as your primary control: patching, "
            "the firewall and key-only remote access do far more."
        ),
        cis="",
        cwe="",
        location="malware detection tooling",
        severity="low",
    ),
}


def lookup(test_id: str) -> Optional[HostControl]:
    """Control for an engine test id, or None. Callers must keep emitting the
    raw finding for an unknown id rather than dropping it."""
    if not test_id:
        return None
    return HOST_CONTROLS.get(test_id.strip().upper())
