# Copyright (C) 2026 Percona LLC
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""Install Percona Server for MongoDB from Percona's official OS packages.

First (and, for now, only) implementation of
:class:`~app.extensions.apps.om_bootstrap.strategy.InstallStrategy` — Ubuntu and Rocky
Linux only, matching the phase-1 OS scope. ``DockerInstallStrategy`` and
``PodmanInstallStrategy`` are future siblings of this module, implementing the same
protocol.

Every per-host step here is package-manager-specific (``apt`` vs. ``dnf``), which
is exactly what the strategy boundary is for: :meth:`PackagesInstallStrategy.plan_steps`
returns the same step *names* regardless of OS, so the stepper never branches on
OS — only :meth:`PackagesInstallStrategy.build_step` does, once, per step.

Data path, log path, port and bind IP all come from :class:`BootstrapSpec`.
Per-member election settings (priority, votes, hidden, delayed) come from
``spec.member_configs``. TLS is still future scope, same as encryption at rest
(``security.enableEncryption``/``encryptionKeyFile``) — ``_mongod_config``
below writes only ``security.authorization``/``keyFile`` (intra-cluster auth),
never an encryption block, so a run today gets neither.

Rollback never touches a MongoDB this run did not install: ``pre_check``
refuses a host that already has one (:data:`CONFIG_PATH`, a non-empty
``spec.data_path``, or ``mongod`` on ``PATH`` or in :data:`EXTRA_MONGOD_DIRS`),
``install_package`` then writes this run's id to :data:`OWNERSHIP_MARKER_PATH`
before installing anything, and every rollback step is a no-op on a host whose
marker does not hold this run's id. The marker outlives a successful run, so a
later run that fails ``pre_check`` on the same host and rolls back leaves the
earlier run's MongoDB intact.

Every step that needs root also carries a ``rootless_command``, which a host
carrying :data:`~app.extensions.apps.om_bootstrap.strategy.ROOTLESS_RECORD_PATH`
runs instead, as the agent's own user, through what the one-time root step set up
there: PackageKit and a polkit rule for the packages, and a ``pmm-mongod@<port>``
unit that runs as ``mongod`` and reads its config and keyFile from
:data:`HANDOVER_DIR`. That host gets a different layout: no ``/etc/mongod.conf``,
no ``mongod.service``, one instance per port, and the ownership marker in the
instance's own hand-over directory.
"""

import base64
import hashlib
import json
import posixpath
import shlex

from app.extensions.apps.om_bootstrap.strategy import (
    BootstrapSpec,
    CREATE_ADMIN_USER_STEP,
    HostBootstrapState,
    MemberConfig,
    OperatingSystem,
    ROOTLESS_RECORD_PATH,
    StepAction,
    StepStatus,
)

#: The step that only inspects the host, so a retry fails the same way.
PRE_CHECK = "pre_check"
#: The first step that changes what rollback undoes; see ``has_anything_to_roll_back``.
INSTALL_PACKAGE = "install_package"

#: Where every step here reads or writes the shared keyFile — planted by the
#: ``distribute_keyfile`` step, ahead of ``configure_mongod``. Fixed, not a
#: :class:`BootstrapSpec` field — keyFile *content* is per-run, but where it
#: lands on disk isn't something the Configure step exposes.
KEY_FILE_PATH = "/etc/mongod.key"

#: Where the packaged mongod's own config file lives on both supported OSes.
#: Fixed for the same reason as :data:`KEY_FILE_PATH`.
CONFIG_PATH = "/etc/mongod.conf"

#: Written by ``install_package``, holding the run's id, once ``pre_check`` has
#: proven the host had no MongoDB of its own. Every rollback step first checks
#: that it holds its own run's id, so rolling back a host this run never
#: installed on removes nothing; ``remove_data``, the last rollback step,
#: deletes it.
OWNERSHIP_MARKER_PATH = "/etc/mongod.om-bootstrap"

#: The packages ``percona-server-mongodb`` pulls in, as an awk regex over package
#: names. apt's unused list can hold anything orphaned on the host, so rollback
#: purges only the PSMDB packages in it.
_PSMDB_PACKAGES_ERE = "^percona-(server-mongodb-|mongodb-mongosh$|telemetry-agent$)"

#: Matches the packaged ``mongod.service``'s own ``PIDFile=`` on both supported
#: OSes. PSMDB 7.0's unit is ``Type=forking``, so this has to agree with it
#: exactly — see :meth:`PackagesInstallStrategy._configure_mongod`. 8.0's unit has
#: no ``PIDFile=`` and runs mongod in the foreground, so it is inert there. Fixed
#: for the same reason as :data:`KEY_FILE_PATH`.
PID_FILE_PATH = "/var/run/mongod.pid"

#: Where ``pre_check`` looks for an existing ``mongod`` besides ``PATH``. Steps run
#: under ``sudo``, whose ``secure_path`` (``/sbin:/bin:/usr/sbin:/usr/bin`` on both
#: supported OSes) leaves out where a tarball install usually lands, so
#: ``command -v`` alone passes a host with ``/usr/local/bin/mongod`` and an install
#: would put a second ``mongod`` beside it. Shell glob patterns: ``*`` is expanded
#: on the host, everything else is matched literally.
EXTRA_MONGOD_DIRS = ("/usr/local/bin", "/opt/*/bin")

#: How many lines of ``mongod``'s journal :func:`_mongod_diagnostics` prints.
JOURNAL_TAIL_LINES = 5

#: The awk program :func:`_mongod_diagnostics` reads ``mongod``'s JSON log with.
#: Each line becomes ``msg: error``, cut to 200 characters, and the last three
#: with severity ``E`` or ``F`` are printed, or the last three lines when none has.
#: ``error`` is the line's ``errmsg`` string field, else its ``error``, else its
#: ``reason``, which is where mongod says ``Address already in use`` or
#: ``DBPathInUse``; a line without ``msg`` is only cut. POSIX awk, so mawk on
#: Ubuntu and gawk on Rocky run it alike.
_MONGOD_LOG_AWK = r"""
function field(line, key,   at) {
  at = index(line, "\"" key "\":\"")
  if (!at) return ""
  line = substr(line, at + length(key) + 4)
  match(line, /^([^"\\]|\\.)*/)
  return substr(line, 1, RLENGTH)
}
function brief(line,   msg, why) {
  msg = field(line, "msg")
  if (msg == "") return substr(line, 1, 200)
  why = field(line, "errmsg")
  if (why == "") why = field(line, "error")
  if (why == "") why = field(line, "reason")
  if (why != "") msg = msg ": " why
  return substr(msg, 1, 200)
}
{ seen[NR] = brief($0) }
/"s":"[EF]"/ { errors[++n] = seen[NR] }
END {
  if (n) { for (i = (n > 3 ? n - 2 : 1); i <= n; i++) print errors[i] }
  else { for (i = (NR > 3 ? NR - 2 : 1); i <= NR; i++) print seen[i] }
}
"""

#: How long a step waits for a (re)started mongod to answer, in seconds.
#: ``systemctl restart`` returning does not mean it does: PSMDB 8.0's unit sets
#: ``MONGODB_CONFIG_OVERRIDE_NOFORK=1`` and has no ``Type=``, so it is ``simple``
#: and returns as soon as the process starts, about two seconds before mongod
#: listens.
MONGOD_READY_WAIT_S = 60

#: How long one readiness ping may run, in seconds. mongosh's socket timeout
#: defaults to none, so a mongod that accepts the connection but stalls on the
#: command would otherwise hold the ping until the step's own timeout kills it.
MONGOD_PING_TIMEOUT_S = 10

#: How long ``enable_auth`` allows for writing the config and ``systemctl restart
#: mongod``, in seconds, on top of the readiness wait that follows them.
MONGOD_RESTART_ALLOWANCE_S = 60

#: Minimum free space at ``spec.data_path`` ``pre_check`` requires, in bytes.
#: 5 GiB — generous for phase-1's single-member/three-member replica sets, not a
#: sized-for-production figure.
MIN_DATA_DISK_BYTES = 5 * 1024 * 1024 * 1024

#: Bytes in a GiB, the unit ``pre_check`` reports free space in.
GIB = 1024 * 1024 * 1024

#: Roles PMM's ``mongodb_exporter`` needs, granted to the user
#: ``create_pmm_monitoring_user`` creates — ``clusterMonitor`` for replication/
#: server-status metrics, ``read`` on ``local`` for oplog metrics. The same
#: minimum PMM's own client-side setup docs grant a manually-created monitoring
#: user.
PMM_MONITORING_USER_ROLES = [
    {"role": "clusterMonitor", "db": "admin"},
    {"role": "read", "db": "local"},
]

#: Roles granted to the customer's own administrator, which ``create_admin_user``
#: creates when the run asks for one.
ADMIN_USER_ROLES = [{"role": "root", "db": "admin"}]

#: How long ``create_pmm_monitoring_user``'s driver waits for a primary to exist
#: before giving up, in milliseconds.
#:
#: This is a wait for an *election*, not for a network round trip. ``rs.initiate``
#: returns as soon as the config is accepted, and the first election follows it by
#: whatever ``electionTimeoutMillis`` and the members' own timers work out to -
#: measured at 11s on a three-member set on a real deployment, against a 10s
#: default election timeout. 30s leaves room for a member that is slow to answer
#: its first heartbeat without waiting so long that a genuinely broken set holds
#: the step past its own dispatch timeout.
PRIMARY_SELECTION_TIMEOUT_MS = 30_000

#: Where ``mongosh --port`` connects. Every local mongosh call here relies on it,
#: so ``bindIp`` always has to reach it.
LOOPBACK_ADDRESS = "127.0.0.1"

#: ``bindIp`` entries that already reach :data:`LOOPBACK_ADDRESS`. The wildcards
#: must never get it added: beside ``127.0.0.1``, mongod refuses to start with
#: ``0.0.0.0`` (``Address already in use``) and listens on loopback alone with ``*``.
_REACHES_LOOPBACK = frozenset({"0.0.0.0", "*", LOOPBACK_ADDRESS, "localhost"})  # noqa: S104 # nosec B104

#: On a host with the root step: one ``<port>`` directory per instance, setgid group
#: ``mongod``, where the agent writes the instance's ``mongod.conf``, ``keyfile``,
#: ``dirs`` (directories the unit creates as ``mongod``) and ``purge`` (what
#: ``pmm-mongod-purge@<port>`` deletes), plus the ownership marker and the
#: ``enabled`` file the boot starter reads.
HANDOVER_DIR = "/var/lib/pmm-agent/mongod"

#: Where ``pmm-mongod@<port>`` copies the keyFile to, as ``mongod`` and mode 400:
#: mongod refuses a keyFile its group can read, which the hand-over copy must be.
ROOTLESS_KEY_FILE_PATH = "/run/mongodb/pmm-{port}/keyfile"

#: Where ``pmm-mongod@<port>`` leaves the last error lines of mongod's log when it
#: stops on a failure, readable by the agent.
ROOTLESS_LAST_ERROR_PATH = "/run/mongodb/pmm-{port}/last-error"

#: Where ``pmm-operations-port@<action>-<port>``, the root step's port helper,
#: leaves its last answer for a port, readable by the agent.
PORT_RESULT_PATH = "/run/pmm-operations/port-{port}"


def _psmdb_channel(mongodb_version: str) -> str:
    """Turn ``"8.0"`` (or ``"8.0.4"``) into the channel name ``"psmdb-80"``.

    Uses only the first two dot-separated components: PMM's own
    ``TriggerHostBootstrapRequest.mongodb_version`` field docs a full patch
    version as a valid example (``"7.0.8"``) and pmm-managed passes it through
    unchanged (``managed/services/om/inventory.go``), so this has to accept
    one: naively stripping every dot from ``"7.0.14"`` produced the
    nonexistent channel ``"psmdb-7014"`` instead of ``"psmdb-70"`` (confirmed
    against a live ``percona-release enable``: "Specified repository does not
    exist"). PSMDB does not ship parallel repos per patch version, matching
    the request field's own "only the major version selects the install
    source" comment.

    :param mongodb_version: A dotted version, major.minor (``"8.0"``) or
        major.minor.patch (``"8.0.4"``).
    :return: The channel name ``percona-release setup`` expects.
    """
    major_minor = ".".join(mongodb_version.split(".")[:2])
    return f"psmdb-{major_minor.replace('.', '')}"


def _shell_step(body: str, *, timeout_s: int = 30) -> StepAction:
    """Build a ``StepAction`` running ``body`` through ``sh -c``.

    :param body: The shell script to run on the host.
    :param timeout_s: How long the step may run, in seconds.
    :return: The step action.
    """
    return StepAction(command=["sh", "-c", body], timeout_s=timeout_s)


def _yaml_str(value: str) -> str:
    """Render ``value`` as a quoted YAML scalar.

    YAML types a bare scalar by its content: ``#...`` is a comment, ``null`` is
    null, ``[a,b]`` a sequence, ``*x`` an alias, ``0x10`` an integer. An operator
    naming a path or an address containing any of those would get a config mongod
    misreads or refuses, with nothing saying why. ``json.dumps`` gives a
    double-quoted scalar with the escaping YAML expects, since JSON string syntax is
    a subset of YAML's, and it escapes control characters, so no value can add a
    line to the file.

    :param value: The string to emit.
    :return: ``value`` double-quoted and escaped, so YAML reads it as a string
        whatever its content.
    """
    return json.dumps(value)


def _with_loopback(bind_ip: str) -> str:
    """Add :data:`LOOPBACK_ADDRESS` to a ``bindIp`` value that does not reach it.

    :param bind_ip: A comma-separated ``bindIp`` value.
    :return: ``bind_ip`` with :data:`LOOPBACK_ADDRESS` in front, unless it already
        reaches it.
    """
    if _REACHES_LOOPBACK.intersection(bind_ip.lower().split(",")):
        return bind_ip
    return f"{LOOPBACK_ADDRESS},{bind_ip}"


def _glob_word(pattern: str) -> str:
    """Quote a path pattern for the shell, leaving its ``*`` wildcards live.

    :param pattern: A path that may contain ``*``.
    :return: The pattern as one shell word: every literal part quoted, every ``*``
        left for the shell to expand.
    """
    return "*".join(shlex.quote(part) if part else "" for part in pattern.split("*"))


def _existing_mongod_check() -> str:
    """Build the ``pre_check`` lines refusing a host that already has a ``mongod``.

    ``command -v`` finds one on ``PATH``; :data:`EXTRA_MONGOD_DIRS` covers where a
    tarball install lands outside ``sudo``'s ``secure_path``. The message names
    where it was found, so the operator knows which install to look at. A pattern
    that matches nothing stays a literal word, and the ``-x`` test rejects it.

    :return: The shell lines.
    """
    candidates = " ".join(
        _glob_word(posixpath.join(directory, "mongod"))
        for directory in EXTRA_MONGOD_DIRS
    )
    return "\n".join(
        [
            f'for m in "$(command -v mongod 2>/dev/null || true)" {candidates}; do',
            '  if [ -n "$m" ] && [ -x "$m" ]; then',
            '    echo "pre_check: mongod is already installed at $m" >&2; exit 1',
            "  fi",
            "done",
        ]
    )


#: Turns one line of ``ss -p`` output into ``pid N, NAME`` for the first process
#: it lists, e.g. ``users:(("mongod",pid=812,fd=11))`` into ``pid 812, mongod``.
_SS_HOLDER_SED = r's/.*users:(("\([^"]*\)",pid=\([0-9]*\).*/pid \2, \1/p'


def _port_free_check(port: int) -> str:
    """Build the ``pre_check`` lines refusing a port something already listens on.

    A taken port otherwise surfaces only at ``start_service``, after the package
    is installed, where systemd's account of it is "see journalctl" and the real
    reason, ``Address already in use``, stays in mongod's own log on the node.

    ``ss`` first, with ``-p`` so the message names the process holding the port
    (``pre_check`` runs as root, so every process is visible). A host without
    ``ss``, or whose ``ss`` refuses the arguments, falls back to the kernel's own
    tables, ``/proc/net/tcp`` and ``tcp6``, where the port is the hex after the
    local address's colon and state ``0A`` is ``LISTEN``; the holder is then the
    process with a descriptor on that socket's inode, when ``find`` can see one,
    named by its pid and by its command while that can still be read. Either way
    a listener on any address counts: one that overlaps ``bindIp`` at all still
    fails mongod's start.

    :param port: The port the new ``mongod`` will listen on.
    :return: The shell lines.
    """
    return "\n".join(
        [
            f"port={port}",
            "held=''",
            (
                "if command -v ss >/dev/null 2>&1 &&"
                ' listeners=$(ss -Hltnp "sport = :$port" 2>/dev/null); then'
            ),
            '  if [ -n "$listeners" ]; then',
            (
                f"    held=$(printf '%s\\n' \"$listeners\" | sed -n '{_SS_HOLDER_SED}'"
                " | head -n 1)"
            ),
            '    [ -n "$held" ] || held="held by an unknown process"',
            "  fi",
            "else",
            "  hex=$(printf '%04X' \"$port\")",
            "  for table in /proc/net/tcp /proc/net/tcp6; do",
            '    [ -r "$table" ] || continue',
            (
                '    inode=$(awk -v p=":$hex"'
                ' \'$2 ~ (p "$") && $4 == "0A" { print $10; exit }\' "$table")'
            ),
            '    [ -n "$inode" ] || continue',
            (
                "    fd=$(find /proc/[0-9]*/fd -maxdepth 1"
                ' -lname "socket:\\[$inode\\]" 2>/dev/null | head -n 1)'
            ),
            "    pid=${fd#/proc/}; pid=${pid%%/*}",
            '    if [ -n "$pid" ]; then',
            '      comm=$(cat "/proc/$pid/comm" 2>/dev/null || true)',
            '      held="pid $pid${comm:+, $comm}"',
            "    else",
            '      held="held by an unknown process"',
            "    fi",
            "    break",
            "  done",
            "fi",
            'if [ -n "$held" ]; then',
            '  echo "pre_check: port $port is already in use ($held)" >&2; exit 1',
            "fi",
        ]
    )


def _disk_space_check(spec: BootstrapSpec) -> str:
    """Build the ``pre_check`` lines refusing a data path with too little free space.

    Measured on the nearest existing ancestor of ``spec.data_path``: on a fresh
    host the path itself does not exist yet, and one the agent cannot look into
    counts as absent, so its parent is measured, which ``statfs`` allows.

    :param spec: The host's bootstrap spec; its data path is read.
    :return: The shell lines.
    """
    data_path = shlex.quote(spec.data_path)
    return "\n".join(
        [
            f"target={data_path}",
            'while [ ! -d "$target" ]; do target="$(dirname "$target")"; done',
            'avail=$(df --output=avail -B1 "$target" | tail -1)',
            (
                "case \"$avail\" in ''|*[!0-9]*) "
                'echo "pre_check: could not measure free space at $target" >&2; '
                "exit 1;; esac"
            ),
            f"tenths=$((avail * 10 / {GIB}))",
            (
                f'if [ "$avail" -lt {MIN_DATA_DISK_BYTES} ]; then '
                f'echo "pre_check: the data directory "{data_path}" needs at least '
                f"{MIN_DATA_DISK_BYTES // GIB} GiB free, but $target has "
                '$((tenths / 10)).$((tenths % 10)) GiB" >&2; exit 1; fi'
            ),
        ]
    )


def _mongod_diagnostics(spec: BootstrapSpec, *, rootless: bool = False) -> str:
    """Build a shell function printing why ``mongod`` did not come up, to stderr.

    A failed ``systemctl restart`` says only "see journalctl", and a failed
    ``ping`` only that nothing answered; the reason (``Address already in use``, a
    data directory it cannot lock) stays on the node unless the step prints it.
    Only stderr leaves the node, and only its last
    :data:`~app.extensions.apps.shared.om.task_failure.MAX_ERROR_DETAIL`
    characters reach the step's detail, so the output is kept short and the most
    specific part goes last: the unit's last :data:`JOURNAL_TAIL_LINES` journal
    messages, without their timestamp and host, then the end of mongod's own log
    as :data:`_MONGOD_LOG_AWK` shortens it - its last error and fatal entries,
    each down to its message and error, or its last lines when it has none.

    No part can fail the step: it is already failing, and the exit code that says
    so is the command's, not this function's.

    On a host with the root step the agent can read neither the journal nor
    mongod's log as a rule. There the unit's result and exit code come first,
    readable by anyone, then the last errors the unit saved from mongod's log when
    it stopped (:data:`ROOTLESS_LAST_ERROR_PATH`).

    :param spec: The host's bootstrap spec; its log path and port are read.
    :param rootless: Whether the step runs on a host with the root step.
    :return: The shell function definition, called ``om_mongod_why``.
    """
    awk = shlex.quote(_MONGOD_LOG_AWK)
    if rootless:
        last_error = shlex.quote(ROOTLESS_LAST_ERROR_PATH.format(port=spec.port))
        return "\n".join(
            [
                "om_mongod_why() {",
                '  echo "mongod did not come up; its unit and log say:" >&2',
                (
                    "  systemctl show -p Result -p ExecMainStatus"
                    f" {_rootless_unit(spec)} >&2 || true"
                ),
                f"  if [ -r {last_error} ]; then",
                f"    awk {awk} {last_error} >&2 || true",
                "  fi",
                "}",
            ]
        )
    log = shlex.quote(spec.log_path)
    return "\n".join(
        [
            "om_mongod_why() {",
            '  echo "mongod did not come up; its journal and log say:" >&2',
            "  if command -v journalctl >/dev/null 2>&1; then",
            (
                "    journalctl -u mongod --no-pager -o cat"
                f" -n {JOURNAL_TAIL_LINES} >&2 || true"
            ),
            "  fi",
            f"  if [ -r {log} ]; then",
            f"    tail -n 200 {log} | awk {awk} >&2 || true",
            "  fi",
            "}",
        ]
    )


def _run_or_explain(command: str) -> str:
    """Run ``command``, and if it fails, say why mongod is down before exiting.

    The command's own exit code is kept, so a step's failure still means what it
    did; only the diagnostics are added in front of it.

    :param command: One shell command.
    :return: The shell lines, which call ``om_mongod_why`` from
        :func:`_mongod_diagnostics`.
    """
    return "\n".join(
        [
            "rc=0",
            f"{command} || rc=$?",
            'if [ "$rc" -ne 0 ]; then om_mongod_why; exit "$rc"; fi',
        ]
    )


def _mongod_config(
    spec: BootstrapSpec, host: str, *, with_auth: bool, rootless: bool = False
) -> str:
    """Render ``mongod.conf``'s contents, with or without the security block.

    Shared by :meth:`PackagesInstallStrategy._configure_mongod` (``with_auth=False``,
    always — see its own docstring for why) and
    :meth:`PackagesInstallStrategy._enable_auth` (``with_auth=True``, turning it
    on afterward): every other setting is identical between the two, so this is
    the one place that has to stay in sync rather than two configs drifting
    apart under maintenance.

    :param spec: The host's bootstrap spec.
    :param host: The host this config is for, which decides its ``bindIp``: a
        member may name its own, and the run-level value applies to the rest.
    :param with_auth: Whether to include ``security.authorization``/``keyFile``.
    :param rootless: Whether the config is for ``pmm-mongod@<port>`` on a host
        with the root step, which runs mongod in the foreground as ``mongod``: no
        ``fork`` or pid file, and the keyFile where that unit copies it.
    :return: The full config file contents, including a trailing newline on the
        last section.
    """
    key_file = (
        ROOTLESS_KEY_FILE_PATH.format(port=spec.port) if rootless else KEY_FILE_PATH
    )
    security = (
        f"security:\n  authorization: enabled\n  keyFile: {key_file}\n"
        if with_auth
        else ""
    )
    process = (
        ""
        if rootless
        else f"processManagement:\n  fork: true\n  pidFilePath: {_yaml_str(PID_FILE_PATH)}\n"
    )
    member = spec.member_configs.get(host)
    bind_ip = _with_loopback((member.bind_ip if member else None) or spec.bind_ip)
    return (
        f"net:\n  bindIp: {_yaml_str(bind_ip)}\n  port: {spec.port}\n"
        f"storage:\n  dbPath: {_yaml_str(spec.data_path)}\n"
        f"{security}"
        f"replication:\n  replSetName: {_yaml_str(spec.replica_set_name)}\n"
        f"{process}"
        f"systemLog:\n  destination: file\n  path: {_yaml_str(spec.log_path)}\n  logAppend: true\n"
    )


def _mongosh_eval_command(js: str, port: int, *, timeout_s: int | None = None) -> str:
    """Build one ``mongosh --quiet --eval`` shell fragment.

    For JS that carries no secret only: ``--eval``'s argument is visible in
    ``ps`` for as long as mongosh runs. JS that embeds a secret goes through
    :func:`_mongosh_file` instead. ``shlex.quote`` on the whole ``--eval``
    argument, not string interpolation into a shell command, avoids the quoting
    bugs that show up trying to nest a JS string literal inside a shell
    double-quoted one.

    ``MONGOSH_DISABLE_ATLAS_LOCAL_DEV_CLUSTER_CHECK=1``: mongosh probes
    ``admin.atlascli`` (Atlas CLI local-deployment detection) as its first
    command on every connection, before anything in ``js`` runs. Against a
    member with authorization enabled and no credentials, that probe is
    rejected as unauthorized — set on every mongosh call so no caller has to
    reason about whether its member has authorization on yet.

    :param js: The JavaScript to evaluate.
    :param port: The port mongod listens on.
    :param timeout_s: Kill mongosh after this many seconds, through coreutils
        ``timeout``, which then exits 124 with nothing printed. ``None`` leaves
        mongosh to the step's own timeout.
    :return: The shell fragment, not yet wrapped in a :class:`StepAction`.
    """
    bound = "" if timeout_s is None else f"timeout {timeout_s} "
    return (
        "MONGOSH_DISABLE_ATLAS_LOCAL_DEV_CLUSTER_CHECK=1 "
        f"{bound}mongosh --quiet --port {port} --eval {shlex.quote(js)}"
    )


def _wait_for_mongod_command(port: int) -> str:
    """Build a shell fragment that pings mongod until it answers, or the wait is up.

    The pings in the loop are silent; one more after it decides the fragment's exit
    code, so a mongod that never answers fails with mongosh's own error rather than
    with the wait just running out. Each ping is killed after
    :data:`MONGOD_PING_TIMEOUT_S`, and a final ping killed that way says so, since
    mongosh prints nothing then. The wait is measured in seconds, not attempts,
    because each mongosh start takes about as long as the sleep between them.

    :param port: The port mongod listens on.
    :return: The fragment, braced so it can be chained with ``&&`` as one command.
    """
    ping = _mongosh_eval_command(
        "db.adminCommand('ping').ok", port, timeout_s=MONGOD_PING_TIMEOUT_S
    )
    timed_out = (
        f"ping to mongod on port {port} timed out after {MONGOD_PING_TIMEOUT_S}s"
    )
    return (
        f"{{ deadline=$(( $(date +%s) + {MONGOD_READY_WAIT_S} )); "
        f'while [ "$(date +%s)" -lt "$deadline" ] && ! {ping} >/dev/null 2>&1; '
        f'do sleep 1; done; {ping} || {{ ping_rc=$?; [ "$ping_rc" -ne 124 ] '
        f"|| echo '{timed_out}' >&2; (exit \"$ping_rc\"); }}; }}"
    )


def _wait_for_mongod_max_s() -> int:
    """Return how long :func:`_wait_for_mongod_command`'s fragment can run, at most.

    The loop's last ping can start just before the deadline and be followed by a
    sleep and the final ping, so the fragment can outlast
    :data:`MONGOD_READY_WAIT_S` by two pings and a second.

    :return: The bound in seconds, for a step's timeout to outlast.
    """
    return MONGOD_READY_WAIT_S + 2 * MONGOD_PING_TIMEOUT_S + 1


def _mongosh_eval(js: str, port: int) -> StepAction:
    """Build a ``StepAction`` running one ``mongosh --quiet --eval`` command.

    Every caller runs before authorization is ever enabled (see
    :meth:`PackagesInstallStrategy._configure_mongod`'s own docstring), so the
    command works unauthenticated on the member it runs on and this never has
    to route around MongoDB's localhost exception. ``enable_auth``
    (:meth:`PackagesInstallStrategy._enable_auth`) is what turns authorization
    on afterward, once ``create_pmm_monitoring_user`` has created the first
    user.

    ``create_pmm_monitoring_user`` deliberately does not use it: its write has
    to reach the elected primary, which the member it runs on need not be, so
    it goes through :func:`_mongosh_file` with a replica-set URI instead.

    :param js: The JavaScript to evaluate.
    :param port: The port mongod listens on.
    :return: The step action.
    """
    return _shell_step(_mongosh_eval_command(js, port), timeout_s=60)


def _replica_set_uri(hosts: list[str], spec: BootstrapSpec) -> str:
    """Build a connection string that resolves to whichever member is primary.

    Every member is listed as a seed and ``replicaSet`` names the set, so the
    driver discovers the topology and sends a write to the primary rather than
    to whichever member it happened to connect to. ``serverSelectionTimeoutMS``
    makes it *wait* for that primary to exist, which is the other half of the
    same problem - see :meth:`PackagesInstallStrategy._create_user`.

    Unauthenticated on purpose, like every other mongosh call here: these steps
    all run before ``enable_auth``.

    :param hosts: Every member of the set.
    :param spec: The run's bootstrap spec; its port and replica set name are read.
    :return: A ``mongodb://`` URI naming every member.
    """
    seeds = ",".join(f"{host}:{spec.port}" for host in hosts)
    return (
        f"mongodb://{seeds}/?replicaSet={spec.replica_set_name}"
        f"&serverSelectionTimeoutMS={PRIMARY_SELECTION_TIMEOUT_MS}"
    )


def _mongosh_file(js: str, port: int, uri: str | None = None) -> StepAction:
    """Build a ``StepAction`` running ``js`` from a private temp file.

    For JS that embeds a secret: ``--eval`` would put it in mongosh's argv,
    visible in ``ps``. The JS is written through a quoted heredoc to a
    ``mktemp`` file created under ``umask 077`` and removed on exit, and mongosh
    reads it with ``--file``. The heredoc delimiter cannot appear inside ``js``
    as a line of its own because every caller builds ``js`` from ``json.dumps``
    output, which never contains a raw newline.

    :param js: The JavaScript to run.
    :param port: The port mongod listens on. Ignored when ``uri`` is given,
        which carries its own ports.
    :param uri: Connect through this connection string instead of to the local
        member on ``port``. For a step that must reach the primary rather than
        the host it runs on; :func:`_replica_set_uri` builds one. It names no
        credentials, so it is no more secret than the argv it replaces.
    :return: The step action.
    """
    target = shlex.quote(uri) if uri else f"--port {port}"
    body = (
        "umask 077\n"
        "js=$(mktemp)\n"
        "trap 'rm -f \"$js\"' EXIT\n"
        "cat > \"$js\" <<'OM_BOOTSTRAP_JS'\n"
        f"{js}\n"
        "OM_BOOTSTRAP_JS\n"
        "MONGOSH_DISABLE_ATLAS_LOCAL_DEV_CLUSTER_CHECK=1 "
        f'mongosh --quiet {target} --file "$js"\n'
    )
    return _shell_step(body, timeout_s=60)


def _require_run_id(spec: BootstrapSpec, step_name: str) -> str:
    """Return ``spec.run_id`` as a string, for a step scoped to its run.

    :param spec: The host's bootstrap spec.
    :param step_name: The step being built, for the error message.
    :return: The run id.
    :raises ValueError: If ``spec.run_id`` is ``None``.
    """
    if spec.run_id is None:
        raise ValueError(f"{step_name} requires spec.run_id")
    return str(spec.run_id)


def _owned_body(body: str, run_id: str, marker: str) -> str:
    """Guard a rollback body so it does nothing on a host this run never installed.

    :param body: The rollback step's shell body.
    :param run_id: The run the rollback belongs to.
    :param marker: The ownership marker's path, already shell-quoted.
    :return: ``body``, run only when ``marker`` holds ``run_id``.
    """
    guard = f'[ "$(cat {marker} 2>/dev/null)" = {shlex.quote(run_id)} ]'
    return f"{guard} || exit 0\n{body}\n"


def _owned_step(
    body: str,
    run_id: str,
    *,
    timeout_s: int = 30,
    spec: BootstrapSpec | None = None,
    rootless_body: str | None = None,
    operations: tuple[str, ...] = (),
) -> StepAction:
    """Build a rollback step that does nothing on a host this run never installed.

    :param body: The rollback step's shell body.
    :param run_id: The run the rollback belongs to.
    :param timeout_s: How long the step may run, in seconds.
    :param spec: The host's bootstrap spec, which locates the rootless marker.
        Required with ``rootless_body``.
    :param rootless_body: The body on a host with the root step, guarded by the
        instance's own marker instead.
    :param operations: The socket helper requests ``rootless_body`` may send.
    :return: A step running ``body`` only when :data:`OWNERSHIP_MARKER_PATH`
        holds ``run_id``.
    """
    action = _shell_step(
        _owned_body(body, run_id, OWNERSHIP_MARKER_PATH), timeout_s=timeout_s
    )
    if rootless_body is None or spec is None:
        return action
    marker = shlex.quote(_rootless_marker(spec))
    return _with_rootless(
        action, _owned_body(rootless_body, run_id, marker), operations
    )


def _instance_dir(spec: BootstrapSpec) -> str:
    """Return the instance's hand-over directory on a host with the root step.

    :param spec: The host's bootstrap spec; its port names the instance.
    :return: The directory's path.
    """
    return posixpath.join(HANDOVER_DIR, str(spec.port))


def _rootless_marker(spec: BootstrapSpec) -> str:
    """Return where a host with the root step keeps this instance's ownership marker.

    :param spec: The host's bootstrap spec.
    :return: The marker's path, inside the instance's hand-over directory.
    """
    return posixpath.join(_instance_dir(spec), "om-bootstrap")


def _rootless_unit(spec: BootstrapSpec) -> str:
    """Return the systemd unit that runs this instance on a host with the root step.

    :param spec: The host's bootstrap spec; its port names the instance.
    :return: The unit's name.
    """
    return f"pmm-mongod@{spec.port}.service"


def _with_rootless(
    action: StepAction, body: str, operations: tuple[str, ...] = ()
) -> StepAction:
    """Add the body a host with the root step runs instead of ``action``'s.

    The body starts with :data:`_OPERATIONS_FUNCTIONS`, so it reaches the root
    step's grants the same way whichever front end the host has.

    :param action: The step as a root host runs it.
    :param body: The shell body for a host with the root step.
    :param operations: The socket helper requests ``body`` may send, which the
        step's grant names.
    :return: ``action`` with ``rootless_command`` and ``operations`` set; its
        timeout covers both.
    """
    return action.model_copy(
        update={
            "rootless_command": ["sh", "-c", f"{_OPERATIONS_FUNCTIONS}\n{body}"],
            "operations": list(operations),
        }
    )


def _rootless_config(
    spec: BootstrapSpec, host: str, *, with_auth: bool, step_name: str
) -> tuple[str, str]:
    """Build the lines handing the instance's config to ``pmm-mongod@<port>``.

    Through the socket helper, the config goes to root with its SHA-256 in the
    request, which the step's grant names, so the host writes only this content,
    where the agent cannot change it, and derives the directories mongod creates
    and purges from it. Through polkit, the agent writes ``mongod.conf``, readable
    by group ``mongod``, into the hand-over directory, plus ``dirs``, the data and
    log directories the unit creates as ``mongod`` before it starts, and ``purge``,
    what the purge unit deletes on rollback; the config beside its final name and
    then moved over it, so the unit never copies half a file.

    :param spec: The host's bootstrap spec.
    :param host: The host being configured, which decides its ``bindIp``.
    :param with_auth: Whether to include ``security.authorization``/``keyFile``.
    :param step_name: The step, named in the failure message.
    :return: The shell lines, and the socket helper request they send.
    """
    config = _mongod_config(spec, host, with_auth=with_auth, rootless=True)
    request = f"config apply {spec.port} {hashlib.sha256(config.encode()).hexdigest()}"
    instance = _instance_dir(spec)
    conf = shlex.quote(posixpath.join(instance, "mongod.conf"))
    data_path = shlex.quote(spec.data_path)
    log_dir = shlex.quote(posixpath.dirname(spec.log_path))
    socket = "\n".join(
        [
            "conf=$(mktemp)",
            f"cat > \"$conf\" <<'MONGOD_CONF'\n{config}MONGOD_CONF",
            f'if ! out=$(pmm-operations {request} < "$conf" 2>&1); then',
            f'  echo "{step_name}: $out" >&2; rm -f "$conf"; exit 1',
            "fi",
            'rm -f "$conf"',
        ]
    )
    handover = "\n".join(
        [
            "umask 0027",
            (
                f"printf '%s\\n' {data_path} {log_dir}"
                f" > {shlex.quote(posixpath.join(instance, 'dirs'))}"
            ),
            (
                f"printf '%s\\n' {data_path} {shlex.quote(spec.log_path)}"
                f" > {shlex.quote(posixpath.join(instance, 'purge'))}"
            ),
            f"cat > {conf}.new <<'MONGOD_CONF'\n{config}MONGOD_CONF",
            f"mv -f {conf}.new {conf}",
        ]
    )
    return f"if om_socket; then\n{socket}\nelse\n{handover}\nfi", request


#: What ``purge_package`` removes on a host with the root step: the packages its
#: polkit rule lets the agent remove.
_ROOTLESS_PACKAGES = (
    "percona-server-mongodb",
    "percona-server-mongodb-server",
    "percona-server-mongodb-mongos",
    "percona-server-mongodb-tools",
    "percona-mongodb-mongosh",
)


#: Reads one key of :data:`ROOTLESS_RECORD_PATH`, the last line naming it.
_RECORD_FUNCTION = (
    f'om_record() {{ sed -n "s/^$1=//p" {ROOTLESS_RECORD_PATH} | tail -n 1; }}'
)

#: What every rootless body starts with: the root step's grants as shell
#: functions, through polkit (``systemctl``, ``pkcon`` and the port unit) or,
#: where the record says ``frontend=socket``, through its socket helper
#: (``pmm-operations``), which reads the step's grant from the environment.
_OPERATIONS_FUNCTIONS = "\n".join(
    [
        _RECORD_FUNCTION,
        'om_socket() { [ "$(om_record frontend)" = socket ]; }',
        (
            'om_unit() { if om_socket; then pmm-operations "$1" "$2"; '
            'else systemctl "$1" "pmm-mongod@$2.service"; fi; }'
        ),
        (
            'om_purge() { if om_socket; then pmm-operations purge "$1"; '
            'else systemctl start "pmm-mongod-purge@$1.service"; fi; }'
        ),
        "om_port() {",
        '  if om_socket; then pmm-operations port "$1" "$2"; return; fi',
        (
            '  if systemctl start "pmm-operations-port@$1-$2.service" 2>/dev/null; '
            "then rc=0; else rc=$?; fi"
        ),
        (
            f'  cat "{PORT_RESULT_PATH.format(port="$2")}" 2>/dev/null'
            ' || echo "pmm-operations-port@$1-$2 failed"'
        ),
        '  return "$rc"',
        "}",
        (
            'om_packages() { if om_socket; then pmm-operations "$@"; '
            'else pkcon -p --noninteractive "$@"; fi; }'
        ),
    ]
)


def _port_helper(action: str, spec: BootstrapSpec, step_name: str) -> str:
    """Build the lines asking the root step's port helper to check, open or close a port.

    The helper runs as root, reached through ``om_port``: the unit
    ``pmm-operations-port@<action>-<port>`` polkit lets the agent start, or the
    socket helper. It checks the port against the range the root step allows,
    then opens it in firewalld and labels it for SELinux, or undoes only what it
    did itself, and answers in :data:`PORT_RESULT_PATH`, since the agent cannot
    read the journal. ``close`` never fails the step.

    :param action: ``check``, ``open`` or ``close``.
    :param spec: The host's bootstrap spec; its port is the one acted on.
    :param step_name: The step, named in the failure message.
    :return: The shell lines.
    """
    call = f"om_port {action} {spec.port}"
    if action == "close":
        return f'answer=$({call} 2>&1) || echo "{step_name}: $answer"'
    return "\n".join(
        [
            f"if ! answer=$({call} 2>&1); then",
            f'  echo "{step_name}: $answer" >&2; exit 1',
            "fi",
            'echo "$answer"',
        ]
    )


def _packages(arguments: str, step_name: str) -> str:
    """Build the lines running one package request, quiet unless it fails.

    Through ``om_packages``: ``pkcon`` or the socket helper, which both report a
    refusal or a failed transaction on stdout, so on failure the end of the
    output goes to stderr, where the step's detail reads it.

    :param arguments: The request (``refresh``, ``install NAME``), already
        shell-quoted, the same for both.
    :param step_name: The step, named in the failure message.
    :return: The shell lines.
    """
    return "\n".join(
        [
            "out=$(mktemp)",
            "trap 'rm -f \"$out\"' EXIT",
            f'if ! om_packages {arguments} >"$out" 2>&1; then',
            f'  echo "{step_name}: {arguments} failed:" >&2',
            '  tail -n 5 "$out" >&2; exit 1',
            "fi",
        ]
    )


class PackagesInstallStrategy:
    """Install Percona Server for MongoDB from Percona's Ubuntu/Rocky packages."""

    def plan_steps(self, spec: BootstrapSpec) -> list[str]:  # noqa: ARG002
        """Return this strategy's fixed per-host step names.

        Fixed rather than spec-dependent for phase 1: packages, Ubuntu or Rocky,
        no TLS. A spec asking for TLS would need this to grow a certificate step —
        not built here, since TLS is out of phase-1 scope.

        :param spec: The host's bootstrap spec.
        :return: Step names, in execution order.
        """
        return [
            PRE_CHECK,
            "configure_repository",
            INSTALL_PACKAGE,
            "distribute_keyfile",
            "configure_mongod",
            "start_service",
            "verify",
        ]

    def build_step(
        self,
        step_name: str,
        host: str,
        spec: BootstrapSpec,
        params: dict[str, str] | None = None,
    ) -> StepAction:
        """Build the action for one of :meth:`plan_steps`' names.

        :param step_name: One of :meth:`plan_steps`' names.
        :param host: The node name being bootstrapped. Used by ``configure_mongod``,
            whose ``bindIp`` may be this member's own address rather than the run's;
            every other step builds a command to run *on* ``host`` rather than one
            naming it, so they ignore it.
        :param spec: The host's bootstrap spec.
        :param params: ``{"key_file_content": ...}`` for ``distribute_keyfile``;
            ignored by every other step.
        :return: What the execution layer needs to run this step.
        :raises ValueError: If ``step_name`` is not one of :meth:`plan_steps`'
            names, ``spec.os`` is not a supported :class:`OperatingSystem`,
            ``distribute_keyfile`` is built without ``params["key_file_content"]``,
            or ``install_package`` is built without ``spec.run_id``.
        """
        builders = {
            "distribute_keyfile": lambda s: self._distribute_keyfile(s, params),
            PRE_CHECK: self._pre_check,
            "configure_repository": self._configure_repository,
            INSTALL_PACKAGE: self._install_package,
            "configure_mongod": lambda s: self._configure_mongod(s, host),
            "start_service": self._start_service,
            "verify": self._verify,
        }
        try:
            builder = builders[step_name]
        except KeyError:
            raise ValueError(
                f"{step_name!r} is not a PackagesInstallStrategy step; "
                f"expected one of {list(builders)}"
            ) from None
        return builder(spec)

    def _distribute_keyfile(
        self,
        spec: BootstrapSpec,
        params: dict[str, str] | None,
    ) -> StepAction:
        """Write the replica set's shared keyFile, owned by ``mongod`` and mode 400.

        Runs after ``install_package`` (so the ``mongod`` system user this chowns
        to already exists) and before ``configure_mongod``, which enables
        ``security.keyFile`` pointing at :data:`KEY_FILE_PATH`. The content comes
        from ``params`` rather than being generated here: keyFiles are generated
        once per run and persisted, encrypted, in PMM's Postgres — this strategy
        only ever plants the one copy the stepper hands it, transiently, at
        dispatch time (see
        :class:`~app.extensions.apps.om_bootstrap.strategy.InstallStrategy`'s docstring).

        The content travels base64-encoded through the shell builtin ``printf``,
        so it can never end a heredoc early or inject a command, and never
        appears in any process's argv. ``mongod`` ignores whitespace in a
        keyFile, so a trailing newline in the caller's content is harmless.

        :param spec: The host's bootstrap spec. Only its port is read, which names
            the instance's hand-over directory on a host with the root step.
        :param params: Must contain ``"key_file_content"``.
        :return: The step action.
        :raises ValueError: If ``params`` is missing ``"key_file_content"``.
        """
        if not params or "key_file_content" not in params:
            raise ValueError("distribute_keyfile requires params['key_file_content']")
        encoded = base64.b64encode(params["key_file_content"].encode()).decode("ascii")
        # Group mongod through the hand-over directory's setgid; the unit copies it
        # to mode 400 as mongod.
        key_file = shlex.quote(posixpath.join(_instance_dir(spec), "keyfile"))
        # Through the socket helper root keeps it, the SHA-256 the grant names.
        digest = hashlib.sha256(params["key_file_content"].encode()).hexdigest()
        request = f"keyfile apply {spec.port} {digest}"
        rootless = (
            "if om_socket; then\n"
            f"  if ! out=$(printf '%s' {shlex.quote(encoded)} | base64 -d | "
            f"pmm-operations {request} 2>&1); then\n"
            '    echo "distribute_keyfile: $out" >&2; exit 1\n'
            "  fi\n"
            "else\n"
            "  umask 0227\n"
            f"  printf '%s' {shlex.quote(encoded)} | base64 -d > {key_file}.new\n"
            f"  mv -f {key_file}.new {key_file}\n"
            "fi\n"
        )
        action = _shell_step(
            f"printf '%s' {shlex.quote(encoded)} | base64 -d | "
            f"install -m 400 -o mongod -g mongod /dev/stdin {KEY_FILE_PATH}"
        )
        return _with_rootless(action, rootless, (request,))

    def _pre_check(self, spec: BootstrapSpec) -> StepAction:
        """Verify OS, paths, and disk space before touching anything.

        The decided pre-checks — OS, path, disk space — all read-only and fast
        enough to run inline rather than as a background job:

        - **OS**: the OS's package manager is present.
        - **Path**: no MongoDB already lives on the host — no ``mongod`` on
          ``PATH`` or in :data:`EXTRA_MONGOD_DIRS`, no :data:`CONFIG_PATH`, and
          ``spec.data_path`` absent or empty. This is also what makes rollback
          safe: ``install_package`` claims the host for its run with
          :data:`OWNERSHIP_MARKER_PATH` only after this passed, and rollback
          removes nothing unless that marker holds its own run's id.
        - **Disk space**: at least :data:`MIN_DATA_DISK_BYTES` free on the
          filesystem ``spec.data_path`` will live on — that of its nearest
          existing ancestor, since on a fresh host the path itself does not
          exist yet. Walking up rather than falling straight back to ``/``
          matters once ``data_path`` sits under its own mount:
          ``/mnt/mongo/data`` can be absent while ``/mnt/mongo`` is a distinct,
          already-mounted volume. The loop terminates because ``dirname`` of
          ``/`` is ``/``.
        - **Port**: nothing listens on ``spec.port`` yet - see
          :func:`_port_free_check`.

        Each failed check names itself on stderr, and a free-space figure ``df``
        could not produce fails the check rather than passing it.

        :param spec: The host's bootstrap spec; its OS, data path and port are
            read.
        :return: The step action.
        """
        pkg_manager = self._require_package_manager(spec.os)
        data_path = shlex.quote(spec.data_path)
        body = "\n".join(
            [
                (
                    f"command -v {pkg_manager} >/dev/null 2>&1 || "
                    f'{{ echo "pre_check: {pkg_manager} not found" >&2; exit 1; }}'
                ),
                _existing_mongod_check(),
                (
                    f"if [ -e {CONFIG_PATH} ]; then "
                    f'echo "pre_check: {CONFIG_PATH} already exists" >&2; exit 1; fi'
                ),
                (
                    f'if [ -d {data_path} ] && [ -n "$(ls -A {data_path})" ]; then '
                    f'echo "pre_check: "{data_path}" is not empty" >&2; exit 1; fi'
                ),
                _disk_space_check(spec),
                _port_free_check(spec.port),
            ]
        )
        return _with_rootless(
            _shell_step(body),
            self._rootless_pre_check(spec),
            (f"port check {spec.port}",),
        )

    def _rootless_pre_check(self, spec: BootstrapSpec) -> str:
        """Build ``pre_check`` for a host with the root step.

        The agent cannot look inside ``mongod``'s directories there, so instead of
        "no MongoDB and an empty data directory" it checks what the root step
        recorded: that the port lies in the range it allows, which its port helper
        then checks as root (or, from a root step without one, that it prepared
        this port), that it enabled the requested series, that the data and log
        paths lie under directories it handed to ``mongod``, and that no instance
        PMM installed here already runs on this port or uses this data path. An installed package is expected: the root step itself refuses a host
        with a MongoDB of its own.

        :param spec: The host's bootstrap spec.
        :return: The shell body.
        """
        channel = _psmdb_channel(spec.mongodb_version)
        data_path = shlex.quote(spec.data_path)
        log_dir = shlex.quote(posixpath.dirname(spec.log_path))
        marker = shlex.quote(_rootless_marker(spec))
        return "\n".join(
            [
                (
                    'om_under() { p=$1; shift; for r in "$@"; do '
                    'case "$p/" in "$r"/*) return 0;; esac; done; return 1; }'
                ),
                "if om_socket; then",
                (
                    '  command -v pmm-operations >/dev/null 2>&1 || { echo "pre_check: '
                    'pmm-operations not found; the root step installs it" >&2; exit 1; }'
                ),
                "else",
                (
                    '  command -v pkcon >/dev/null 2>&1 || { echo "pre_check: pkcon '
                    'not found; the root step installs PackageKit" >&2; exit 1; }'
                ),
                "fi",
                # A root step without the port helper prepared fixed ports only.
                'range=$(om_record port_range)\nif [ -z "$range" ]; then',
                (
                    f'  case " $(om_record ports) " in *" {spec.port} "*) ;; *) '
                    f'echo "pre_check: the root step did not prepare port {spec.port}'
                    ' (it prepared: $(om_record ports))" >&2; exit 1;; esac'
                ),
                (
                    f'elif [ {spec.port} -lt "${{range%-*}}" ] || '
                    f'[ {spec.port} -gt "${{range#*-}}" ]; then'
                ),
                (
                    f'  echo "pre_check: port {spec.port} is outside the range the '
                    'root step allows ($range)" >&2; exit 1'
                ),
                "else",
                _port_helper("check", spec, PRE_CHECK),
                "fi",
                (
                    f'case " $(om_record series) " in *" {channel} "*) ;; *) '
                    f'echo "pre_check: the root step did not enable {channel}'
                    ' (it enabled: $(om_record series))" >&2; exit 1;; esac'
                ),
                (
                    f'if [ -e {marker} ]; then echo "pre_check: PMM already installed '
                    f'an instance on port {spec.port} here" >&2; exit 1; fi'
                ),
                (
                    f'case "/"{data_path}"/ /"{log_dir}"/" in */../*|*/./*) '
                    'echo "pre_check: the data and log paths must not contain . or .."'
                    " >&2; exit 1;; esac"
                ),
                (
                    f"om_under {data_path} $(om_record data_roots) || {{ "
                    f'echo "pre_check: the data path "{data_path}" is not under a '
                    'directory the root step prepared ($(om_record data_roots))" >&2; '
                    "exit 1; }"
                ),
                (
                    f"om_under {log_dir} $(om_record log_roots) || {{ "
                    f'echo "pre_check: the log directory "{log_dir}" is not under a '
                    'directory the root step prepared ($(om_record log_roots))" >&2; '
                    "exit 1; }"
                ),
                f"for used in {HANDOVER_DIR}/*/dirs; do",
                f'  if [ -r "$used" ] && grep -qxF {data_path} "$used"; then',
                (
                    f'    echo "pre_check: the data path "{data_path}" belongs to the '
                    'instance on port $(basename "$(dirname "$used")")" >&2; exit 1'
                ),
                "  fi",
                "done",
                _disk_space_check(spec),
                _port_free_check(spec.port),
            ]
        )

    def _configure_repository(self, spec: BootstrapSpec) -> StepAction:
        """Install ``percona-release`` and enable the requested PSMDB channel.

        :param spec: The host's bootstrap spec; its OS and MongoDB version are read.
        :return: The step action.
        :raises ValueError: If ``spec.os`` is not a supported :class:`OperatingSystem`.
        """
        channel = _psmdb_channel(spec.mongodb_version)
        if spec.os is OperatingSystem.UBUNTU:
            command = (
                "curl -fsSL -o /tmp/percona-release.deb "
                "https://repo.percona.com/apt/percona-release_latest.generic_all.deb && "
                "dpkg -i /tmp/percona-release.deb && "
                f"percona-release setup -y {shlex.quote(channel)}"
            )
        elif spec.os is OperatingSystem.ROCKY:
            command = (
                "dnf install -y "
                "https://repo.percona.com/yum/percona-release-latest.noarch.rpm && "
                f"percona-release setup -y {shlex.quote(channel)}"
            )
        else:
            raise ValueError(f"unsupported OperatingSystem: {spec.os!r}")
        # The root step enabled the series and pre_check confirmed it; the agent
        # may only refresh the package lists.
        rootless = _packages("refresh", "configure_repository")
        return _with_rootless(
            _shell_step(command, timeout_s=120), rootless, ("refresh",)
        )

    def _install_package(self, spec: BootstrapSpec) -> StepAction:
        """Claim the host for this run, then install ``percona-server-mongodb``.

        The marker, holding the run's id, goes first so a rollback of a
        half-finished install still cleans up. It is only ever written after
        ``pre_check`` proved the host had no MongoDB of its own — see the module
        docstring.

        :param spec: The host's bootstrap spec; its OS and run id are read.
        :return: The step action.
        :raises ValueError: If ``spec.run_id`` is ``None``.
        """
        run_id = _require_run_id(spec, INSTALL_PACKAGE)
        pkg_manager = self._require_package_manager(spec.os)
        install = "apt-get install -y" if pkg_manager == "apt-get" else "dnf install -y"
        installed = (
            "dpkg-query -W -f '${Status}' percona-server-mongodb 2>/dev/null"
            " | grep -q 'ok installed'"
            if pkg_manager == "apt-get"
            else "rpm -q percona-server-mongodb >/dev/null 2>&1"
        )
        instance = shlex.quote(_instance_dir(spec))
        # The new directory inherits group mongod and setgid from the hand-over
        # directory; a chmod by the agent, not in group mongod, would clear setgid.
        rootless = "\n".join(
            [
                "umask 0027",
                f"[ -d {instance} ] || mkdir {instance}",
                f"printf '%s\\n' {shlex.quote(run_id)} > {shlex.quote(_rootless_marker(spec))}",
                f"if ! {installed}; then",
                _packages("install percona-server-mongodb", INSTALL_PACKAGE),
                "fi",
            ]
        )
        action = _shell_step(
            f"printf '%s\\n' {shlex.quote(run_id)} > {OWNERSHIP_MARKER_PATH}\n"
            f"{install} percona-server-mongodb",
            timeout_s=300,
        )
        return _with_rootless(action, rootless, ("install percona-server-mongodb",))

    def _configure_mongod(self, spec: BootstrapSpec, host: str) -> StepAction:
        """Write ``mongod.conf`` enabling replication, with authorization left off.

        Deliberately does **not** set ``security.authorization``/``keyFile`` here,
        even though :data:`KEY_FILE_PATH` already exists on disk (planted by
        ``distribute_keyfile``, immediately before this step): MongoDB's localhost
        exception — the unauthenticated window a fresh member normally uses to
        bootstrap its first user — is unreliable once a replica set already has
        more than one member. Confirmed against a real multi-member run, not a
        theoretical concern: 40 consecutive, freshly-connected ``createUser``
        attempts all failed identically once the first one did, because the
        exception closes *permanently* for that mongod's whole lifetime the
        moment any privileged op on it fails once — not just for the one
        connection that failed it. Retrying, waiting for a stable primary, or
        avoiding mongosh's own extra connections none of it helped; the only
        reliable fix is to never need the exception at all. So authorization
        stays off through ``rs_initiate``/``create_pmm_monitoring_user``, and
        :meth:`_enable_auth` — a finalize step, dispatched only once that user
        already exists — turns it on afterward, per host.

        Also creates ``spec.data_path``, owned by ``mongod``, rather than
        assuming the package's own post-install already did — confirmed
        against a real failure that it does not: mongod exits immediately on
        first start with ``NonExistentPath: Data directory /var/lib/mongo not
        found``, and ``start_service`` (``systemctl restart``) reports
        success regardless, since ``Type=forking`` only waits for the initial
        fork, not for mongod's own startup logic to run, and 8.0's unit does not
        wait even for that (see :data:`MONGOD_READY_WAIT_S`). ``verify``, a step
        later, is what actually surfaces the failure — by then the run has
        already reported ``start_service`` as done.

        Creates each directory only when absent (``[ -d ... ] ||``), not
        unconditionally: ``install -d`` reapplies ``-m``/``-o``/``-g`` to a
        directory that already exists too, and a ``log_path`` of
        ``/var/log/mongod.log`` — a plausible operator value, and the mongod
        default on some layouts — has ``/var/log`` as its dirname. An
        unconditional ``install -d`` there hands the host's shared log
        directory to ``mongod:mongod`` at 750, breaking logging for
        everything else on the box.

        Sets ``processManagement.fork``/``pidFilePath`` for the same reason:
        PSMDB 7.0's packaged ``mongod.service`` is ``Type=forking``, so systemd
        waits for mongod itself to daemonize and write :data:`PID_FILE_PATH`.
        Without ``fork: true`` mongod runs in the foreground indefinitely —
        confirmed against a real run where mongod started and stayed healthy,
        but systemd's default 90s ``TimeoutStartSec`` elapsed waiting for a fork
        that was never coming and killed it, so ``verify`` found nothing
        listening on 27017 a step later, again after ``start_service`` had
        already reported success. 8.0's unit sets ``fork`` back to false with
        ``MONGODB_CONFIG_OVERRIDE_NOFORK=1`` and runs mongod in the foreground,
        so both settings are inert there.

        ``systemLog.path`` is required alongside ``fork: true`` — mongod refuses
        to start at all otherwise (``BadValue: --fork has to be used with
        --logpath or --syslog``), confirmed against a real run once the
        fork-without-a-logpath combination above was fixed. The unit's own
        ``STDOUT``/``STDERR`` redirects in ``/etc/default/mongod`` do not stand
        in for this: those capture only the pre-fork parent, which prints
        nothing once mongod backgrounds itself.

        Also creates ``spec.log_path``'s directory, owned by ``mongod``, the
        same way and for the same reason as ``spec.data_path`` above — a gap
        this one had until a real bootstrap run against a bare host (no
        pre-existing ``/var/log/mongo``, unlike the sandbox's own database
        topology images) confirmed it the same way: mongod's control process
        exits immediately (``Can't initialize rotatable log file :: caused by ::
        Failed to open <path>``) if the directory the configured log path names
        does not already exist, and ``start_service`` again reports success
        regardless, for the same reason. The package's own post-install cannot
        be assumed to have created it: it defaults to a directory
        (``/var/log/mongo`` on both Ubuntu and Rocky) that only matches
        ``spec.log_path`` by coincidence, and the wizard's own default
        (``/var/log/mongodb/mongod.log``) does not.

        :param spec: The host's bootstrap spec.
        :param host: The host being configured, which decides its ``bindIp``.
        :return: The step action.
        """
        config = _mongod_config(spec, host, with_auth=False)
        quoted_data_path = shlex.quote(spec.data_path)
        quoted_log_dir = shlex.quote(posixpath.dirname(spec.log_path))
        command = (
            f"{{ [ -d {quoted_data_path} ] || "
            f"install -d -m 750 -o mongod -g mongod {quoted_data_path} ; }} && "
            f"{{ [ -d {quoted_log_dir} ] || "
            f"install -d -m 750 -o mongod -g mongod {quoted_log_dir} ; }} && "
            f"cat > {CONFIG_PATH} <<'MONGOD_CONF'\n{config}MONGOD_CONF\n"
        )
        config_body, config_request = _rootless_config(
            spec, host, with_auth=False, step_name="configure_mongod"
        )
        rootless = "\n".join(
            [
                config_body,
                'if [ -n "$(om_record port_range)" ]; then',
                _port_helper("open", spec, "configure_mongod"),
                "fi",
            ]
        )
        # semanage takes about 15s to label a port on RHEL 8.
        return _with_rootless(
            _shell_step(command, timeout_s=120),
            rootless,
            (config_request, f"port open {spec.port}"),
        )

    def _start_service(self, spec: BootstrapSpec) -> StepAction:
        """Enable the ``mongod`` systemd unit and (re)start it on the config just written.

        Explicitly ``restart``, not ``enable --now``: ``install_package`` may have
        left ``mongod`` already running, and ``enable --now`` only starts a unit
        that is not already active. Against one the package started it is a
        no-op, so the process stays live on whatever config it booted with, which
        is the package's own default and carries no ``replication`` block. It
        therefore never picks up :meth:`_configure_mongod`'s rewrite of
        :data:`CONFIG_PATH` a step earlier, and ``verify`` right after only pings
        the server, so that does not catch it either.

        Whether the package pre-starts the service is not something this step
        needs to distinguish: Ubuntu's ``.deb`` postinst does, Rocky's ``%post``
        does not, and ``restart`` is correct for both, since restarting a unit
        that ``install_package`` never started behaves exactly like starting it.

        A failed restart prints mongod's journal and log errors before exiting
        with ``systemctl``'s own code - see :func:`_mongod_diagnostics`.

        :param spec: The host's bootstrap spec; its log path is read.
        :return: The step action.
        """
        action = _shell_step(
            f"{_mongod_diagnostics(spec)}\n"
            "systemctl enable mongod\n"
            f"{_run_or_explain('systemctl restart mongod')}\n",
            timeout_s=60,
        )
        # polkit grants no "enable": the root step's boot unit starts every
        # instance whose hand-over directory holds an "enabled" file.
        enabled = shlex.quote(posixpath.join(_instance_dir(spec), "enabled"))
        rootless = (
            f"{_mongod_diagnostics(spec, rootless=True)}\n"
            f"touch {enabled}\n"
            f"{_run_or_explain(f'om_unit restart {spec.port}')}\n"
        )
        return _with_rootless(action, rootless, (f"restart {spec.port}",))

    def _verify(self, spec: BootstrapSpec) -> StepAction:
        """Confirm ``mongod`` answers before declaring this host done.

        ``start_service`` can succeed with mongod dying right after (see
        :meth:`_configure_mongod`), so this is often where a mongod that never
        came up is first seen; a failed ``ping`` prints mongod's journal and log
        errors before exiting with mongosh's own code. It waits for mongod
        rather than pinging once: on PSMDB 8.0 ``start_service`` returns before
        mongod listens (see :data:`MONGOD_READY_WAIT_S`).

        :param spec: The host's bootstrap spec; its port and log path are read.
        :return: The step action.
        """
        wait = _wait_for_mongod_command(spec.port)
        action = _shell_step(
            f"{_mongod_diagnostics(spec)}\n{_run_or_explain(wait)}\n",
            timeout_s=_wait_for_mongod_max_s() + 30,
        )
        rootless = (
            f"{_mongod_diagnostics(spec, rootless=True)}\n{_run_or_explain(wait)}\n"
        )
        return _with_rootless(action, rootless)

    def _require_package_manager(self, os_: OperatingSystem) -> str:
        """Map a supported OS to its package manager, or reject an unsupported one.

        :param os_: The host's OS.
        :return: The package manager's command name.
        :raises ValueError: If ``os_`` is not a supported :class:`OperatingSystem`.
        """
        if os_ is OperatingSystem.UBUNTU:
            return "apt-get"
        if os_ is OperatingSystem.ROCKY:
            return "dnf"
        raise ValueError(f"unsupported OperatingSystem: {os_!r}")

    def plan_run_steps(self, spec: BootstrapSpec) -> list[str]:
        """Return this strategy's run-level step names.

        All of them need every member's mongod already running (every host's
        :meth:`plan_steps` succeeded) — the stepper's job to wait for, not this
        method's.

        :param spec: The run's bootstrap spec; ``create_admin_user`` adds that step.
        :return: Step names, in execution order.
        """
        steps = ["rs_initiate"]
        if spec.create_admin_user:
            steps.append(CREATE_ADMIN_USER_STEP)
        steps.append("create_pmm_monitoring_user")
        return steps

    def build_run_step(
        self,
        step_name: str,
        hosts: list[str],
        spec: BootstrapSpec,
        params: dict[str, str] | None = None,
    ) -> StepAction:
        """Build the action for one of :meth:`plan_run_steps`' names.

        :param step_name: One of :meth:`plan_run_steps`' names.
        :param hosts: Every host in this run — see
            :meth:`~app.extensions.apps.om_bootstrap.strategy.InstallStrategy.build_run_step`'s
            own docstring for why index 0 is where this action actually runs.
        :param spec: The run's bootstrap spec.
        :param params: ``{"username": ..., "password": ...}`` for
            ``create_admin_user`` and ``create_pmm_monitoring_user``; ignored by
            ``rs_initiate``.
        :return: What the execution layer needs to run this step.
        :raises ValueError: If ``step_name`` is not one of :meth:`plan_run_steps`'
            names, or a user-creating step is built without both ``params`` entries.
        """
        if step_name == "rs_initiate":
            return self._rs_initiate(hosts, spec)
        if step_name == CREATE_ADMIN_USER_STEP:
            return self._create_user(step_name, hosts, spec, params, ADMIN_USER_ROLES)
        if step_name == "create_pmm_monitoring_user":
            return self._create_user(
                step_name, hosts, spec, params, PMM_MONITORING_USER_ROLES
            )
        raise ValueError(
            f"{step_name!r} is not a PackagesInstallStrategy run step; "
            f"expected one of {self.plan_run_steps(spec)}"
        )

    def _rs_initiate(self, hosts: list[str], spec: BootstrapSpec) -> StepAction:
        """Initiate the replica set from its seed member (``hosts[0]``).

        Per-member priority/votes/hidden/delay come from ``spec.member_configs``,
        keyed by host — a host missing from it gets :class:`MemberConfig`'s own
        defaults.

        Tolerates ``rs.initiate`` already having succeeded: a dispatch that
        times out at the PMM Extensions/Nomad layer *after* the command actually took
        effect on the host looks, to the stepper's retry policy, exactly like
        one that never ran — it retries. A bare retry fails with
        ``AlreadyInitialized`` and, retries exhausted, triggers rollback
        (including ``rm -rf`` of the data directory), tearing down a replica
        set that had already initiated successfully. Swallowing exactly that
        one ``codeName`` makes the retry a no-op instead.

        :param hosts: Every member, in run order; ``hosts[0]`` is the seed.
        :param spec: The run's bootstrap spec.
        :return: The step action.
        """
        members = []
        for index, host in enumerate(hosts):
            member = spec.member_configs.get(host, MemberConfig())
            entry = {
                "_id": index,
                "host": f"{host}:{spec.port}",
                "priority": member.priority,
                "votes": 1 if member.votes else 0,
                "hidden": member.hidden,
            }
            if member.delay_secs:
                entry["secondaryDelaySecs"] = member.delay_secs
            members.append(entry)
        config = {"_id": spec.replica_set_name, "members": members}
        js = (
            f"try {{ rs.initiate({json.dumps(config)}) }} "
            "catch (e) { if (e.codeName !== 'AlreadyInitialized') throw e }"
        )
        return _mongosh_eval(js, spec.port)

    def _create_user(
        self,
        step_name: str,
        hosts: list[str],
        spec: BootstrapSpec,
        params: dict[str, str] | None,
        roles: list[dict[str, str]],
    ) -> StepAction:
        """Create one MongoDB user in ``admin``: the customer's administrator or PMM's monitoring user.

        Created once for the whole set — MongoDB replicates ``admin.system.users``
        to every other member automatically, so this never needs to run per host.
        ``params`` rather than a generated value here for the same reason
        ``distribute_keyfile`` takes one: PMM's encrypted Postgres is this
        secret's durable home, not this strategy. Run through
        :func:`_mongosh_file`, so the password never appears in any argv.

        Connects through :func:`_replica_set_uri` rather than to the member this
        action runs on, and that is the whole point of the indirection.
        ``createUser`` is a write, so it needs the primary — and the member this
        runs on is ``hosts[0]``, the seed, which is *not* reliably the primary.
        ``rs.initiate`` only proposes the config; the election that follows is
        open to every member, and any of them can win it.

        Confirmed against a real multi-member run, not a theoretical race: a
        different member won the election, every dispatch of this step died
        with ``MongoServerError: not primary``, and retrying could not help
        because each attempt went to the same secondary - so the run exhausted
        its retries and rolled back a set that was otherwise fine. An identical
        run whose seed happened to win succeeded, which is what made this look
        intermittent rather than wrong.

        The URI fixes the ordering too: the driver waits up to
        :data:`PRIMARY_SELECTION_TIMEOUT_MS` for a primary to exist, so this no
        longer depends on an election having finished before it is dispatched.

        Tolerates the user already existing, for the same reason
        :meth:`_rs_initiate` tolerates ``AlreadyInitialized``: a dispatch that
        times out after ``createUser`` already took effect looks, to the
        retry policy, like one that never ran. A bare retry fails with
        ``UserAlreadyExists`` (51003) and, retries exhausted, rolls the whole
        run back over a user that was actually created successfully.

        :param step_name: The step being built, named in the missing-params error.
        :param hosts: Every member of the set, used to build the connection
            string. Not an execution target: index 0 is still where this action
            runs, it just no longer has to be the primary.
        :param spec: The run's bootstrap spec; its port and replica set name are
            read.
        :param params: Must contain ``"username"`` and ``"password"``.
        :param roles: The roles to grant.
        :return: The step action.
        :raises ValueError: If ``params`` is missing ``"username"`` or
            ``"password"``.
        """
        if not params or "username" not in params or "password" not in params:
            raise ValueError(
                f"{step_name} requires params['username'] and params['password']"
            )
        username = json.dumps(params["username"])
        create = (
            f"db.getSiblingDB('admin').createUser({{"
            f"user: {username}, "
            f"pwd: {json.dumps(params['password'])}, "
            f"roles: {json.dumps(roles)}"
            f"}})"
        )
        js = f"if (!db.getSiblingDB('admin').getUser({username})) {{ {create} }}"
        return _mongosh_file(js, spec.port, uri=_replica_set_uri(hosts, spec))

    def plan_finalize_steps(self, spec: BootstrapSpec) -> list[str]:  # noqa: ARG002
        """Return this strategy's fixed per-host finalize step names.

        :param spec: The host's bootstrap spec.
        :return: Step names, in execution order.
        """
        return ["enable_auth"]

    def build_finalize_step(
        self,
        step_name: str,
        host: str,
        spec: BootstrapSpec,
        params: dict[str, str] | None = None,  # noqa: ARG002
    ) -> StepAction:
        """Build the action for one of :meth:`plan_finalize_steps`' names.

        :param step_name: One of :meth:`plan_finalize_steps`' names.
        :param host: The node name being finalized. Used by ``enable_auth``, which
            rewrites mongod.conf and therefore needs this member's ``bindIp``.
        :param spec: The host's bootstrap spec.
        :param params: Unused — ``enable_auth`` needs no secret it doesn't
            already have on disk (:data:`KEY_FILE_PATH`, planted by
            ``distribute_keyfile``).
        :return: What the execution layer needs to run this step.
        :raises ValueError: If ``step_name`` is not one of
            :meth:`plan_finalize_steps`' names.
        """
        if step_name == "enable_auth":
            return self._enable_auth(spec, host)
        raise ValueError(
            f"{step_name!r} is not a PackagesInstallStrategy finalize step; "
            f"expected one of {self.plan_finalize_steps(spec)}"
        )

    def _enable_auth(self, spec: BootstrapSpec, host: str) -> StepAction:
        """Turn MongoDB authorization on, now that the first user exists.

        Rewrites the *same* :data:`CONFIG_PATH` :meth:`_configure_mongod` wrote,
        adding exactly the ``security`` block that method left out — see its own
        docstring for why authorization has to stay off until now. Restarts
        ``mongod`` to pick the new config up: unlike ``processManagement.fork``
        or ``systemLog.path``, ``security.authorization`` cannot be changed on a
        running server, only at startup.

        A plain ``restart`` rather than ``stop`` then ``start``: systemd runs
        them as one unit transaction either way, and a two-step version would
        leave a window (however short) where ``mongod`` isn't running at all if
        something between the two commands failed.

        Joins the write, the restart, and a readiness wait with ``&&``, not a
        bare newline: ``systemctl restart`` reports success before mongod has
        accepted the new config (see :data:`MONGOD_READY_WAIT_S`) — a config
        write that failed (read-only filesystem, full disk) would otherwise
        still restart mongod on the *old*, auth-less config, and the step would
        report SUCCEEDED with authorization still off. The wait pings with the
        same unauthenticated ``ping`` ``verify`` uses: MongoDB answers it
        without credentials even with ``security.authorization: enabled``, so
        this proves mongod actually came back up on the new config rather than
        starting and then exiting. A wait rather than one ping, because on PSMDB
        8.0 the restart returns before mongod listens.

        :param spec: The host's bootstrap spec.
        :param host: The host being configured, which decides its ``bindIp``.
        :return: The step action.
        """
        config = _mongod_config(spec, host, with_auth=True)
        command = (
            f"cat > {CONFIG_PATH} <<'MONGOD_CONF' && systemctl restart mongod "
            f"&& {_wait_for_mongod_command(spec.port)}\n{config}MONGOD_CONF\n"
        )
        action = _shell_step(
            command, timeout_s=MONGOD_RESTART_ALLOWANCE_S + _wait_for_mongod_max_s()
        )
        # set -e stops the step at a failed write, before the restart.
        config_body, config_request = _rootless_config(
            spec, host, with_auth=True, step_name="enable_auth"
        )
        rootless = (
            f"{config_body}\n"
            f"om_unit restart {spec.port}\n"
            f"{_wait_for_mongod_command(spec.port)}\n"
        )
        return _with_rootless(
            action, rootless, (config_request, f"restart {spec.port}")
        )

    def plan_rollback_steps(self, spec: BootstrapSpec) -> list[str]:  # noqa: ARG002
        """Return this strategy's fixed per-host rollback step names.

        The reverse of :meth:`plan_steps`, undoing what a host's forward steps
        did rather than mirroring their names one-for-one: there is nothing to
        undo for ``pre_check``/``verify`` (read-only), and ``configure_repository``
        is left alone deliberately — removing ``percona-release`` would affect
        anything else on the host that depends on it, well outside this run's
        blast radius.

        Every step is a no-op on a host whose :data:`OWNERSHIP_MARKER_PATH`
        does not hold this run's id — see the module docstring.

        :param spec: The host's bootstrap spec.
        :return: Step names, in the order rollback applies them.
        """
        return [
            "stop_service",
            "remove_config",
            "remove_keyfile",
            "purge_package",
            "remove_data",
        ]

    def build_rollback_step(
        self,
        step_name: str,
        host: str,  # noqa: ARG002
        spec: BootstrapSpec,
    ) -> StepAction:
        """Build the action for one of :meth:`plan_rollback_steps`' names.

        :param step_name: One of :meth:`plan_rollback_steps`' names.
        :param host: The node name being rolled back. Unused — same reasoning as
            :meth:`build_step`'s own ``host`` parameter.
        :param spec: The host's bootstrap spec.
        :return: What the execution layer needs to run this step.
        :raises ValueError: If ``step_name`` is not one of
            :meth:`plan_rollback_steps`' names, ``spec.run_id`` is ``None``, or
            ``spec.os`` is not a supported :class:`OperatingSystem`.
        """
        builders = {
            "stop_service": self._rollback_stop_service,
            "remove_config": self._rollback_remove_config,
            "remove_keyfile": self._rollback_remove_keyfile,
            "purge_package": self._rollback_purge_package,
            "remove_data": self._rollback_remove_data,
        }
        try:
            builder = builders[step_name]
        except KeyError:
            raise ValueError(
                f"{step_name!r} is not a PackagesInstallStrategy rollback step; "
                f"expected one of {list(builders)}"
            ) from None
        run_id = _require_run_id(spec, step_name)
        return builder(spec, run_id)

    def is_retryable(self, step_name: str) -> bool:
        """Retry every step but ``pre_check``, which only inspects the host.

        A taken port, a mongod already installed or a small disk is still there a
        few seconds later, so a second ``pre_check`` fails exactly like the first.

        :param step_name: Any step name this strategy plans.
        :return: Whether a failure of it is worth one retry.
        """
        return step_name != PRE_CHECK

    def has_anything_to_roll_back(self, state: HostBootstrapState) -> bool:
        """Report whether ``install_package`` can have run on this host.

        It plants :data:`OWNERSHIP_MARKER_PATH` before the package manager runs, and
        every rollback step is a no-op on a host whose marker does not hold this
        run's id. The steps before it change nothing rollback would undo:
        ``pre_check`` only reads, and ``configure_repository`` is deliberately left
        in place (see :meth:`plan_rollback_steps`).

        Only a host where a step before it has not succeeded is proven untouched:
        PMM's stepper dispatches a host's steps in order, each once every step
        before it has succeeded or been skipped. ``install_package``'s own record
        proves nothing, since the Tasks API can accept it before its attempt is
        saved; there the marker makes the rollback a no-op if nothing was installed.

        :param state: The host's progress so far.
        :return: Whether its rollback steps may have anything to undo.
        """
        for step in state.steps:
            if step.name == INSTALL_PACKAGE:
                return True
            if step.status not in (StepStatus.SUCCEEDED, StepStatus.SKIPPED):
                return False
        return False

    def _rollback_stop_service(self, spec: BootstrapSpec, run_id: str) -> StepAction:
        """Stop and disable ``mongod``, tolerant of it never having started.

        :param spec: The host's bootstrap spec; its port names the instance on a
            host with the root step.
        :param run_id: The run the rollback belongs to.
        :return: The step action.
        """
        enabled = shlex.quote(posixpath.join(_instance_dir(spec), "enabled"))
        return _owned_step(
            "systemctl disable --now mongod || true",
            run_id,
            timeout_s=60,
            spec=spec,
            rootless_body=f"rm -f {enabled}\nom_unit stop {spec.port} || true",
            operations=(f"stop {spec.port}",),
        )

    def _rollback_remove_config(self, spec: BootstrapSpec, run_id: str) -> StepAction:
        """Remove the config file ``configure_mongod`` wrote.

        On a host with the root step ``purge`` stays: ``remove_data`` needs it.
        The port helper there closes what ``configure_mongod`` opened.

        :param spec: The host's bootstrap spec; its port names the instance on a
            host with the root step.
        :param run_id: The run the rollback belongs to.
        :return: The step action.
        """
        instance = _instance_dir(spec)
        files = " ".join(
            shlex.quote(posixpath.join(instance, name))
            for name in ("mongod.conf", "dirs")
        )
        rootless = "\n".join(
            [
                f"rm -f {files}",
                'if [ -n "$(om_record port_range)" ]; then',
                _port_helper("close", spec, "remove_config"),
                "fi",
            ]
        )
        return _owned_step(
            f"rm -f {CONFIG_PATH}",
            run_id,
            timeout_s=60,
            spec=spec,
            rootless_body=rootless,
            operations=(f"port close {spec.port}",),
        )

    def _rollback_remove_keyfile(self, spec: BootstrapSpec, run_id: str) -> StepAction:
        """Remove the keyFile ``distribute_keyfile`` wrote.

        :param spec: The host's bootstrap spec; its port names the instance on a
            host with the root step.
        :param run_id: The run the rollback belongs to.
        :return: The step action.
        """
        key_file = shlex.quote(posixpath.join(_instance_dir(spec), "keyfile"))
        return _owned_step(
            f"rm -f {KEY_FILE_PATH}",
            run_id,
            spec=spec,
            rootless_body=f"rm -f {key_file}",
        )

    def _rollback_purge_package(self, spec: BootstrapSpec, run_id: str) -> StepAction:
        """Purge the ``percona-server-mongodb`` package ``install_package`` installed.

        Tolerant of the install itself having failed part-way: the marker is
        planted before the package manager runs, so a host whose
        ``install_package`` failed still rolls back, and the purge tolerates a
        package that never landed.

        ``percona-server-mongodb`` is a metapackage: removing it with apt leaves
        mongod, mongos, the tools and mongosh installed, so apt also purges those
        it then reports unused. dnf removes every dependency only the install
        needed itself, with ``clean_requirements_on_remove``, set here so the
        host's ``dnf.conf`` cannot turn it off.

        :param spec: The host's bootstrap spec; only its OS is read.
        :param run_id: The run the rollback belongs to.
        :return: The step action.
        """
        pkg_manager = self._require_package_manager(spec.os)
        if pkg_manager == "apt-get":
            remove = "\n".join(
                [
                    "apt-get remove -y --purge percona-server-mongodb || true",
                    (
                        "unused=$(apt-get -s autoremove 2>/dev/null"
                        f" | awk -v re={shlex.quote(_PSMDB_PACKAGES_ERE)}"
                        ' \'($1 == "Remv" || $1 == "Purg") && $2 ~ re { print $2 }\')'
                    ),
                    '[ -z "$unused" ] || apt-get remove -y --purge $unused || true',
                ]
            )
        else:
            remove = (
                "dnf remove -y --setopt=clean_requirements_on_remove=True "
                "percona-server-mongodb || true"
            )
        return _owned_step(
            remove,
            run_id,
            timeout_s=300,
            spec=spec,
            rootless_body=self._rootless_purge_package(spec),
            operations=(f"remove {' '.join(_ROOTLESS_PACKAGES)}",),
        )

    def _rootless_purge_package(self, spec: BootstrapSpec) -> str:
        """Build ``purge_package`` for a host with the root step.

        Removes every PSMDB package the root step lets the agent remove, through
        PackageKit or the socket helper, unless another instance PMM installed on
        the host still needs them. PackageKit leaves the dependencies it pulled in
        itself, such as ``percona-telemetry-agent``, which the grant does not name.
        A refused or failed removal does not fail the rollback, as on a root host.

        :param spec: The host's bootstrap spec; its OS and port are read.
        :return: The shell body.
        """
        packages = " ".join(_ROOTLESS_PACKAGES)
        # Package ids, not names: PackageKit's apt backend lists an installed
        # package once per Percona source and refuses to pick one.
        if self._require_package_manager(spec.os) == "apt-get":
            ids = (
                "dpkg-query -W -f '${db:Status-Abbrev} ${Package};${Version};"
                f"${{Architecture}};installed\\n' {packages} 2>/dev/null"
                " | awk '$1 == \"ii\" { print $2 }' || true"
            )
        else:
            ids = (
                "rpm -q --qf '%{NAME};%{VERSION}-%{RELEASE};%{ARCH};installed\\n'"
                f" {packages} 2>/dev/null | grep ';installed$' || true"
            )
        instance = shlex.quote(_instance_dir(spec) + "/")
        return "\n".join(
            [
                f"for d in {HANDOVER_DIR}/*/; do",
                f'  if [ "$d" != {instance} ] && [ -e "$d/om-bootstrap" ]; then',
                "    echo 'purge_package: kept for the other instances here'; exit 0",
                "  fi",
                "done",
                # The socket helper takes names and removes the installed ones.
                "if om_socket; then",
                f"  pmm-operations remove {packages} 2>&1 | tail -n 5 || true",
                "  exit 0",
                "fi",
                f"ids=$({ids})",
                '[ -n "$ids" ] || exit 0',
                "out=$(mktemp)",
                "trap 'rm -f \"$out\"' EXIT",
                'pkcon -p --noninteractive remove $ids >"$out" 2>&1 || tail -n 5 "$out"',
            ]
        )

    def _rollback_remove_data(self, spec: BootstrapSpec, run_id: str) -> StepAction:
        """Remove the data directory, then the ownership marker, as the last step.

        On a host with the root step ``pmm-mongod-purge@<port>`` empties the data
        directory and removes the log as ``mongod``, which is all it can touch;
        removing the instance's hand-over directory then removes the marker.

        :param spec: The host's bootstrap spec; only its data path and port are read.
        :param run_id: The run the rollback belongs to.
        :return: The step action.
        """
        body = f"rm -rf {shlex.quote(spec.data_path)}\nrm -f {OWNERSHIP_MARKER_PATH}"
        rootless = f"om_purge {spec.port}\nrm -rf {shlex.quote(_instance_dir(spec))}"
        return _owned_step(
            body,
            run_id,
            timeout_s=60,
            spec=spec,
            rootless_body=rootless,
            operations=(f"purge {spec.port}",),
        )
