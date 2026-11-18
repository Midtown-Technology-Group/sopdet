"""Fail-closed ggshield gate for committed PR history or Git pre-push input."""

import sys

# This bootstrap uses only the built-in sys module before enforcing isolation.
if __name__ == "__main__" and not sys.flags.isolated:
    sys.stderr.write(
        "UNAVAILABLE: run this gate with Python -I; publication blocked.\n"
    )
    sys.exit(21)

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

MINIMUM_PYTHON = (3, 11)
MAX_TAG_CHAIN = 8
APPROVALS_FILE = ".secret-gate-false-positives.json"
APPROVAL_FIELDS = {"ignore_sha", "detector", "reason"}
SAFE_DETECTOR = re.compile(r"[\w .()/+-]{1,80}")
GITDIR_PREFIX = "gitdir:"


class GateError(Exception):
    """A safe, classified publication-blocking failure."""

    def __init__(self, code, message):
        """Retain the exit classification and a value-free diagnostic."""
        self.code = code
        self.message = message


def metadata_path(path, anchor):
    """Confine metadata access, including symlinks, to its allowed Git directory."""
    try:
        anchor = anchor.resolve()
        path = path.absolute()
        if any(
            p.is_symlink() for p in (path, *path.parents) if p.is_relative_to(anchor)
        ):
            raise ValueError("metadata symlink")
        resolved = path.resolve()
        relative = resolved.relative_to(anchor)
        if any(
            p.is_symlink()
            for p in (resolved, *resolved.parents)
            if p.is_relative_to(anchor)
        ):
            raise ValueError("unresolved metadata symlink")
    except (ValueError, OSError, RuntimeError) as error:
        raise GateError(
            20, "BASE_ERROR: Git metadata escapes its allowed directory."
        ) from error
    return anchor / relative


def metadata_text(path, anchor):
    """Read only a bounded, confined Git metadata record; never display it."""
    path = metadata_path(path, anchor)
    try:
        if not path.is_file():
            raise GateError(20, "BASE_ERROR: missing or non-regular Git metadata.")
        with open(path, "rb", opener=metadata_opener) as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise GateError(20, "BASE_ERROR: non-regular Git metadata.")
            data = stream.read(8193)
    except (OSError, ValueError) as error:
        raise GateError(20, "BASE_ERROR: unreadable Git metadata.") from error
    if len(data) > 8192:
        raise GateError(20, "BASE_ERROR: oversized Git metadata record.")
    if b"\0" in data:
        raise GateError(20, "BASE_ERROR: invalid Git metadata path.")
    try:
        return data.decode("utf-8").strip()
    except UnicodeError as error:
        raise GateError(
            20, "BASE_ERROR: unsupported Git metadata path encoding."
        ) from error


def metadata_opener(path, flags):
    """Avoid blocking on a FIFO swapped in before descriptor validation."""
    return os.open(
        path, flags | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    )


def linked_roots(common):
    """Read registered worktree pointers inside this Git metadata directory."""
    roots = set()
    registry = metadata_path(common / "worktrees", common)
    if not registry.exists():
        return roots
    if not registry.is_dir():
        raise GateError(20, "BASE_ERROR: non-directory worktree registry.")
    try:
        entries = list(registry.iterdir())
    except OSError as error:
        raise GateError(20, "BASE_ERROR: unreadable worktree registry.") from error
    for entry in entries:
        entry = metadata_path(entry, common)
        if not entry.is_dir():
            raise GateError(20, "BASE_ERROR: non-directory worktree registration.")
        pointer = entry / "gitdir"
        try:
            target = (pointer.parent / metadata_text(pointer, common)).resolve()
        except (OSError, ValueError, RuntimeError) as error:
            raise GateError(
                20, "BASE_ERROR: invalid linked-worktree metadata."
            ) from error
        if target.name != ".git":
            raise GateError(20, "BASE_ERROR: unsupported linked-worktree metadata.")
        roots.add(target.parent)
    return roots


def checkout_roots():
    """Read this checkout's standard Git metadata without executing a tool."""
    cwd = Path.cwd().resolve()
    root = next((p for p in (cwd, *cwd.parents) if (p / ".git").exists()), None)
    if root is None:
        raise GateError(20, "BASE_ERROR: run from the intended Git worktree.")
    marker = root / ".git"
    gitdir = marker
    if marker.is_file():
        text = metadata_text(marker, root)
        if not text.startswith(GITDIR_PREFIX) or "\n" in text:
            raise GateError(20, "BASE_ERROR: unsupported Git worktree metadata.")
        gitdir = (root / text[len(GITDIR_PREFIX) :].strip()).resolve()
    gitdir = gitdir.resolve()
    owner = next((p for p in (gitdir, *gitdir.parents) if p.name == ".git"), None)
    if owner is None:
        raise GateError(20, "BASE_ERROR: unsupported Git metadata layout.")
    common_file = metadata_path(gitdir / "commondir", owner)
    common = (
        metadata_path(gitdir / metadata_text(common_file, owner), owner)
        if common_file.exists()
        else gitdir
    )
    if not (common / "objects").is_dir():
        raise GateError(20, "BASE_ERROR: unsupported Git metadata layout.")
    return (
        {root, owner.parent, common, gitdir}
        | linked_roots(common)
        | linked_roots(owner)
    )


def metadata_owned(directory, roots):
    """Recognize Git associations and exclude unsearchable tool candidates."""
    marker = directory / ".git"
    try:
        try:
            marker.lstat()
        except (FileNotFoundError, NotADirectoryError):
            return False
        if marker.is_dir():
            gitdir = marker.resolve()
        elif marker.is_file():
            text = metadata_text(marker, directory)
            if not text.startswith(GITDIR_PREFIX) or "\n" in text:
                raise GateError(20, "BASE_ERROR: unsupported tool-checkout metadata.")
            gitdir = (directory / text[len(GITDIR_PREFIX) :].strip()).resolve()
        else:
            return True
        if any(gitdir.is_relative_to(root) for root in roots):
            return True
        common_file = gitdir / "commondir"
        try:
            common_file.lstat()
        except FileNotFoundError:
            return False
        common = (gitdir / metadata_text(common_file, gitdir)).resolve()
        return any(common.is_relative_to(root) for root in roots)
    except OSError:
        # lstat retains permission errors on Python versions whose predicates
        # suppress them. Exclude the candidate before constructing child PATH.
        return True


def checkout_owned(path, roots):
    """Reject code owned by this repository or its linked worktrees."""
    return any(path.is_relative_to(root) for root in roots) or any(
        metadata_owned(directory, roots) for directory in (path, *path.parents)
    )


def command_environment():
    """Bind children to the current checkout and approved import directories."""
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("PYTHON", "GITGUARDIAN_", "GG_", "GIT_TRACE"))
    }
    for name in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
        "GIT_CEILING_DIRECTORIES",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_EXEC_PATH",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_PROXY_COMMAND",
        "GIT_CURL_VERBOSE",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONUSERBASE",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
    ):
        env.pop(name, None)
    for name in (
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
    ):
        value = env.get(name)
        if name == "GIT_ASKPASS" and value == "":
            continue
        if value is not None and os.path.normcase(value) != os.path.normcase(
            os.devnull
        ):
            path = Path(value)
            if not path.is_absolute() or checkout_owned(
                path.resolve(), checkout_roots()
            ):
                raise GateError(
                    20,
                    "BASE_ERROR: Git config/askpass override requires an approved absolute path "
                    "outside the checkout.",
                )
            env[name] = str(path.resolve())
    env["PYTHONSAFEPATH"] = "1"
    return env


def executable(name):
    """Resolve approved tools outside the checkout, including on Windows."""
    if name not in {"git", "ggshield"}:
        return None
    roots = checkout_roots()
    os.environ["NODEFAULTCURRENTDIRECTORYINEXEPATH"] = "1"
    suffixes = [""]
    if os.name == "nt":
        suffixes += os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(os.pathsep)
    directories = []
    for entry in os.get_exec_path():
        directory = Path(entry).resolve()
        if not Path(entry).is_absolute() or checkout_owned(directory, roots):
            continue
        # A rejected Git symlink must not remain available to ggshield's own
        # PATH lookup, which runs with the scanner credential in its environment.
        candidates = (
            shutil.which(str(directory / (tool + suffix)))
            for tool in ("git", "ggshield")
            for suffix in suffixes
        )
        if any(
            checkout_owned(Path(found).resolve(), roots)
            for found in filter(None, candidates)
        ):
            continue
        directories.append(str(directory))
    os.environ["PATH"] = os.pathsep.join(directories)
    for directory in directories:
        for suffix in suffixes:
            # A path containing a directory bypasses Python 3.11's implicit cwd lookup.
            found = shutil.which(str(Path(directory) / (name + suffix)))
            if found and not checkout_owned(Path(found).resolve(), roots):
                return str(Path(found).resolve())
    return None


def git(*args, strip=True):
    """Run Git without interactive authentication or replacement objects."""
    if not args or not all(re.fullmatch(r"[\w./@{}^~+:=,-]+", arg) for arg in args):
        raise GateError(20, "BASE_ERROR: invalid Git argument.")
    tool = executable("git")
    if not tool:
        raise GateError(21, "UNAVAILABLE: install approved Git outside the checkout.")
    env = dict(
        command_environment(),
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_GRAFT_FILE=os.devnull,
        GIT_TERMINAL_PROMPT="0",
        GCM_INTERACTIVE="Never",
    )
    result = subprocess.run(
        [tool, *args],
        check=False,
        env=env,
        capture_output=True,
        timeout=90,
    )
    if result.returncode:
        raise GateError(
            20,
            "BASE_ERROR: Git operation failed; check refs/access and fetch the base.",
        )
    output = result.stdout.decode("utf-8")
    return output.strip() if strip else output


def commit(ref):
    """Resolve a ref to an immutable commit before selecting history."""
    if not re.fullmatch(r"(?!-)[\w./@{}^~+=,-]+", ref):
        raise GateError(
            20, "BASE_ERROR: unsupported commit reference; pass a full commit SHA."
        )
    sha = git("rev-parse", "--verify", "--end-of-options", ref + "^{commit}")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", sha):
        raise GateError(20, "BASE_ERROR: reference did not resolve to one commit.")
    return sha


def remote_base(remote):
    """Resolve the configured remote default tip without guessing a branch."""
    if not re.fullmatch(r"(?!-)[\w./@+=,-]+", remote):
        raise GateError(20, "BASE_ERROR: invalid remote name.")
    if remote not in git("remote").splitlines():
        raise GateError(
            20, "BASE_ERROR: select a configured remote or an explicit --base."
        )
    for line in git("ls-remote", "--symref", "--", remote, "HEAD").splitlines():
        parts = line.split()
        if (
            len(parts) == 2
            and parts[1] == "HEAD"
            and re.fullmatch(r"[0-9a-f]{40,64}", parts[0])
        ):
            return commit(parts[0])
    raise GateError(
        20,
        "BASE_ERROR: no remote default; supply --base or --all-history.",
    )


def base_commit(ref):
    """Require a full destination ref or commit SHA instead of an ambiguous name."""
    if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", ref):
        if not ref.startswith("refs/"):
            raise GateError(20, "BASE_ERROR: --base requires a full ref or commit SHA.")
        git("check-ref-format", ref)
    return commit(ref)


def active_grafts(common):
    """Read confined graft metadata with the documented failure classification."""
    grafts = metadata_path(common / "info/grafts", common)
    try:
        return grafts.exists() and grafts.stat().st_size
    except OSError as error:
        raise GateError(20, "BASE_ERROR: unreadable graft metadata.") from error


def ranges(args, stream, head):
    """Select complete PR or pre-push commit ranges."""
    common = Path(git("rev-parse", "--git-common-dir"))
    if active_grafts(common) or os.environ.get("GIT_GRAFT_FILE"):
        raise GateError(
            20, "BASE_ERROR: grafted history is unsupported; restore complete history."
        )
    if git("rev-parse", "--is-shallow-repository") != "false":
        raise GateError(
            20, "BASE_ERROR: shallow history; fetch --unshallow before scanning."
        )
    if not args.pre_push:
        base = base_commit(args.base) if args.base is not None else None
        if not base and not args.all_history:
            base = remote_base(args.remote)
        return [f"{base}..{head}" if base else head], []
    result = []
    annotations = []
    for line in stream:
        revision, tags = push_range(line)
        if revision:
            result.append(revision)
        annotations.extend(tags)
    return list(dict.fromkeys(result)), list(dict.fromkeys(annotations))


def push_range(line):
    """Parse one complete Git pre-push update into its outgoing range."""
    fields = line.split()
    if len(fields) != 4 or not all(
        re.fullmatch(r"[0-9a-f]{40,64}", fields[i]) for i in (1, 3)
    ):
        raise GateError(20, "BASE_ERROR: malformed Git pre-push input.")
    _, local, _, old = fields
    if set(local) == {"0"}:
        return None, []
    tags = tag_chain(local)
    head = commit(local)
    # New refs include root history, without a hook commit limit or HEAD~1 guess.
    return (head if set(old) == {"0"} else f"{commit(old)}..{head}"), tags


def tag_chain(sha):
    """List every annotated tag object between a pushed tip and its commit."""
    chain = []
    while git("cat-file", "-t", sha) == "tag":
        if len(chain) == MAX_TAG_CHAIN:
            raise GateError(
                20, "BASE_ERROR: nested tag chain is too deep; publication blocked."
            )
        # Check the size before reading: captured Git output is held in memory.
        if int(git("cat-file", "-s", sha)) > 64 * 1024:
            raise GateError(
                20, "BASE_ERROR: oversized tag annotation; publication blocked."
            )
        headers = git("cat-file", "tag", sha, strip=False).partition("\n\n")[0]
        target = re.match(r"object ([0-9a-f]{40}|[0-9a-f]{64})\ntype ", headers)
        if not target:
            raise GateError(
                20, "BASE_ERROR: unsupported tag object; publication blocked."
            )
        chain.append(sha)
        sha = target.group(1)
    if git("cat-file", "-t", sha) != "commit":
        raise GateError(
            20, "BASE_ERROR: tags must point to a commit; publication blocked."
        )
    return chain


def scanner_result(result):
    """Keep findings, authentication and scanner failures distinct for every scan."""
    if result.returncode == 1:
        raise GateError(1, "FINDINGS: secrets detected; remediate before publication.")
    if result.returncode == 3:
        raise GateError(
            3, "AUTH_FAILED: restore approved native ggshield authentication."
        )
    if result.returncode:
        raise GateError(
            4, f"SCAN_ERROR: scanner exit {result.returncode}; publication blocked."
        )


def write_messages(revision, count, directory):
    """Prepare bounded, private commit-message documents without logging content."""
    commits = git("rev-list", revision, "--").splitlines()
    if len(commits) != count or len(set(commits)) != count:
        raise GateError(4, "SCAN_ERROR: commit traversal changed during scanning.")
    directory.mkdir(mode=0o700)
    documents = []
    for sha in commits:
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha):
            raise GateError(20, "BASE_ERROR: invalid outgoing commit identity.")
        if int(git("cat-file", "-s", sha)) > 128 * 1024:
            raise GateError(
                20, "BASE_ERROR: oversized commit metadata; publication blocked."
            )
        headers, separator, message = git(
            "cat-file", "commit", sha, strip=False
        ).partition("\n\n")
        if any(line.startswith("mergetag ") for line in headers.split("\n")):
            raise GateError(
                20,
                "BASE_ERROR: merged tag annotations are unsupported; publication blocked.",
            )
        serialized = ("Commit: " + sha + "\n\n" + message).encode("utf-8")
        if not separator or "\x00" in message or len(serialized) > 64 * 1024:
            raise GateError(
                20, "BASE_ERROR: unsupported commit message; publication blocked."
            )
        document = directory / (sha + ".txt")
        document.write_bytes(serialized)
        documents.append(document)
    return documents


def write_annotations(tags, directory):
    """Prepare private tag-object documents: headers, message and signature."""
    directory.mkdir(mode=0o700)
    documents = []
    for sha in tags:
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha):
            raise GateError(20, "BASE_ERROR: invalid outgoing tag identity.")
        # tag_chain() already bounded each object's size before reading it.
        text = git("cat-file", "tag", sha, strip=False)
        if "\x00" in text:
            raise GateError(
                20, "BASE_ERROR: unsupported tag annotation; publication blocked."
            )
        document = directory / (sha + ".txt")
        document.write_bytes(("Tag: " + sha + "\n\n" + text).encode("utf-8"))
        documents.append(document)
    return documents


def load_approvals(source):
    """Read reviewed false positives from the destination, never the candidate."""
    if source is None:
        return {}
    listing = git("ls-tree", source, "--", APPROVALS_FILE)
    if not listing:
        return {}
    invalid = GateError(
        20, "BASE_ERROR: invalid false-positive list; publication blocked."
    )
    fields = listing.split(None, 3)
    if len(fields) != 4 or fields[1] != "blob":
        raise invalid
    if int(git("cat-file", "-s", fields[2])) > 64 * 1024:
        raise invalid
    try:
        data = json.loads(git("cat-file", "blob", fields[2]))
    except ValueError as error:
        raise invalid from error
    if (
        not isinstance(data, dict)
        or set(data) != {"version", "false_positives"}
        or data["version"] != 1
        or not isinstance(data["false_positives"], list)
    ):
        raise invalid
    approvals = {}
    for entry in data["false_positives"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != APPROVAL_FIELDS
            or not isinstance(entry["ignore_sha"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", entry["ignore_sha"])
            or not isinstance(entry["detector"], str)
            or not SAFE_DETECTOR.fullmatch(entry["detector"])
            or not isinstance(entry["reason"], str)
            or len(entry["reason"].strip()) < 10
            or entry["ignore_sha"] in approvals
        ):
            raise invalid
        approvals[entry["ignore_sha"]] = entry["detector"]
    return approvals


def approved(incident, approvals):
    """Match one finding to a reviewed false positive by exact hash and detector."""
    return (
        isinstance(incident, dict)
        and incident.get("policy") == "Secrets detection"
        and isinstance(incident.get("ignore_sha"), str)
        and approvals.get(incident["ignore_sha"]) == incident.get("type")
    )


def report_entries(report, kind):
    """Yield (commit, entry) pairs from a ggshield JSON report of one kind."""
    if not isinstance(report, dict) or report.get("errors"):
        raise TypeError("unsupported report")
    if kind == "commit-range" and report.get("type") == "commit-range":
        scans = report.get("scans")
        if not isinstance(scans, list):
            raise TypeError("unsupported report")
        for item in scans:
            entries = (
                item.get("entities_with_incidents") if isinstance(item, dict) else None
            )
            if not isinstance(entries, list):
                raise TypeError("unsupported report")
            yield from ((item.get("id"), entry) for entry in entries)
    elif kind == "path" and report.get("type") == "path_scan":
        entries = report.get("entities_with_incidents")
        if not isinstance(entries, list):
            raise TypeError("unsupported report")
        yield from ((None, entry) for entry in entries)
    else:
        raise TypeError("unsupported report")


def describe(commit, entry, incident):
    """Return safe finding metadata: detector, ignore hash and location only."""
    detector = incident.get("type")
    ignore = incident.get("ignore_sha")
    name = entry.get("filename")
    lines = sorted(
        {
            o.get("line_start")
            for o in incident.get("occurrences") or []
            if isinstance(o, dict) and isinstance(o.get("line_start"), int)
        }
    )
    where = name if isinstance(name, str) and name.isprintable() else "<unprintable>"
    if isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40,64}", commit):
        where = commit[:12] + ":" + where
    return (
        f"FINDING: {detector if isinstance(detector, str) and SAFE_DETECTOR.fullmatch(detector) else '<unknown>'}"
        f" ignore_sha={ignore if isinstance(ignore, str) and re.fullmatch(r'[0-9a-f]{64}', ignore) else '<unknown>'}"
        f" at {where}" + (f" line {','.join(map(str, lines))}" if lines else "")
    )


def settle_findings(output, kind, approvals):
    """Allow a findings exit only when every finding is a reviewed false positive."""
    findings = GateError(1, "FINDINGS: secrets detected; remediate before publication.")
    try:
        report = json.loads(output)
        found = []
        for commit, entry in report_entries(report, kind):
            incidents = entry.get("incidents") if isinstance(entry, dict) else None
            if not isinstance(incidents, list):
                raise TypeError("unsupported report")
            found.extend((commit, entry, incident) for incident in incidents)
    except (ValueError, TypeError) as error:
        raise findings from error
    if not found or len(found) != report.get("total_incidents"):
        raise findings
    rejected = [item for item in found if not approved(item[2], approvals)]
    for item in rejected:
        print(
            describe(*item) if isinstance(item[2], dict) else "FINDING: <unknown>",
            file=sys.stderr,
        )
    if rejected:
        raise findings
    print(
        f"APPROVED: {len(found)} reviewed false positive(s) in {kind} scan.", flush=True
    )


def clean_receipt(record, approvals=None):
    """Recognize a result whose findings, if any, are all reviewed false positives."""
    if not isinstance(record, dict) or record.get("errors") or record.get("scans"):
        return False
    incidents = record.get("incidents") or []
    if not isinstance(incidents, list) or not all(
        approved(i, approvals or {}) for i in incidents
    ):
        return False
    occurrences = sum(
        i.get("total_occurrences")
        if isinstance(i.get("total_occurrences"), int)
        else -1
        for i in incidents
    )
    return (
        record.get("total_incidents") == len(incidents)
        and record.get("total_occurrences") == occurrences
    )


def confirm_message_scan(output, documents, directory, approvals=None):
    """Require exactly one clean SDK result for every generated document."""
    failure = "SCAN_ERROR: incomplete or unsupported message scan; publication blocked."
    try:
        report = json.loads(output)
    except (ValueError, TypeError) as error:
        raise GateError(4, failure) from error
    if not isinstance(report, dict):
        raise GateError(4, failure)
    entries = report.get("entities_with_incidents")
    if (
        report.get("type") != "path_scan"
        or not isinstance(entries, list)
        or len(entries) != len(documents)
        or not all(isinstance(e, dict) for e in entries)
        or report.get("errors")
        or report.get("scans")
        or report.get("total_incidents")
        != sum(e.get("total_incidents", -1) for e in entries)
        or report.get("total_occurrences")
        != sum(e.get("total_occurrences", -1) for e in entries)
    ):
        raise GateError(4, failure)
    expected = {os.path.normcase(os.path.normpath(document)) for document in documents}
    confirmed = set()
    for entry in entries:
        if (
            not clean_receipt(entry, approvals)
            or entry.get("mode") != "FILE"
            or not isinstance(entry.get("filename"), str)
        ):
            raise GateError(4, failure)
        # Normalize lexically; never follow a scanner-provided filesystem path.
        path = os.path.normcase(
            os.path.normpath(os.path.join(directory, entry["filename"]))
        )
        if path not in expected or path in confirmed:
            raise GateError(4, failure)
        confirmed.add(path)
    if confirmed != expected:
        raise GateError(4, failure)


def scan(revisions, executable, annotations=(), approvals=dict):
    # Keep native authentication, but prevent config/dotenv/fail-open/logging
    # settings from changing this gate. Never persist or forward findings.
    """Run strict ggshield scans and suppress sensitive scanner diagnostics."""
    env = {
        k: v
        for k, v in command_environment().items()
        if not k.startswith(("GITGUARDIAN_", "GG_"))
    }
    for key in ("GITGUARDIAN_API_KEY", "GITGUARDIAN_INSTANCE"):
        if key in os.environ:
            env[key] = os.environ[key]
    env.update(
        GITGUARDIAN_DONT_LOAD_ENV="1",
        GITGUARDIAN_EXIT_ZERO="false",
        GITGUARDIAN_FAIL_ON_SERVER_ERROR="true",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_GRAFT_FILE=os.devnull,
        GIT_TERMINAL_PROMPT="0",
        GCM_INTERACTIVE="Never",
        GIT_DIR=git("rev-parse", "--absolute-git-dir"),
        GIT_WORK_TREE=git("rev-parse", "--show-toplevel"),
    )
    temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
    with tempfile.TemporaryDirectory(
        prefix="secret-gate-", dir=temporary_root
    ) as directory:
        # Resolve only our owned directory, before generating documents or
        # launching children. SDK paths use the physical cwd on macOS/Windows.
        directory = str(Path(directory).resolve(strict=True))
        version = subprocess.run(
            [executable, "--version"],
            check=False,
            env=env,
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=30,
        )
        match = re.fullmatch(
            r"ggshield, version (\d+)\.(\d+)\.(\d+)\s*", version.stdout
        )
        if version.returncode or not match:
            raise GateError(
                21, "UNAVAILABLE: cannot verify the approved ggshield version."
            )
        if not (1, 56, 1) <= tuple(map(int, match.groups())) < (2, 0, 0):
            raise GateError(21, "UNAVAILABLE: ggshield >=1.56.1,<2 is required.")
        config = Path(directory) / "config.yaml"
        config.write_text(
            "version: 2\nexit_zero: false\nsecret:\n  show_secrets: false\n",
            encoding="utf-8",
        )

        reviewed = []

        def run(arguments, documents=None):
            # Even censored findings can include sensitive source context. JSON
            # stays in memory; only finding metadata is ever printed.
            result = subprocess.run(
                [
                    executable,
                    "--no-check-for-updates",
                    "--config-path",
                    config.name,
                    "secret",
                    "scan",
                    *arguments,
                ],
                check=False,
                env=env,
                cwd=directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=1800,
            )
            granted = {}
            if result.returncode == 1:
                if not reviewed:
                    reviewed.append(approvals())
                granted = reviewed[0]
                settle_findings(
                    result.stdout,
                    "path" if documents is not None else "commit-range",
                    granted,
                )
            else:
                scanner_result(result)
            if documents is not None:
                confirm_message_scan(result.stdout, documents, directory, granted)

        def run_documents(folder, documents):
            run(
                [
                    "path",
                    "--all-secrets",
                    "--recursive",
                    "--yes",
                    "--json",
                    folder.name,
                ],
                documents,
            )

        for index, (revision, count) in enumerate(revisions):
            messages = Path(directory) / f"messages-{index}"
            documents = write_messages(revision, count, messages)
            print(f"SCANNING: {count} commit(s), {revision}", flush=True)
            run(["commit-range", "--all-secrets", "--json", revision])
            run_documents(messages, documents)
        if annotations:
            folder = Path(directory) / "annotations"
            documents = write_annotations(annotations, folder)
            print(f"SCANNING: {len(annotations)} tag annotation(s)", flush=True)
            run_documents(folder, documents)
    return 0


def source(args, selected):
    """Locate reviewed approvals: the scanned PR base, else the remote default tip."""
    if not args.pre_push and not args.all_history and ".." in selected[0]:
        return selected[0].split("..", 1)[0]
    try:
        return remote_base(args.remote)
    except GateError:
        return None


def verify_snapshot(args, head, selected):
    """Reject a changed candidate or destination after the scan completes."""
    if not args.pre_push and head != commit("HEAD"):
        raise GateError(
            4,
            "SCAN_ERROR: HEAD changed; rerun for the new candidate.",
        )
    if not args.pre_push and not args.all_history and ".." in selected[0]:
        scanned_base = selected[0].split("..", 1)[0]
        current_base = (
            base_commit(args.base)
            if args.base is not None
            else remote_base(args.remote)
        )
        if current_base != scanned_base:
            raise GateError(
                4, "SCAN_ERROR: base changed; rerun for the new destination."
            )
    common = Path(git("rev-parse", "--git-common-dir"))
    if active_grafts(common) or git("rev-parse", "--is-shallow-repository") != "false":
        raise GateError(4, "SCAN_ERROR: history completeness changed during scanning.")


def main(argv=None, stream=None):
    """Run the publication gate and return its classified exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--base",
        help="fully qualified destination ref or full commit SHA",
    )
    mode.add_argument(
        "--all-history",
        action="store_true",
        help="scan all HEAD history for an initial/orphan publication",
    )
    mode.add_argument(
        "--pre-push",
        action="store_true",
        help="read Git ref updates from stdin; performs no push",
    )
    parser.add_argument(
        "--remote",
        default="origin",
        help="configured remote for the default PR base lookup",
    )
    args = parser.parse_args(argv)
    try:
        if sys.version_info < MINIMUM_PYTHON:
            raise GateError(
                21,
                "UNAVAILABLE: use supported Python "
                f"{MINIMUM_PYTHON[0]}.{MINIMUM_PYTHON[1]} or newer.",
            )
        if not executable("git"):
            raise GateError(21, "UNAVAILABLE: install Git before running this gate.")
        head = None if args.pre_push else commit("HEAD")
        selected, annotations = ranges(
            args, sys.stdin if stream is None else stream, head
        )
        revisions = [(r, int(git("rev-list", "--count", r, "--"))) for r in selected]
        revisions = [(r, n) for r, n in revisions if n]
        if not revisions and not annotations:
            raise GateError(
                10, "SKIPPED: no outgoing content; no clean scan is claimed."
            )
        scanner = executable("ggshield")
        if not scanner:
            raise GateError(
                21,
                "UNAVAILABLE: install approved ggshield; publication blocked.",
            )
        scan(
            revisions,
            scanner,
            annotations,
            lambda: load_approvals(source(args, selected)),
        )
        verify_snapshot(args, head, selected)
        tags = f" and {len(annotations)} tag annotation(s)" if annotations else ""
        print(
            f"CLEAN: ggshield passed for {sum(n for _, n in revisions)}"
            f" commit scan(s){tags}."
        )
        return 0
    except GateError as error:
        print(error.message, file=sys.stderr)
        return error.code
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print(
            "SCAN_ERROR: command failed or timed out; publication blocked.",
            file=sys.stderr,
        )
        return 4


if __name__ == "__main__":
    sys.exit(main())
