"""Explicit offline CLI artifacts for a new trial; no transport runs on import.

The CLI, not Python, signs/encrypts/verifies new protocol artifacts. Server
CurrentState is never an authority input. Online commit and UID checks remain
the responsibility of the explicit live bridge and existing runtime gates.
"""

import base64
import copy
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

LIMIT = 64 << 20
LABEL = re.compile(r"[a-z][a-z0-9-]{0,63}")
HASH = re.compile(r"[0-9a-f]{64}")


class ProvisionError(RuntimeError):
    def __init__(self, reason="ProvisionAdapterRejected"):
        super().__init__(reason)


def require(condition, reason="ProvisionAdapterRejected"):
    if not condition:
        raise ProvisionError(reason)


def safe_public(function):
    """Do not let a transport/helper exception echo private fixture material."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception:
            raise ProvisionError("ProvisionLiveOperationRejected") from None
    return wrapped


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except Exception:
        raise ProvisionError("ProvisionJSONRejected") from None


def cli_binding(binding):
    # The CRD accepts explicit false; the Go CLI requires the typed JSON
    # representation of Target, whose allowEmpty field uses omitempty.
    value = copy.deepcopy(binding)
    target = value.get("target")
    if isinstance(target, dict) and target.get("allowEmpty") is False:
        del target["allowEmpty"]
    return canonical(value)


def strict(raw, maximum=LIMIT):
    require(isinstance(raw, bytes) and 0 < len(raw) <= maximum and not raw.startswith(b"\xef\xbb\xbf"), "ProvisionJSONRejected")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "ProvisionJSONRejected")
            result[key] = value
        return result
    def forbidden(_):
        raise ProvisionError("ProvisionJSONRejected")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=forbidden, parse_constant=forbidden)
        def check(item, depth=0):
            require(depth <= 16, "ProvisionJSONRejected")
            if isinstance(item, str):
                item.encode("utf-8", "strict")
            elif isinstance(item, dict):
                for key, child in item.items():
                    check(key, depth + 1)
                    check(child, depth + 1)
            elif isinstance(item, list):
                for child in item:
                    check(child, depth + 1)
            elif type(item) is int:
                require(0 <= item <= 9007199254740991, "ProvisionJSONRejected")
            else:
                require(item is None or type(item) is bool, "ProvisionJSONRejected")
        check(value)
        return value
    except Exception:
        raise ProvisionError("ProvisionJSONRejected") from None


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def counter(raw):
    require(type(raw) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", raw) is not None
        and int(raw) <= 18446744073709551615, "ProvisionCounterRejected")
    return int(raw)


class SecureRoot:
    """Linux dirfd boundary; existing private directory, no symlink parents."""
    def __init__(self, path, private=True):
        require(sys.platform == "linux", "ProvisionLinuxRequired")
        path = Path(path)
        require(path.is_absolute() and str(path) != "/" and str(path) == os.path.normpath(str(path)), "ProvisionFileRejected")
        self.path = path
        self.private = private
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for part in path.parts[1:]:
                new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = new
            if private:
                self._directory(fd)
            else:
                require(stat.S_ISDIR(os.fstat(fd).st_mode), "ProvisionFileRejected")
        except Exception:
            os.close(fd)
            raise ProvisionError("ProvisionFileRejected") from None
        self.fd = fd

    def __repr__(self):
        return "<private provision files [redacted]>"

    @staticmethod
    def _directory(fd):
        value = os.fstat(fd)
        require(stat.S_ISDIR(value.st_mode) and value.st_uid == os.geteuid() and not value.st_mode & 0o077, "ProvisionFileRejected")

    @staticmethod
    def parts(path):
        require(type(path) is str and path and not any(char in path for char in ("\\", "\x00")) and not path.startswith("/"), "ProvisionFileRejected")
        result = path.split("/")
        require(all(part not in ("", ".", "..") for part in result), "ProvisionFileRejected")
        return result

    def parent(self, path):
        parts = self.parts(path)
        fd = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = new
                self._directory(fd)
            return fd, parts[-1]
        except Exception:
            os.close(fd)
            raise ProvisionError("ProvisionFileRejected") from None

    def mkdir(self, path):
        require(self.private, "ProvisionFileRejected")
        parent, name = self.parent(path)
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            os.fsync(parent)
        except Exception:
            raise ProvisionError("ProvisionExclusiveCreateRejected") from None
        finally:
            os.close(parent)

    def write(self, path, raw, executable=False):
        require(self.private, "ProvisionFileRejected")
        require(type(raw) is bytes and len(raw) <= max(LIMIT, 256 << 20), "ProvisionFileRejected")
        parent, name = self.parent(path)
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fchmod(stream.fileno(), 0o500 if executable else 0o600)
                os.fsync(stream.fileno())
            os.fsync(parent)
        except Exception:
            raise ProvisionError("ProvisionExclusiveCreateRejected") from None
        finally:
            os.close(parent)

    def read(self, path, maximum=LIMIT):
        parent, name = self.parent(path)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
            return self.read_fd(fd, maximum, private=self.private)
        except Exception:
            raise ProvisionError("ProvisionFileRejected") from None
        finally:
            os.close(parent)

    @staticmethod
    def read_fd(fd, maximum, private=True):
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum
                and (not private or before.st_uid == os.geteuid() and not before.st_mode & 0o077), "ProvisionFileRejected")
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
            require(len(raw) <= maximum and (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink)
                == (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink), "ProvisionFileRejected")
            return raw

    def names(self, path):
        parent, name = self.parent(path)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                self._directory(fd)
                return set(os.listdir(fd))
            finally:
                os.close(fd)
        finally:
            os.close(parent)

    def close(self):
        os.close(self.fd)


def read_external(path, maximum, private=True):
    """Explicit single input; never glob or search a fixture/credential tree."""
    path = Path(path)
    root = SecureRoot(path.parent, private=private)
    try:
        raw = root.read(path.name, maximum)
        return raw
    finally:
        root.close()


class PinnedCLI:
    def __init__(self, files, source, sha256):
        require(HASH.fullmatch(sha256 or "") is not None, "ProvisionBinaryPinRejected")
        # Copy exact public executable bytes into this new private operation
        # tree. No signing key is in the binary, arguments or environment.
        raw = read_external(source, 256 << 20, private=False)
        require(digest(raw) == sha256 and raw.startswith(b"\x7fELF"), "ProvisionBinaryPinRejected")
        files.write("tools/sekvyr-provision", raw, executable=True)
        self.files, self.sha256 = files, sha256

    def __repr__(self):
        return "<hash-pinned offline provision CLI [redacted]>"

    def invoke(self, command, request, output, expected):
        require(command in ("keygen", "public", "genesis", "snapshot", "transition", "bootstrap", "recovery"), "ProvisionCommandRejected")
        parent, name = self.files.parent("tools/sekvyr-provision")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        os.close(parent)
        proc, pidfd = None, None
        try:
            # A read-only private copy plus exec-by-fd closes pathname swapping.
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_mode & 0o777 == 0o500 and before.st_nlink == 1, "ProvisionBinaryPinRejected")
            require(digest(SecureRoot.read_fd(os.dup(fd), 256 << 20)) == self.sha256, "ProvisionBinaryPinRejected")
            proc = subprocess.Popen(["/proc/self/fd/" + str(fd), command, "--work-dir", str(self.files.path),
                "--input", request, "--output", output], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL, pass_fds=(fd,), close_fds=True,
                env={"PATH": "/usr/bin:/bin", "HOME": str(self.files.path), "LANG": "C.UTF-8"})
            pidfd = os.pidfd_open(proc.pid)
            streams = {"stdout": bytearray(), "stderr": bytearray()}
            deadline = time.monotonic() + 90
            with selectors.DefaultSelector() as selected:
                for stream, label in ((proc.stdout, "stdout"), (proc.stderr, "stderr")):
                    os.set_blocking(stream.fileno(), False)
                    selected.register(stream, selectors.EVENT_READ, label)
                while selected.get_map():
                    require(time.monotonic() < deadline, "ProvisionProcessTimedOut")
                    for key, _ in selected.select(min(0.2, max(0, deadline - time.monotonic()))):
                        block = os.read(key.fileobj.fileno(), 4096)
                        if not block:
                            selected.unregister(key.fileobj)
                            continue
                        streams[key.data].extend(block)
                        require(len(streams[key.data]) <= 4096, "ProvisionProcessOutputRejected")
            require(proc.wait(timeout=max(0.01, deadline - time.monotonic())) == 0, "ProvisionCLIRejected")
            require(not streams["stderr"], "ProvisionProcessOutputRejected")
            result = strict(bytes(streams["stdout"]), 4096)
            require(type(result) is dict and set(result) == {"format", "operation", "artifacts", "offline_only", "online_verification_required", "identity_computed"}
                and result["format"] == "sekvyr-offline-provision-receipt-v1" and result["operation"] == command
                and type(result["artifacts"]) is int and result["artifacts"] == len(expected)
                and result["offline_only"] is True and result["online_verification_required"] is True
                and type(result["identity_computed"]) is bool
                and (command == "bootstrap" or result["identity_computed"] is False), "ProvisionProcessOutputRejected")
            require(self.files.names(output) == set(expected), "ProvisionArtifactSetRejected")
            after = os.fstat(fd)
            require((before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "ProvisionBinaryPinRejected")
            return result
        except Exception:
            raise ProvisionError("ProvisionExecutionRejected") from None
        finally:
            termination_failed = False
            if proc is not None:
                if proc.returncode is None:
                    try:
                        if pidfd is not None:
                            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                        else:
                            # Direct, unreaped child only; no wrapper, sudo,
                            # shell, process group or foreign PID.
                            proc.kill()
                    except ProcessLookupError:
                        pass
                    except Exception:
                        termination_failed = True
                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        termination_failed = True
                proc.stdout.close()
                proc.stderr.close()
            if pidfd is not None:
                os.close(pidfd)
            os.close(fd)
            if termination_failed:
                raise ProvisionError("ProvisionProcessTerminationUnconfirmed") from None


class Bundle:
    def __init__(self, files, output, hashes, manifest_hash):
        self._files, self._output, self._hashes, self.manifest_hash = files, output, hashes, manifest_hash

    def __repr__(self):
        return "<exclusive CLI artifact bundle [redacted]>"

    def raw(self, name):
        require(name in self._hashes, "ProvisionArtifactSetRejected")
        raw = self._files.read(self._output + "/" + name)
        require(digest(raw) == self._hashes[name], "ProvisionArtifactChanged")
        return raw

    def value(self, name):
        return strict(self.raw(name))


class CLIProvider:
    def __init__(self, binary, binary_sha256, work, *, registration, authority, scope, panel_origin, node_public,
                 node_fingerprint, key_files, read_key):
        work = Path(work)
        parent = SecureRoot(work.parent)
        try:
            parent.mkdir(work.name)
        finally:
            parent.close()
        self.files = SecureRoot(work)
        for name in ("tools", "inputs", "requests", "outputs", "pins", "keys", "chains"):
            self.files.mkdir(name)
        try:
            self.cli = PinnedCLI(self.files, binary, binary_sha256)
        except Exception:
            self.files.close()
            raise ProvisionError("ProvisionBinaryPinRejected") from None
        self.registration, self.authority, self.scope = copy.deepcopy(registration), copy.deepcopy(authority), copy.deepcopy(scope)
        self.panel_origin = panel_origin
        self.node_public, self.node_fingerprint = bytes(node_public), node_fingerprint
        self.key_files, self.read_key = dict(key_files), bytes(read_key)
        require(set(key_files) == {"admin", "publisher"} and len(read_key) == 32, "ProvisionFixtureRejected")
        self._key_hashes = {}
        self.files.write("pins/registration.json", canonical(self.registration))
        public = {"admin": self.authority["admin_key"], "publisher": self.authority["publisher_keys"][0]}
        require(len(self.authority["publisher_keys"]) == 1 and self.registration["admin_public_key"] == public["admin"]["public_key"], "ProvisionFixtureRejected")
        public["node"] = {"key_id": node_fingerprint, "public_key": base64.urlsafe_b64encode(node_public).decode().rstrip("=")}
        for role, value in public.items():
            self.files.write("pins/" + role + ".json", canonical({"format": "sekvyr-provision-public-key-v1", "role": role, **value}))
        profile = canonical({"scope": self.scope, "authority": self.authority,
            "registration": self.registration, "panel_origin": panel_origin, "node_fingerprint": self.node_fingerprint, "binary_sha256": binary_sha256})
        self.files.write("pins/profile.json", profile)
        self._profile_hash = digest(profile)

    @classmethod
    def from_protocol(cls, binary, sha256, work, protocol):
        return cls(binary, sha256, work, registration=protocol.registration, authority=protocol.authority,
            scope=protocol.scope, panel_origin=protocol.panel_origin, node_public=protocol.node_public, node_fingerprint=protocol.node_fingerprint,
            key_files={role: protocol.root / (role + ".key") for role in ("admin", "publisher")}, read_key=protocol.read_key)

    def __repr__(self):
        return "<offline CLI trial artifact provider [redacted]>"

    def key(self, role):
        require(role in ("admin", "publisher", "read"), "ProvisionRoleRejected")
        path = "keys/" + role + (".bin" if role == "read" else ".pem")
        if role not in self._key_hashes:
            raw = self.read_key if role == "read" else read_external(self.key_files[role], 16 << 10)
            self.files.write(path, raw)
            self._key_hashes[role] = digest(raw)
        require(digest(self.files.read(path)) == self._key_hashes[role], "ProvisionKeyInputChanged")
        return path

    def _operation(self, command, label, request, inputs, expected):
        require(LABEL.fullmatch(label or "") is not None, "ProvisionOperationLabelRejected")
        self.files.mkdir("inputs/" + label)
        for name, raw in inputs.items():
            require(LABEL.fullmatch(name) is not None, "ProvisionInputNameRejected")
            self.files.write("inputs/" + label + "/" + name, raw)
        request_path, output = "requests/" + label + ".json", "outputs/" + label
        self.files.write(request_path, canonical(request))
        paths = [request_path]
        def references(value):
            if isinstance(value, dict):
                for name, child in value.items():
                    if name.endswith("_file") and child:
                        paths.append(child)
                    else:
                        references(child)
        references(request)
        pin = {path: digest(self.files.read(path)) for path in sorted(set(paths))}
        manifest = {"format": "sekvyr-stage8-cli-inputs-v1", "command": command, "label": label,
            "inputs": pin, "expected_artifacts": sorted(expected)}
        raw_manifest = canonical(manifest)
        self.files.write("requests/" + label + "-manifest.json", raw_manifest)
        receipt = self.cli.invoke(command, request_path, output, expected)
        require(all(digest(self.files.read(path)) == value for path, value in pin.items()), "ProvisionInputChanged")
        hashes = {name: digest(self.files.read(output + "/" + name)) for name in sorted(expected)}
        completed = canonical({"format": "sekvyr-stage8-cli-completed-v1", "input_manifest_hash": digest(raw_manifest),
            "artifacts": hashes, "receipt": receipt})
        self.files.write("requests/" + label + "-completed.json", completed)
        return Bundle(self.files, output, hashes, digest(raw_manifest))

    def input_path(self, label, name):
        return "inputs/" + label + "/" + name

    def _chain_guard(self, chain):
        raw_profile = self.files.read("pins/profile.json")
        require(digest(raw_profile) == self._profile_hash, "ProvisionIndependentPinChanged")
        profile = strict(raw_profile)
        require(profile["authority"] == self.authority and profile["scope"] == self.scope
            and profile["registration"] == self.registration and profile["node_fingerprint"] == self.node_fingerprint,
            "ProvisionIndependentPinChanged")
        require(type(chain) is dict and set(chain) == {"registration_file", "records_file", "expected_cursor"}
            and chain["registration_file"] == "pins/registration.json", "ProvisionIndependentPinChanged")
        require(strict(self.files.read("pins/registration.json")) == self.registration, "ProvisionIndependentPinChanged")
        path = chain["records_file"]
        require(type(path) is str and re.fullmatch(r"chains/[a-z][a-z0-9-]{0,63}\.json", path) is not None, "ProvisionChainRejected")
        require(strict(self.files.read(path[:-5] + "-request.json")) == chain, "ProvisionSavedChainChanged")

    def freeze_chain(self, label, records, expected_cursor):
        require(LABEL.fullmatch(label or "") is not None and type(records) is list and 0 < len(records) <= 4096, "ProvisionChainRejected")
        raw = canonical(records)
        require(type(expected_cursor) is dict and set(expected_cursor) == {"journal_sequence", "record_hash"}
            and HASH.fullmatch(expected_cursor["record_hash"] or "") is not None, "ProvisionChainRejected")
        counter(expected_cursor["journal_sequence"])
        require(len(raw) <= LIMIT and type(records[0]) is dict and type(records[0].get("genesis")) is dict
            and records[0]["genesis"].get("body", {}).get("scope") == self.scope, "ProvisionChainRejected")
        self.files.write("chains/" + label + ".json", raw)
        chain = {"registration_file": "pins/registration.json", "records_file": "chains/" + label + ".json",
            "expected_cursor": copy.deepcopy(expected_cursor)}
        # This is not an authority verification; each actual CLI command must
        # replay this complete chain and its original independently pinned floor.
        self.files.write("chains/" + label + "-request.json", canonical(chain))
        return chain

    def genesis(self, label, reviewed_body):
        require(reviewed_body == {"format": "sekvyr-journal-genesis-v1", "scope": self.scope,
            "panel_origin": self.panel_origin, "authority": self.authority, "recovery_from": None}, "ProvisionGenesisContextChanged")
        bundle = self._operation("genesis", label, {"body_file": self.input_path(label, "body"),
            "admin_key_file": self.key("admin"), "admin_public_file": "pins/admin.json"},
            {"body": canonical(reviewed_body)}, {"record.json", "registration.json", "records.json"})
        require(bundle.value("registration.json") == self.registration, "ProvisionOriginalGenesisChanged")
        return bundle

    def snapshot(self, label, chain, previous_snapshot, generation, demo):
        self._chain_guard(chain)
        require(type(generation) is str and type(demo) is str, "ProvisionValuesRejected")
        previous = counter(previous_snapshot["sequence"])
        require(previous < 18446744073709551615, "ProvisionCounterRejected")
        sequence = str(previous + 1)
        header = {"protocol": "e2e2", "suite": "HKDF-SHA256+A256GCM+Ed25519", "intent": "publish", **self.scope,
            "sequence": sequence, "previous_hash": previous_snapshot["envelope_hash"], "read_key_epoch": self.authority["read_key_epoch"],
            "publisher_policy_epoch": self.authority["publisher_policy_epoch"], "publisher_key_id": self.authority["publisher_keys"][0]["key_id"],
            "snapshot_salt": "", "entry_count": 2, "action": "initial" if sequence == "1" else "update", "restored_from": None, "parents": []}
        plain = {"format": "sekvyr-e2e2-values-v1", "context": self.scope, "entries": [
            {"path": "/runtime", "name": "DEMO_VALUE", "value": demo}, {"path": "/runtime", "name": "GENERATION", "value": generation}]}
        return self._operation("snapshot", label, {"chain": chain, "pending": False, "header_file": self.input_path(label, "header"),
            "plaintext_file": self.input_path(label, "plaintext"), "read_key_file": self.key("read"),
            "publisher_key_file": self.key("publisher"), "publisher_public_file": "pins/publisher.json", "recipient_public_file": "pins/node.json"},
            {"header": canonical(header), "plaintext": canonical(plain)}, {"envelope.json", "reader-wrap.json", "candidate.json", "record.json"})

    def transition(self, label, chain, reviewed_body):
        self._chain_guard(chain)
        return self._operation("transition", label, {"chain": chain, "body_file": self.input_path(label, "body"), "admin_key_file": self.key("admin")},
            {"body": canonical(reviewed_body)}, {"transition.json", "record.json"})

    def bootstrap(self, label, chain, config, receipts, binding):
        self._chain_guard(chain)
        return self._operation("bootstrap", label, {"chain": chain, "config_file": self.input_path(label, "config"),
            "receipts_file": self.input_path(label, "receipts"), "binding_file": self.input_path(label, "binding"),
            "node_public_file": "pins/node.json", "trust_key": binding["encryption"]["trustKey"],
            "publisher_key_id": self.authority["publisher_keys"][0]["key_id"]},
            {"config": canonical(config), "receipts": canonical(receipts), "binding": cli_binding(binding)},
            {"installation.json", "trust.json", "state-marker.json", "receipts.json"})

    def recovery(self, label, chain, config, receipts, binding, reviewed_body, retained_state=None):
        self._chain_guard(chain)
        inputs = {"config": canonical(config), "receipts": canonical(receipts), "binding": cli_binding(binding), "body": canonical(reviewed_body)}
        if retained_state is not None:
            require(type(retained_state) is bytes, "ProvisionStateRejected")
            inputs["retained-state"] = retained_state
        return self._operation("recovery", label, {"chain": chain, "config_file": self.input_path(label, "config"),
            "receipts_file": self.input_path(label, "receipts"), "binding_file": self.input_path(label, "binding"),
            "body_file": self.input_path(label, "body"), "state_file": self.input_path(label, "retained-state") if retained_state is not None else "",
            "admin_key_file": self.key("admin")}, inputs, {"plan.json"})

    def close(self):
        self.files.close()
