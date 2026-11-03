"""Temporary Git fixtures only; never inspect the real ignored signing key."""

import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "selfcheck.py"
spec = importlib.util.spec_from_file_location("sekvyr_selfcheck_inventory", SOURCE)
selfcheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selfcheck)


class InventoryPrivacyGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sekvyr-selfcheck-source-")
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name).resolve()
        self.repo = self.parent / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", str(self.repo)], check=True, capture_output=True)
        (self.repo / ".gitignore").write_text("agent-signing-key.txt\nignored.txt\nprivate/\n", encoding="utf-8")
        (self.repo / "tracked.py").write_text("# public tracked source\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", ".gitignore", "tracked.py"], check=True, capture_output=True)
        self.canary = "SYNTHETIC_SIGNING_CANARY_NEVER_READ"
        (self.repo / "agent-signing-key.txt").write_text(self.canary + "\u200b", encoding="utf-8")
        (self.repo / "ignored.txt").write_text("SYNTHETIC_IGNORED_TEXT\u200b", encoding="utf-8")
        (self.repo / "private").mkdir()
        (self.repo / "private" / "hidden.py").write_text("SYNTHETIC_PRIVATE_SOURCE\u200b", encoding="utf-8")
        self.previous = Path.cwd()
        os.chdir(self.repo)
        self.addCleanup(os.chdir, self.previous)
        selfcheck.PROBLEMS.clear()
        self.addCleanup(selfcheck.PROBLEMS.clear)
        self.read_opens = []
        active = {"value": True}
        self.addCleanup(active.update, value=False)
        # Audit real open/os.open events, not just the scanner's read wrapper.
        def audit(event, args):
            if not active["value"] or event != "open" or not isinstance(args[0], (str, bytes, os.PathLike)):
                return
            path = Path(os.fsdecode(args[0]))
            path = path if path.is_absolute() else Path.cwd() / path
            flags = args[2] if isinstance(args[2], int) else 0
            if not flags & (os.O_WRONLY | os.O_RDWR):
                self.read_opens.append(path)
                if path.name.casefold() == "agent-signing-key.txt":
                    raise AssertionError("Synthetic ignored signing material was opened")
        sys.addaudithook(audit)

    def test_git_inventory_reads_tracked_and_untracked_but_never_ignored_key_or_text(self):
        (self.repo / "new-source.py").write_text("# NEW_UNTRACKED\u200b\n", encoding="utf-8")
        selfcheck.check_invisible_chars()
        self.assertTrue(any("new-source.py:1:" in value for value in selfcheck.PROBLEMS))
        self.assertIn(self.repo / "tracked.py", self.read_opens)
        self.assertIn(self.repo / "new-source.py", self.read_opens)
        self.assertNotIn(self.repo / "agent-signing-key.txt", self.read_opens)
        self.assertNotIn(self.repo / "ignored.txt", self.read_opens)
        self.assertNotIn(self.repo / "private" / "hidden.py", self.read_opens)
        self.assertFalse(any("SYNTHETIC" in value for value in selfcheck.PROBLEMS))

    def test_protected_filename_direct_read_is_refused_before_any_open(self):
        for name in ("agent-signing-key.txt", "AGENT-SIGNING-KEY.TXT", "agent-signing-key.txt.", "agent-signing-key.txt ", "agent-signing-key.txt::$DATA"):
            with self.subTest(name=name), self.assertRaises(selfcheck.SourceReadError):
                selfcheck.read(name)
        self.assertFalse(self.read_opens)

    def test_force_added_protected_filename_fails_without_opening_material(self):
        # A staged filename remains listed even if .gitignore matches it. Inject
        # the inventory, rather than making Git itself read/stage a private key.
        with patch.object(selfcheck, "_source_inventory", return_value=["agent-signing-key.txt"]):
            selfcheck.check_invisible_chars()
        self.assertTrue(selfcheck.PROBLEMS)
        self.assertFalse(self.read_opens)

    def test_git_unavailable_is_fail_closed_and_does_not_walk_fallback(self):
        with patch.object(selfcheck.subprocess, "run", side_effect=FileNotFoundError("PUBLIC Git unavailable")),\
                patch.object(selfcheck.os, "walk", side_effect=AssertionError("No filesystem fallback")):
            selfcheck.check_invisible_chars()
        self.assertTrue(selfcheck.PROBLEMS)
        self.assertFalse(self.read_opens)

    def test_git_error_output_is_not_reported_and_never_leads_to_source_reads(self):
        failure = subprocess.CalledProcessError(1, ["git"], output=self.canary.encode(), stderr=self.canary.encode())
        with patch.object(selfcheck.subprocess, "run", side_effect=failure):
            selfcheck.check_invisible_chars()
        self.assertTrue(selfcheck.PROBLEMS)
        self.assertNotIn(self.canary, str(selfcheck.PROBLEMS))
        self.assertFalse(self.read_opens)

    def test_escape_or_non_nul_terminated_git_path_is_refused(self):
        for bad in (b"../outside.py\0", b"/outside.py\0", b"C:/outside.py\0", b"nested/../outside.py\0", b"new.py"):
            selfcheck.PROBLEMS.clear()
            result = [SimpleNamespace(stdout=os.fsencode(str(self.repo)) + b"\n"), SimpleNamespace(stdout=bad)]
            with self.subTest(path=bad), patch.object(selfcheck.subprocess, "run", side_effect=result):
                selfcheck.check_invisible_chars()
            self.assertTrue(selfcheck.PROBLEMS)
        self.assertFalse(self.read_opens)

    def test_outside_symlink_is_not_read_even_with_nontext_suffix(self):
        outside = self.parent / "outside.txt"
        outside.write_text("PUBLIC_OUTSIDE_CANARY\u200b", encoding="utf-8")
        link = self.repo / "outside.bin"
        try:
            link.symlink_to(outside)
        except OSError:
            # Windows without symlink privilege still runs the same metadata
            # refusal branch. Linux CI uses the native symlink above.
            link.write_bytes(b"PUBLIC_METADATA_FIXTURE")
            original = Path.lstat
            def symlink_stat(path):
                if path == link:
                    return SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
                return original(path)
            with patch.object(Path, "lstat", symlink_stat):
                selfcheck.check_invisible_chars()
        else:
            selfcheck.check_invisible_chars()
        self.assertTrue(selfcheck.PROBLEMS)
        self.assertNotIn(outside, self.read_opens)
        self.assertNotIn(link, self.read_opens)

    def test_parent_directory_symlink_escape_and_direct_absolute_escape_are_denied(self):
        outside = self.parent / "outside.py"
        outside.write_text("PUBLIC_OUTSIDE_SOURCE\u200b", encoding="utf-8")
        with self.assertRaises(selfcheck.SourceReadError):
            selfcheck.read(str(outside))
        self.assertNotIn(outside, self.read_opens)
        link = self.repo / "linked"
        try:
            link.symlink_to(self.parent, target_is_directory=True)
        except OSError:
            original = Path.lstat
            def symlink_stat(path):
                if path == link:
                    return SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
                return original(path)
            with patch.object(Path, "lstat", symlink_stat), self.assertRaises(selfcheck.SourceReadError):
                selfcheck.read("linked/outside.py")
        else:
            with self.assertRaises(selfcheck.SourceReadError):
                selfcheck.read("linked/outside.py")
        self.assertNotIn(link / "outside.py", self.read_opens)

    def test_identity_change_after_open_is_refused_before_reading(self):
        original = selfcheck.os.fstat
        for change in ("inode", "links"):
            def replaced(fd):
                before = original(fd)
                return SimpleNamespace(st_mode=before.st_mode, st_nlink=2 if change == "links" else before.st_nlink,
                    st_dev=before.st_dev, st_ino=before.st_ino + (change == "inode"))
            with self.subTest(change=change), patch.object(selfcheck.os, "fstat", side_effect=replaced),\
                    patch.object(selfcheck.io, "open", side_effect=AssertionError("No bytes read after identity/link mismatch")),\
                    self.assertRaises(selfcheck.SourceReadError):
                selfcheck.read("tracked.py")

    def test_hardlink_alias_to_ignored_key_is_rejected_before_open_or_read(self):
        key, alias = self.repo / "agent-signing-key.txt", self.repo / "new-nonignored.txt"
        original = Path.lstat
        def linked_stat(path):
            info = original(path)
            if path == alias:
                return SimpleNamespace(st_mode=info.st_mode, st_nlink=2, st_file_attributes=0)
            return info
        try:
            os.link(key, alias)
        except OSError:
            # Some test filesystems lack native hardlinks; exercise the same
            # regular-file metadata branch without opening the ignored key.
            alias.write_text("PUBLIC_METADATA_HARDLINK_FIXTURE", encoding="utf-8")
            context = patch.object(Path, "lstat", linked_stat)
        else:
            self.assertGreater(alias.lstat().st_nlink, 1)
            context = patch.object(Path, "lstat", original)
        with context, patch.object(selfcheck.io, "open", side_effect=AssertionError("No content read through a hardlink")):
            with self.assertRaisesRegex(selfcheck.SourceReadError, "hardlinked"):
                selfcheck.read(str(alias))
        self.assertNotIn(alias, self.read_opens)
        self.assertNotIn(key, self.read_opens)
        # The real Git inventory includes the new alias but excludes the key.
        with context:
            selfcheck.check_invisible_chars()
        self.assertTrue(selfcheck.PROBLEMS)
        self.assertNotIn(alias, self.read_opens)
        self.assertNotIn(key, self.read_opens)
        self.assertNotIn(self.canary, str(selfcheck.PROBLEMS))

    def test_deleted_tracked_source_does_not_force_read_or_skip_untracked_source(self):
        (self.repo / "tracked.py").unlink()
        (self.repo / "new.txt").write_text("PUBLIC_UNTRACKED\u200b", encoding="utf-8")
        selfcheck.check_invisible_chars()
        self.assertEqual(len(selfcheck.PROBLEMS), 1)
        self.assertIn("new.txt:1:", selfcheck.PROBLEMS[0])


if __name__ == "__main__":
    unittest.main()
