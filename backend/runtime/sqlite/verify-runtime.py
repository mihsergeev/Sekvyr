"""Acceptance gate for the installed SQLite APK; no external data or disk DBs."""
import json
import sqlite3
import subprocess
from pathlib import Path

VERSION = "3.54.1"
SOURCE_ID = "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76"
REQUIRED_OPTIONS = {
    "ENABLE_FTS3", "ENABLE_FTS3_PARENTHESIS", "ENABLE_FTS4", "ENABLE_FTS5",
    "ENABLE_COLUMN_METADATA", "SECURE_DELETE", "ENABLE_UNLOCK_NOTIFY",
    "ENABLE_RTREE", "ENABLE_GEOPOLY", "USE_URI", "ENABLE_DBSTAT_VTAB",
    "SOUNDEX", "MAX_VARIABLE_NUMBER=250000", "ENABLE_SESSION", "THREADSAFE=1",
}


def verify():
    if sqlite3.sqlite_version != VERSION:
        raise RuntimeError("SQLite version mismatch")
    with sqlite3.connect(":memory:") as connection:
        # This pragma must run before any DML opens an implicit transaction.
        connection.execute("PRAGMA foreign_keys=ON")
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise RuntimeError("SQLite foreign keys unavailable")
        if connection.execute("SELECT sqlite_source_id()").fetchone()[0] != SOURCE_ID:
            raise RuntimeError("SQLite source identity mismatch")
        options = {row[0] for row in connection.execute("PRAGMA compile_options")}
        if not REQUIRED_OPTIONS.issubset(options):
            raise RuntimeError("SQLite compile options mismatch")
        # Exercise the negative-docid prefix-list merge fixed by upstream
        # a7f8c92f623e9cbe8a61266d949916acc9e5110c94dff4aa6fd1ad2ea8a60d4e.
        for detail in ("none", "column", "full"):
            connection.execute(f"CREATE VIRTUAL TABLE probe USING fts5(value, detail={detail})")
            connection.executemany("INSERT INTO probe(rowid,value) VALUES(?,?)",
                                   [(i, "ab") for i in range(1, 56)] + [(-(2**63), "abc")])
            if connection.execute("SELECT count(*) FROM probe('a*')").fetchone()[0] != 56:
                raise RuntimeError("SQLite FTS5 regression")
            connection.execute("DROP TABLE probe")
        connection.execute("CREATE TABLE parent(id INTEGER PRIMARY KEY)")
        connection.execute("CREATE TABLE child(parent_id INTEGER REFERENCES parent(id))")
        connection.execute("INSERT INTO parent VALUES(1)")
        connection.execute("INSERT INTO child VALUES(1)")
        try:
            connection.execute("INSERT INTO child VALUES(2)")
        except sqlite3.IntegrityError:
            pass
        else:
            raise RuntimeError("SQLite foreign key constraint not enforced")
    # Inspect the actual loaded object, not just a library search result.
    mapped = set()
    for line in Path("/proc/self/maps").read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and Path(fields[5]).name.startswith("libsqlite3.so"):
            mapped.add(fields[5])
    if len(mapped) != 1:
        raise RuntimeError("SQLite loaded-library ambiguity")
    library = Path(mapped.pop())
    if library.parent != Path("/usr/lib") or not library.is_file():
        raise RuntimeError("SQLite loaded-library path mismatch")
    owner = subprocess.run(["apk", "--legacy-info", "info", "--who-owns", str(library)],
                           capture_output=True, text=True, check=True).stdout.strip()
    if owner.rsplit(" ", 1)[-1] != "sqlite-libs-3.54.1-r0":
        raise RuntimeError("SQLite library APK ownership mismatch")
    subprocess.run(["apk", "info", "--exists", "sqlite-libs=3.54.1-r0"],
                   capture_output=True, check=True)
    return {"sqliteVersion": VERSION, "sourceIdVerified": True,
            "compileOptionsVerified": True, "fts5NegativeRowidRegression": True,
            "foreignKeyConstraintVerified": True, "loadedLibraryOwnedByAPK": True}


if __name__ == "__main__":
    try:
        print(json.dumps(verify(), sort_keys=True))
    except Exception:
        raise SystemExit("SQLite runtime verification failed") from None
