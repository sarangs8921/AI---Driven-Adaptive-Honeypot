from __future__ import annotations

import os
import tempfile

from cowrie.shell.fs import HoneyPotFilesystem


def main() -> None:
    print("Creating test Cowrie filesystem...")

    # Create a standalone Cowrie virtual filesystem.
    fs = HoneyPotFilesystem(
        arch="linux-x64-lsb",
        home="/root",
    )

    virtual_path = "/tmp/system_backup.txt"

    # Make sure the parent directory exists.
    if not fs.exists("/tmp"):
        print("ERROR: /tmp does not exist")
        return

    # Do not duplicate the test file.
    if fs.exists(virtual_path):
        print("ERROR: decoy already exists")
        return

    content = """SYSTEM BACKUP REPORT
====================
Hostname: svr04
Backup status: completed
Backup ID: BKP-2026-0928
Last backup: 2026-09-28
Database status: healthy
"""

    print("Creating virtual file...")

    created = fs.mkfile(
        virtual_path,
        uid=0,
        gid=0,
        size=len(content.encode("utf-8")),
        mode=0o644,
    )

    if not created:
        print("ERROR: mkfile failed")
        return

    # Get the virtual filesystem node.
    node = fs.getfile(virtual_path)

    if node is None:
        print("ERROR: could not retrieve virtual file")
        return

    # Create safe temporary backing content.
    fd, backing_path = tempfile.mkstemp(
        prefix="cowrie-decoy-",
        suffix=".txt",
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)

        # Connect the virtual Cowrie file to the synthetic content.
        fs.update_realfile(node, backing_path)

        print()
        print("SUCCESS")
        print("Virtual path :", virtual_path)
        print("Backing path :", backing_path)
        print()

        # Verify that Cowrie's filesystem can read it.
        result = fs.file_contents(virtual_path)

        print("CONTENT RETURNED BY COWRIE:")
        print("--------------------------------")
        print(result.decode("utf-8"))
        print("--------------------------------")

    finally:
        # Remove temporary backing file.
        try:
            os.unlink(backing_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()