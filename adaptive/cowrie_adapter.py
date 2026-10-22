from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any


class CowrieAdaptiveFilesystem:
    """
    Safe adapter for modifying the filesystem of one active Cowrie
    HoneyPotFilesystem instance.

    Only creates inert decoy files inside Cowrie's virtual filesystem.
    """

    def __init__(self, filesystem: Any) -> None:
        self.fs = filesystem
        self.backing_files: list[str] = []

    def create_decoy_file(
        self,
        virtual_path: str,
        content: str,
        uid: int = 0,
        gid: int = 0,
        mode: int = 0o644,
    ) -> bool:
        """
        Create a virtual Cowrie file and attach safe synthetic content.
        """

        # Make sure the parent directory exists.
        parent = os.path.dirname(virtual_path)

        if not self.fs.exists(parent):
            return False

        # Don't overwrite an existing virtual file.
        if self.fs.exists(virtual_path):
            return False

        # Create a private virtual file.
        created = self.fs.mkfile(
            virtual_path,
            uid,
            gid,
            len(content.encode("utf-8")),
            mode,
        )

        if not created:
            return False

        # Retrieve the newly-created virtual file node.
        node = self.fs.getfile(virtual_path)

        if node is None:
            return False

        # Create an inert backing file outside Cowrie's virtual filesystem.
        fd, backing_path = tempfile.mkstemp(
            prefix="cowrie-decoy-",
            suffix=".txt",
        )

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)

            # Attach backing file to the virtual Cowrie file.
            self.fs.update_realfile(node, backing_path)

            self.backing_files.append(backing_path)

            return True

        except Exception:
            try:
                os.unlink(backing_path)
            except OSError:
                pass
            raise

    def cleanup(self) -> None:
        """Remove temporary backing files created by this adapter."""

        for path in self.backing_files:
            try:
                Path(path).unlink()
            except FileNotFoundError:
                pass

        self.backing_files.clear()