import asyncio
import tempfile
from contextlib import suppress

import uuid
import os
import os.path
from pathlib import Path, PureWindowsPath
from typing import Union, Optional
from .constants import VENDOR_DIR, PLATFORM_OS


def as_wine_path(filename: 'str', *, check_exists=False) -> 'PureWindowsPath':  # noqa
    """Converts a Unix path to the corresponding WinNT path"""
    root, *rest = Path(filename).absolute().resolve().parts
    return PureWindowsPath('Z:\\').joinpath(*(p.replace('/', '\\') for p in rest))


async def winepath(path: 'os.PathLike', output='Windows') -> 'PureWindowsPath':
    """Run `winepath` on `path`, converting a Unix/Windows path to it's counterpart.

    `as_windows_filename` is considerably faster when converting an ordinary Unix path for WINE
    """
    proc = await asyncio.create_subprocess_exec(
        'winepath', {
            'Unix': '-u',
            'Windows': '-w',
            'DOS': '-s'
        }[output],
        os.path.abspath(path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        stdin=asyncio.subprocess.DEVNULL
    )
    npath = await asyncio.wait_for(proc.stdout.readline(), timeout=2.0)
    return PureWindowsPath(npath.decode().strip())


class ArtifactTempfile:
    """sync & async ctxmgr for temporary artifacts

    Notes::

    You may supply bytes as the first argument, which will be
    written to a file whose path is returned to you.

        >>> blob = b'hello world'
        >>> async with ArtifactTempfile(blob) as path:
        >>>     scan(path)
        ScanResult(bit=True, verdict=False)

    If you have a filename you'd like to use, you can provide
    it with the `filename` argument (you can still supply some bytes
    as the first argument if you'd like to overwrite that file)

        >>> with ArtifactTempfile(blob, filename='/tmp/existing') as path:
        >>>     with open(path, 'r') as of:
        >>>         of.read()
        'hello world'

    In either case, the underlying file is *always* deleted

    Warning::

    **THIS OBJECT NO LONGER RETURNS A FILE-LIKE OBJECT**

    The limited (nonexistent) users of `AsyncArtifactTempfile` which
    needed to manipulate the fileobj, together with the number of
    engines which required manually closing the fileobj before scanning [1]_,
    has motivated a change to a simpler context manager which returns a
    *filename*, which is deleted after the context exits.

    .. [1] Some Windows engines refuse to scan files with existing open file handles
    """
    def __init__(self, blob: 'bytes' = None, filename: 'str' = None):
        self.blob = blob
        self.name = filename

    async def __aenter__(self):
        return await asyncio.get_event_loop().run_in_executor(None, self.__enter__)

    async def __aexit__(self, exc, value, tb):
        return await asyncio.get_event_loop().run_in_executor(None, self.__exit__, exc, value, tb)

    def __enter__(self):
        self.name = self.name or os.path.join(tempfile.gettempdir(), f'artifact-{uuid.uuid4()}')

        if self.blob:
            # create a new empty file and grant the fd write privileges alone
            flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
            if PLATFORM_OS == 'Windows':
                flags |= os.O_BINARY

            RDWR_NOEXEC = 0o666  # create our underlying file as +rw-x

            with open(os.open(self.name, flags, RDWR_NOEXEC), 'w+b', closefd=True) as f:
                f.write(self.blob)

        del self.blob
        return self.name

    def __exit__(self, exc, value, tb):
        os.unlink(self.name)
        return False


try:
    import puremagic

    async def content_type(content: 'Union[bytes, bytearray]') -> 'Optional[str]':
        """Guesses an extension suffix (with a starting '.') for `content`"""
        try:
            return await asyncio.get_running_loop().run_in_executor(None, puremagic.from_string, content)
        except puremagic.PureError:
            return None
except ImportError:
    pass
