import asyncio
import tempfile

import functools
import platform
import uuid
import shutil
from os import getenv
import os.path
from pathlib import PureWindowsPath
from typing import Union, Optional


def path_template(tmpl):
    if platform.system() == 'Windows':
        MICROENGINE_INSTALL_ROOT = getenv('PSC_INSTALL_DIR', 'C:\\microengine\\')
    else:
        MICROENGINE_INSTALL_ROOT = getenv('PSC_INSTALL_DIR', '/usr/src/app/')

    return tmpl.format_map({'VENDOR_ROOT': os.path.join(MICROENGINE_INSTALL_ROOT, '/vendor/')})


def as_windows_filename(path: 'os.PathLike') -> 'PureWindowsPath':
    """Converts a Unix path to the corresponding WinNT path"""
    return PureWindowsPath('Z:').joinpath(os.path.abspath(path)).replace('/', '\\')


async def winepath(path: 'os.PathLike', output='windows') -> 'PureWindowsPath':
    """Run `winepath` on `path`, converting a Unix/Windows path to it's counterpart.

    `as_windows_filename` is considerably faster when converting an ordinary Unix path for WINE
    """
    proc = await asyncio.create_subprocess_exec(
        'winepath', {
            'unix': '-u',
            'windows': '-w',
            'dos': '-s'
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
    def __init__(self, blob: 'bytes' = None, filename: 'str' = None, mode: 'str' = 'w+b'):
        if not filename:
            filename = os.path.join(tempfile.gettempdir(), f'artifact-{uuid.uuid4()}')
        self.name = filename

        flags = (
            os.O_RDWR |  # open fd for both reading and writing
            os.O_CREAT |  # create if doesn't already exist
            getattr(os, 'O_BINARY', 0) |  # WinNT requires this for binary files
            getattr(os, 'O_SEQUENTIAL', 0)  # optimize for (but don't require) sequential access
        )

        fd = os.open(self.name, flags, 0o666)
        try:
            self.file = open(fd, mode, buffering=0, closefd=True)
        except:  # noqa
            os.close(fd)

        self.blob = blob
        self._executor = asyncio.get_event_loop().run_in_executor

    def __enter__(self):
        self.file.__enter__()
        if self.blob is not None:
            self.file.truncate()
            self.file.write(self.blob)
            self.file.seek(0)
            self.blob = None
        self.file.close()
        return self.name

    def __exit__(self, exc, value, tb):
        try:
            os.unlink(self.name)
        except FileNotFoundError:  # noqa
            return False
        else:
            return True

    async def __aenter__(self):
        return await self._executor(self.__enter__)

    # trap __aexit__ to ensure the file gets deleted when used in `async with`
    async def __aexit__(self, exc, value, tb):
        return await self._executor(self.__exit__, exc, value, tb)


try:
    import puremagic

    async def content_type(content: 'Union[bytes, bytearray]') -> 'Optional[str]':
        """Guesses an extension suffix (with a starting '.') for `content`"""
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, puremagic.from_string, content)
        except puremagic.PureError:
            return None

except ImportError:
    pass
