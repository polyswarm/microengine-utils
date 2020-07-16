import asyncio
import tempfile
from contextlib import suppress

import platform
import uuid
import os
import os.path
from pathlib import Path, PureWindowsPath
from typing import Union, Optional
from .constants import VENDOR_DIR


def as_wine_filename(path: 'os.PathLike') -> 'PureWindowsPath':
    """Converts a Unix path to the corresponding WinNT path"""
    return PureWindowsPath('Z:').joinpath(os.path.abspath(path)).replace('/', '\\')


def vendor_path(*parts: 'str', winnt=False, check_exists=True) -> 'str':
    """

    >>> vendor_path('engine', 'scanner.exe')
    '/usr/src/app/vendor/engine/scanner.exe'

    >>> vendor_path('engine', 'scanner.exe', winnt=True)
    'Z:\\usr\\src\\app\\vendor\\engine\\scanner.exe'

    """
    f = Path(VENDOR_DIR).joinpath(vendordir)
    if check_exists and not f.exists():
        raise FileNotFoundError(str(f))
    return str(as_wine_filename(f) if winnt else f.as_posix())


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
        return await self.asyncio.get_event_loop().run_in_executor(self.__enter__)

    async def __aexit__(self, exc, value, tb):
        return await self.asyncio.get_event_loop().run_in_executor(self.__exit__, exc, value, tb)

    def __enter__(self):
        self.name = self.name or os.path.join(tempfile.gettempdir(), f'artifact-{uuid.uuid4()}')

        if self.blob:
            # create a new empty file and grant the fd write privileges alone
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if platform.platform() == 'Windows':
                flags |= os.O_SEQUENTIAL | os.O_BINARY

            RDWR_NOEXEC = 0o666  # create our underlying file as +rw-x

            with open(os.open(self.name, flags, RDWR_NOEXEC), 'w+b', closefd=True) as f:
                f.write(self.blob)

        del self.blob
        return self.name

    def __exit__(self, exc, value, tb):
        with suppress(FileNotFoundError):  # noqa
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
