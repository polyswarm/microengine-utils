import asyncio
import tempfile
from contextlib import suppress

import pydantic
import platform
import uuid
import os
import os.path
from pathlib import Path, PureWindowsPath
from typing import Union, Optional
from .constants import VENDOR_DIR, PLATFORM


class ArtifactFilename(collections.UserString):
    def __format__(self, fspec):
        if 'wine' in fspec:
            return as_wine_filename(self.data) if 'wine' in fspec
        else:
            super().__format__(fspec)


def as_wine_filename(path: 'os.PathLike') -> 'PureWindowsPath':
    """Converts a Unix path to the corresponding WinNT path"""
    return PureWindowsPath('Z:').joinpath(os.path.abspath(path)).replace('/', '\\')


# class UniversalPath(Path):
#     def __init__(self, path: 'os.PathLike'):
#         self.is_winepath = self.is_winnt(path) and PLATFORM != 'Windows'
#         if self.is_winepath:
#             super().__init__(self.to_realpath(path))
#         else:
#             super().__init__(path)

#     @classmethod
#     def to_realpath(cls, path: 'os.PathLike'):
#         """Converts a WINE (or real) path to one understood by the host"""
#         path_fmt = 'Windows' if PLATFORM == 'Windows' else 'Unix'
#         p = asyncio.run(winepath(path, output=path_fmt)) if is_winnt(path) else path
#         return Path(p)

#     @classmethod
#     def to_winepath(cls, path: 'os.PathLike'):
#         """Converts a WINE (or real) path to one understood by the host"""
#         p = path if cls.is_winnt(path) else asyncio.run(winepath(path, output='windows'))
#         return PureWindowsPath(p)

#     @classmethod
#     def is_winnt(cls, path: 'os.PathLike'):
#         return '\\' in str(path)


# class UniversalFilename(UniversalPath):
#     @classmethod
#     def __modify_schema__(cls, field_schema: Dict[str, Any]) -> None:
#         field_schema.update(format='file-path')

#     @classmethod
#     def __get_validators__(cls) -> 'CallableGenerator':
#         universal_path_validator
#         yield cls.validate

#     @classmethod
#     def validate(cls, value: Path) -> Path:
#         if not value.is_file():
#             raise FileNotFoundError

#         return value


# class UniversalDirectory(UniversalPath):
#     @classmethod
#     def __modify_schema__(cls, field_schema: Dict[str, Any]) -> None:
#         field_schema.update(format='directory-path')

#     @classmethod
#     def __get_validators__(cls) -> 'CallableGenerator':
#         universal_path_validator
#         yield cls.validate

#     @classmethod
#     def validate(cls, value: Path) -> Path:
#         if not value.is_dir():
#             raise NotADirectoryError

#         return value


async def winepath(path: 'os.PathLike', output='windows') -> 'PureWindowsPath':
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


def universal_path_validator(v: Any) -> Path:
    p = UniversalPath(v)
    if p.exists():
        return p
    else:
        raise pydantic.errors.PathNotExistsError(path=v)

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


class MicroengineConfig(BaseSettings):
    INSTALL_DIR: DirectoryPath
    VENDOR_DIR: DirectoryPath

    CMD_EXE: Optional[FilePath]
    FILESCAN_CMD: Optional[str]
    UPDATE_CMD: Optional[str]

    class Config:
        env_prefix = 'MICROENGINE_'


microengine_config = MicroengineConfig()


class ArtifactFilename:
    filename: 'str'

    def __init__(self, filename: 'str'):
        self.filename = filename

    def __format__(self, fspec):
        if 'WINE' in fspec:
            return as_wine_filename(self.filename)
        return self.filename


class CommandRunner:
    def __init__(self, cmd: 'str'):
        self.cmd = cmd

    async def run(self, blob):
        async with ArtifactTempfile(blob) as filename:
            self.create_scanner_exec(self.cmd.format(path=filename, config=microengine_config()))


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
        return ArtifactFilename(self.name)

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
