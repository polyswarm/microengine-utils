from base64 import b64decode
from functools import lru_cache, partial
from pathlib import Path
from itertools import chain, groupby, tee
from collections import namedtuple, defaultdict
from contextlib import suppress
from polyswarmartifact.schema import Verdict
import pytest
from polyswarmartifact import ArtifactType

from typing import Optional, Union, All, Callable, ClassVar
from dataclasses import field, dataclass, asdict


@dataclass(frozen=True, eq=False)
class Artifixture:
    FIXTURES_ROOT: ClassVar[Path] = Path(__file__).parent

    fixture: str
    mime: str
    bit: bool = field(default=True)
    verdict: bool = field(default=True)
    packer: Optional[str] = field(default=None)

    is_encrypted: bool = field(default=False)
    is_denial_of_service: bool = field(default=False)
    is_packed = property(lambda self: self.packer is not None)

    _parts = property(lambda self: self.name.split('/'))
    conclusion = property(lambda self: self._parts[0])
    extension = property(lambda self: self._parts[1])
    name = property(lambda self: self._parts[2])

    path = property(lambda self: self.FIXTURES_ROOT.joinpath(self.fixture))

    def _read_content(self):
        path = self.FIXTURES_ROOT.joinpath(self.fixture)
        return path.read_bytes() if path.exists() else b64decode(Path(str(path) + '.b64').read_bytes())

    content: Union[bytes, Callable] = field(default=property(lru_cache(1)(_read_content)))

    def parametrize(self):
        return pytest.param(self, id=f'{self.name} [{self.conclusion}]')


class ArtifixtureIterator:
    def __init__(self, src, proc=iter):
        self.src = src
        self.proc = proc

    def __iter__(self):
        yield from self.proc(self.src)

    def filter(self, pred):
        return ArtifixtureIterator(self, partial(filter, pred))

    def exclude(self, **props):
        return self.filter(lambda o: all(getattr(o, k, v) != v for k, v in props.items()))

    def include(self, **props):
        return self.filter(lambda o: any(getattr(o, k, v) == v for k, v in props.items()))


FIXTURES = [
    Artifixture('benign/pe/dotnet.exe', mime='application/x-dosexec', verdict=False),
    Artifixture('benign/pe/i386.exe', mime='application/x-dosexec', verdict=False),
    Artifixture('benign/pe/x86_64.exe', mime='application/x-dosexec', verdict=False),
    Artifixture('malicious/7z/encrypted:eicar.7z', mime='application/x-7z-compressed', is_encrypted=True, bit=False),
    Artifixture('malicious/7z/folder.7z', mime='application/x-7z-compressed'),
    Artifixture('malicious/elf/amd64:cornel', mime='application/x-executable'),
    Artifixture('malicious/elf/ARM:Android:lootor', mime='application/x-executable'),
    Artifixture('malicious/elf/i386:blitz', mime='application/x-executable'),
    Artifixture('malicious/elf/SPARC:SunOS:sunkit', mime='application/x-executable'),
    Artifixture('malicious/jar/CVE20121723:axd.jar', mime='application/java-archive'),
    Artifixture('malicious/lnk/reconyc.lnk', mime='application/octet-stream'),
    Artifixture('malicious/macho/ARM:ikee', mime='application/x-mach-binary'),
    Artifixture('malicious/macho/i386-amd64:universal:flashback', mime='application/x-mach-binary'),
    Artifixture('malicious/macho/PPC:cmcradar', mime='application/x-mach-binary'),
    Artifixture('malicious/office/CDFv2:word97:sagent.doc', mime='application/msword'),
    Artifixture('malicious/office/word2007:stratos.docx', mime='application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
    Artifixture('malicious/pdf/CVE20100188:pidief.pdf', mime='application/pdf'),
    Artifixture('malicious/pe/amd64:heuristic.exe', mime='application/x-dosexec'),
    Artifixture('malicious/pe/i386:NSIS:heuristic.exe', mime='application/x-dosexec'),
    Artifixture('malicious/pe/i386:UPX:mydoom.exe', mime='application/x-dosexec'),
    Artifixture('malicious/pe/i386:waledac.exe', mime='application/x-dosexec'),
    Artifixture('malicious/powershell/pegazus.ps1', mime='text/plain'),
    Artifixture('malicious/rar/encrypted:eicar.rar', mime='application/x-rar', is_encrypted=True, bit=False),
    Artifixture('malicious/rar/folder.rar', mime='application/x-rar'),
    Artifixture('malicious/rtf/CVE20103333.rtf', mime='text/rtf'),
    Artifixture('malicious/tar/folder.tar.gz', mime='application/x-gzip'),
    Artifixture('malicious/tar/DOS:infinite.tar.gz', mime='application/x-gzip', is_denial_of_service=True, bit=False),
    Artifixture('malicious/zip/DOS:infinite.zip', mime='application/zip', is_denial_of_service=True, bit=False),
    Artifixture('malicious/zip/DOS:non_recursive_overlapping.zip', mime='application/zip', is_denial_of_service=True, bit=False),
    Artifixture('malicious/zip/encrypted:eicar.zip', mime='application/zip', is_encrypted=True, bit=False),
    Artifixture('malicious/zip/folder.zip', mime='application/zip')
]

scan_fixtures = ArtifixtureIterator(FIXTURES)


@pytest.fixture(scope='module')
@pytest.mark.asyncio
async def scanner(request):
    Scanner = getattr(request.module, "smtpserver", "smtp.gmail.com")
    sobj = Scanner()
    await sobj.setup()
    yield sobj
    if hasattr(sobj, 'teardown'):
        await sobj.teardown()


@pytest.fixture(
    scope='function',
    params=map(
        lambda a: a.parametrize(),
        scan_fixtures.exclude(bit=False, is_denial_of_service=True, is_encrypted=True)
    )
)
def scannable(request):
    fx = request.param
    if fx.is_encrypted:
        request.applymarker(pytest.mark.is_encrypted)
    elif fx.is_denial_of_service:
        request.applymarker(pytest.mark.is_denial_of_service)


@pytest.fixture(scope='function')
def eicar():
    return Artifixture('malicious/eicar/eicar', mimetype='text/plain').parametrize()


@pytest.fixture
def scanguid():
    return 'nocare'


def test_scan_eicar(scanfn, engine_info, eicar):
    scanity_check(scanfn(eicar.content, ArtifactType.FILE), eicar, engine_info=engine_info)


def test_scan_artifacts(scanfn, engine_info, artifact):
    scanity_check(scanfn(artifact.content, ArtifactType.FILE), artifact, engine_info=engine_info)


def test_scan_encrypted_archives(scanfn, engine_info, encrypted):
    scanfn = getattr(scanfn, '__wrapped__', scanfn)
    with pytest.raises(Exception):
        scanfn.__wrapped__(encrypted.content, ArtifactType.FILE)


def scanity_check(
    scan: 'ScanResult',
    expected: 'Optional[Artifixture]' = None,
    bit=None,
    verdict=None,
    engine_info: 'Optional[EngineInfo]' = None
):
    if bit is None:
        bit = expected.bit

    if type(bit) is not bool:
        raise ValueError("Invalid bit or fixture object: ", bit, expected)

    if verdict is None:
        verdict = expected.verdict

    assert scan.bit is bit

    assert isinstance(scan.metadata, (str, type(None)))
    if scan.metadata is not None:
        meta = Verdict.parse_raw(scan.metadata)

        if bit is True:
            assert 'scan_error' not in meta.__dict__

        if engine_info is not None:
            scanner = Verdict.parse_raw(scan.metadata).scanner
            for k, value in engine_info.scanner_info().items():
                assert getattr(scanner, k) == value

    if scan.verdict is not verdict:
        return pytest.xfail()
