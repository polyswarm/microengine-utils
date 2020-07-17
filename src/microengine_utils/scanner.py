import asyncio
from functools import wraps
import platform
from contextlib import suppress
from datetime import datetime
from operator import attrgetter, itemgetter
from time import perf_counter
from typing import (TYPE_CHECKING, Callable, Mapping, NewType, Optional, Text, Tuple, TypedDict, Union)

from polyswarmartifact import ArtifactType
from polyswarmartifact.schema.verdict import Verdict
from polyswarmclient import ScanResult

from .datadog import (
    SCAN_FAIL, SCAN_NO_RESULT, SCAN_SUCCESS, SCAN_TIME, SCAN_TYPE_INVALID, SCAN_VERDICT, statsd
)
from .errors import (
    BaseScanError, CalledProcessScanError, CommandNotFoundScanError, MalformedResponseScanError,
    TimeoutScanError
)


async def create_scanner_exec(
    *cmd: 'str',
    stdout: 'asyncio.StreamReader' = asyncio.subprocess.PIPE,
    stderr: 'asyncio.StreamReader' = asyncio.subprocess.PIPE,
    stdin: 'asyncio.StreamReader' = asyncio.subprocess.DEVNULL,
    check: 'bool' = False,
    timeout: 'int' = 15,
) -> 'Tuple[int, Text, ...]':
    """Run an engine filescan `cmd`, timing out after `timeout` seconds"""
    try:
        proc = await asyncio.subprocess.create_subprocess_exec(
            *cmd,
            stdout=stdout,
            stderr=stderr,
            stdin=stdin,
        )
        streams = await proc.communicate()
        if check and proc.returncode != 0:
            raise CalledProcessScanError(cmd, f'Non-zero return code: {proc.returncode}')
        return (
            proc.returncode,
            *(s.decode(errors='ignore') if isinstance(s, bytes) else str(s or '') for s in streams)
        )
    except FileNotFoundError:  # noqa
        raise CommandNotFoundScanError(cmd)
    except (BrokenPipeError, ConnectionResetError) as e:  # noqa
        proc.kill()
        raise CalledProcessScanError(cmd, str(type(e)))
    except asyncio.TimeoutError as e:
        proc.kill()
        raise TimeoutScanError


def collect_scan(verbose: 'bool' = False) -> 'Callable[[str, ArtifactType, bytes, Dict, str], ScanResult]':
    """Decorator for `async_scan` to automatically handle errors and boilerplate scanner metadata

    - Record and send timing data to Datadog
    - Read the `ScanResult`'s fields to automatically figure out which metrics should be collected
    - Merges `ScanResult` `metadata` with boilerplate scanner information from `EngineInfo`
    """
    def wrapper(scan_fn: 'Callable[[str, ArtifactType, bytes, Dict, str], ScanResult]') -> 'Callable':
        async def scan_wrapper(
            self,
            guid: 'str',
            artifact_type: 'ArtifactType',
            content: 'bytes',
            metadata: 'Dict',
            chain: 'str',
        ):
            tags = [f'type:{ ArtifactType.to_string(artifact_type) }']  # e.g 'type:file' or 'type:url'

            try:
                if asyncio.iscoroutinefunction(scan_fn):
                    start = perf_counter()
                    scan = await scan_fn(guid, artifact_type, content, metadata, chain)
                    statsd.timing(scan, perf_counter() - start)
                else:
                    with statsd.timer(SCAN_TIME):
                        scan = scan_fn(guid, artifact_type, content, metadata, chain)

                # invalid bit or verdict
                if type(scan.verdict) is not bool or type(scan.bit) is not bool:
                    statsd.increment(SCAN_TYPE_INVALID, tags=tags)

                # successful scan, verdict reported
                elif scan.bit:
                    with suppress(AttributeError, KeyError):
                        getter = itemgetter if isinstance(scan.metadata, Mapping) else attrgetter
                        tags.append(f'malware_family:{getter("scan.metadata.malware_family")}')

                    # malicious/benign metrics
                    if verbose:
                        statsd.increment(
                            SCAN_VERDICT,
                            tags=[*tags, 'verdict:malicious' if scan.verdict else 'verdict:benign']
                        )

                    statsd.increment(SCAN_SUCCESS, tags=tags)
                # no result reported
                elif not scan.bit:
                    if verbose:
                        statsd.increment(SCAN_NO_RESULT, tags=tags)

            except BaseScanError as e:
                # If we encountered a scan error, we still return a scan result with `scan_error`
                # documenting the error which occurred
                v = Verdict().set_malware_name('').set_extra('scan_error', e.event_name)
                scan = ScanResult(bit=False, verdict=False, metadata=v)

                # e.g 'scan_error:fileskippedscanerror'
                tags.append(f'scan_error:{e.event_name}')
                statsd.increment(SCAN_FAIL, tags=tags)
            finally:
                # If engines define `scanner_metadata`, we'll automatically include all of the
                # boilerplate data (e.g `platform`, `machine`, `signature_info`, etc.)
                if isinstance(getattr(self, 'scanner_metadata', None), EngineInfo):
                    self.info.update_metadata(scan)

                return scan

        if asyncio.iscoroutinefunction(scan_fn):
            driver = scan_wrapper
        else:

            def driver(*args, **kwargs):
                return asyncio.run(driver(*args, **kwargs))

        wraps(driver, scan_fn)
        return driver

    return wrapper


class EngineInfo(types.SimpleNamespace):
    """A standard object to store scanner & signature metadata

    Notes::

    Some engines report signature metadata with their scan's output, others
    do so during expensive signature updates.

    You can use `EngineInfo` in both cases, providing a way to store the
    results of `update` or just to simplify the logic of setting up
    a `ScanResult`'s scanner info ::

        class Engine(Scanner):
            info = EngineInfo(version=polyswarm_nanoav.__version__)

            def update(...):
                update: Mapping[str, str] = ... #
                self.info.signature_version = update['definitions_version']
                self.info.engine_version = update['engine_version']

            def sync_scan(...)
                scan_result: ScanResult = do_scan(...)
                self.info.update_verdict(scan_result.verdict)
                return scan_result
    """
    operating_system: str
    architecture: str
    name: Optional[str]  # AV tool
    vendor: Optional[str]  # AV vendor
    version: Optional[str]  # version of the polyswarm engine module
    vendor_version: Optional[str]  # version of the AV engine
    signature_version: Optional[str]  # version of the AV signature signatures
    signature_timestamp: Optional[Union[str, datetime.datetime]]  # date of the signature's last release

    def __init__(self, *args, **kwargs):
        self.operating_system = platform.system()
        self.architecture = platform.machine()
        super().__init__(*args, **kwargs)

    def scanner_info(self) -> 'Mapping':
        """Returns a ``dict`` usable as ``Verdict.set_scanner_info`` kwargs"""

        fields = set((
            'operating_system',
            'architecture'
            'version',
            'signature_version',
            'vendor_version',
        ))
        o = {k: getattr(self, k) for k in fields if hasattr(self, k)}
        with suppress(AttributeError):
            o['signature_release'] = self.signature_info()
        return o

    def signature_info(self):
        """Combine signature version and release into an easily destructured value

        Example::

        >>> info = EngineInfo(signature_version='0.14.34.18525', signature_release='2020-07-06 21:24')
        >>> info.signature_info()
        '0.14.34.18525 <2020-07-06 21:24>'

        """
        return '{} <{!s}>'.format(self.signature_version, self.signature_timestamp)

    def update_metadata(self, scan: 'Optional[ScanResult]') -> 'ScanResult':
        """Update a ``ScanResult``'s with shared scanner metadata"""
        if hasattr(scan, 'metadata'):
            # if it's not already one, try to parse metadata as a verdict (handles JSON, dict, etc.)
            if not isinstance(scan.metadata, Verdict):
                scan.metadata = Verdict.parse_raw(scan.metadata)
        else:
            # if we don't have one at all, create one anew so we can fill in the scanner information
            scan.metadata = Verdict().set_malware_name('')

        scan.metadata.set_scanner_info(**self.scanner_info())
        scan.metadata = scan.metadata.json()
