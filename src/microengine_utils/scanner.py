import asyncio
import functools
import os
from contextlib import suppress
from datetime import datetime
from operator import attrgetter, itemgetter
from time import perf_counter
from typing import (TYPE_CHECKING, Callable, Mapping, NewType, Optional, Text, Tuple, TypedDict, Union)

from polyswarmartifact import ArtifactType
from polyswarmartifact.schema.verdict import Verdict
from polyswarmclient import ScanResult

from .constants import PLATFORM_MACHINE, PLATFORM_OS
from .datadog import (
    SCAN_FAIL, SCAN_NO_RESULT, SCAN_SUCCESS, SCAN_TIME, SCAN_TYPE_INVALID, SCAN_VERDICT, statsd
)
from .errors import (
    BaseScanError, CalledProcessScanError, CommandNotFoundScanError, MalformedResponseScanError
)
from .filesystem import (
    ArtifactFilename, ArtifactTempfile, as_wine_filename, universal_path_validator, winepath
)


async def create_scanner_exec(
    *cmd: 'str',
    stdout: 'asyncio.StreamReader' = asyncio.subprocess.PIPE,
    stderr: 'asyncio.StreamReader' = asyncio.subprocess.PIPE,
    stdin: 'asyncio.StreamReader' = asyncio.subprocess.DEVNULL,
    check: 'bool' = False,
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


def collect_scan(
    verbose: 'bool' = False,
    engine_info: 'Optional[Union[Callable[[Any], Any], EngineInfo]]' = None
) -> 'Callable[[str, ArtifactType, bytes, Dict, str], ScanResult]':
    """Decorator for `async_scan` to automatically handle errors and boilerplate scanner metadata

    - Record and send timing data to Datadog
    - Read the `ScanResult`'s fields to automatically figure out which metrics should be collected
    - Merges `ScanResult` `metadata` with boilerplate scanner information from `EngineInfo`
    """
    def wrapper(scan_fn: 'Callable[[...], ScanResult]') -> 'Callable[[...], ScanResult]':
        if asyncio.iscoroutinefunction(scan_fn):

            async def driver(
                self, guid: 'str', artifact_type: 'ArtifactType', content: 'bytes', metadata: 'Dict',
                chain: 'str'
            ):
                engine_info = engine_info(self) if callable(engine_info) else engine_info

                tags = [f'type:{ ArtifactType.to_string(artifact_type) }']  # e.g 'type:file' or 'type:url'

                try:
                    start = perf_counter()
                    scan = await scan_fn(guid, artifact_type, content, metadata, chain)
                    statsd.timing(scan, perf_counter() - start)

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

                except (asyncio.TimeoutError, BaseScanError) as e:
                    if isinstance(e, asyncio.TimeoutError):
                        event = 'timeout'
                    elif isinstance(e, BaseScanError):
                        event = e.event_name
                    else:
                        raise e

                    # If we encountered a scan error, we still return a scan result with `scan_error`
                    # documenting the error which occurred
                    v = Verdict().set_malware_name('').set_extra('scan_error', event)
                    scan = ScanResult(bit=False, verdict=False, metadata=v)

                    # e.g 'scan_error:fileskippedscanerror'
                    tags.append(f'scan_error:{event}')
                    statsd.increment(SCAN_FAIL, tags=tags)
                finally:
                    # If engines define `scanner_metadata`, we'll automatically include all of the
                    # boilerplate data (e.g `platform`, `machine`, `signature_info`, etc.)
                    if engine_info is not None:
                        self.info.update_metadata(scan)

                    return scan
        else:

            @wraps(scan_fn)
            def driver(
                self, guid: 'str', artifact_type: 'ArtifactType', content: 'bytes', metadata: 'Dict',
                chain: 'str'
            ):
                engine_info = engine_info(self) if callable(engine_info) else engine_info

                tags = [f'type:{ ArtifactType.to_string(artifact_type) }']  # e.g 'type:file' or 'type:url'

                try:
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

                except (asyncio.TimeoutError, BaseScanError) as e:
                    if isinstance(e, asyncio.TimeoutError):
                        event = 'timeout'
                    elif isinstance(e, BaseScanError):
                        event = e.event_name
                    else:
                        raise e

                    # If we encountered a scan error, we still return a scan result with `scan_error`
                    # documenting the error which occurred
                    v = Verdict().set_malware_name('').set_extra('scan_error', event)
                    scan = ScanResult(bit=False, verdict=False, metadata=v)

                    # e.g 'scan_error:fileskippedscanerror'
                    tags.append(f'scan_error:{event}')
                    statsd.increment(SCAN_FAIL, tags=tags)
                finally:
                    # If engines define `scanner_metadata`, we'll automatically include all of the
                    # boilerplate data (e.g `platform`, `machine`, `signature_info`, etc.)
                    if engine_info is not None:
                        self.info.update_metadata(scan)

                    return scan

        functools.wraps(scan_fn)
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
    # platform, e.g `linux', `windows' or `darwin'
    operating_system: str = PLATFORM_OS

    # machine architecture, e.g `amd64' or `i386'
    architecture: str = PLATFORM_MACHINE

    # captures the module version of the microengine that rendered this verdict
    version: Optional[str]

    # captures the name of this engine
    engine_name: Optional[str]

    # captures the vendor / author of this engine
    vendor_name: Optional[str]

    # captures the version of engine itself
    vendor_version: Optional[str]

    # captures the version of the engine's signatures/definitions used
    signature_version: Optional[str]

    # captures the release date of the signatures/definitions used
    signature_timestamp: Optional[Union[str, datetime.datetime]]

    def __init__(self, *args, **kwargs):
        self.engine_name = os.getenv('MICROENGINE_NAME')
        self.vendor_name = os.getenv('MICROENGINE_VENDOR_NAME')
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
        if getattr(scan, 'metadata', None):
            # try to parse the JSON string/dict/... inside `scan.metadata' into a `Verdict'
            if not isinstance(scan.metadata, Verdict):
                scan.metadata = Verdict.parse_raw(scan.metadata)
        else:
            # if the ScanResult doesn't exist or is falsy, build a new one so we can at least fill
            # in the bare-bones of scanner information
            scan.metadata = Verdict().set_malware_name('')

        scan.metadata.set_scanner_info(**self.scanner_info())
        scan.metadata = scan.metadata.json()
