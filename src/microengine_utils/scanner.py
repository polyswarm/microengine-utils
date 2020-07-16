import asyncio
import functools
import platform
import time
from contextlib import contextmanager, suppress
from typing import (TYPE_CHECKING, Callable, NewType, Optional, Text, Tuple, TypedDict, Union)

import datadog
from polyswarmartifact import ArtifactType
from polyswarmartifact.schema.verdict import Verdict

from .datadog import (SCAN_FAIL, SCAN_NO_RESULT, SCAN_SUCCESS, SCAN_TIME, SCAN_TYPE_INVALID, SCAN_VERDICT)
from .errors import (BaseScanError, CalledProcessScanError, MalformedResponseScanError, TimeoutScanError)
from .fs import AsyncArtifactTempfile, winepath

if TYPE_CHECKING:
    ExitCodeT = int

    from polyswarmclient import ScanResult
    from datetime import datetime

    FILE_TYPE = ArtifactType.FILE
    URL_TYPE = ArtifactType.URL


async def create_scanner_exec(
    *cmd: 'str',
    stdout: 'asyncio.StreamReader' = asyncio.subprocess.PIPE,
    stderr: 'asyncio.StreamReader' = asyncio.subprocess.PIPE,
    stdin: 'asyncio.StreamReader' = asyncio.subprocess.DEVNULL,
    check: 'bool' = False,
    timeout: 'int' = 15,
) -> 'Tuple[ExitCodeT, Text, ...]':
    """Run an engine filescan `cmd`, timing out after `timeout` seconds"""
    try:
        proc = await asyncio.subprocess.create_subprocess_exec(
            *cmd,
            stdout=stdout,
            stderr=stderr,
            stdin=stdin,
        )
        streams = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if check and proc.returncode != 0:
            raise CalledProcessScanError
        return (
            proc.returncode,
            *(s.decode(errors='ignore') if isinstance(s, bytes) else str(s or '') for s in streams)
        )
    except (BrokenPipeError, ConnectionResetError):  # noqa
        proc.kill()
        raise CalledProcessScanError
    except asyncio.TimeoutError as e:
        proc.kill()
        raise TimeoutScanError


def collect_scan(verbose: 'bool' = False) -> 'Callable[..., ScanResult]':
    """Decorator for `async_scan` to automatically handle errors and boilerplate scanner metadata

    - Record and send timing data to Datadog
    - Read the `ScanResult`'s fields to automatically figure out which metrics should be collected
    - Merges `ScanResult` `metadata` with boilerplate scanner information from `EngineInfo`
    """
    statsd = datadog.statsd

    def wrapper(scan_fn: 'Callable'):
        @functools.wraps(scan_fn)
        async def driver(
            self,
            guid: 'str',
            artifact_type: 'ArtifactType',
            content: 'bytes',
            metadata: 'Dict',
            chain: 'Optional[str]',
        ):
            start = time.time()
            tags = []

            # e.g 'type:file' or 'type:url'
            tags.append('type:%s' % ArtifactType.to_string(artifact_type))

            try:
                scan = await scan_fn(guid, artifact_type, content, metadata, chain)
            except BaseScanError as e:
                # e.g 'scan_error:fileskippedscanerror'
                tags.append('scan_error:{e.event_name}')
                statsd.increment(SCAN_FAIL, tags=tags)
                # If we encountered a scan error, we still return a scan result with `scan_error`
                # documenting the error which occurred
                scan = ScanResult(
                    bit=False,
                    verdict=False,
                    metadata=Verdict().set_malware_name('').set_extra('scan_error', e.event_name),
                )
            else:
                # No result
                if scan.bit is False:
                    if verbose:
                        statsd.increment(SCAN_NO_RESULT, tags=tags)
                # Verdict reported
                elif scan.bit is True and (scan.verdict is True or scan.verdict is False):
                    statsd.increment(SCAN_SUCCESS, tags=tags)

                    # We (generally) don't need to track every single verdict, but should retain
                    # the ability to do so
                    if verbose:
                        tags.append('verdict:{}'.format('malicious' if scan.verdict else 'benign'))
                        with suppress(AttributeError):
                            tags.append(f'malware_family:{ scan.metadata.malware_family }')
                        statsd.increment(SCAN_VERDICT, tags=tags)
                # Invalid bit or verdict
                else:
                    statsd.increment(SCAN_TYPE_INVALID, tags=tags)
            finally:

                if getattr(scan, 'metadata', None):
                    # If engines define `scanner_metadata`, we'll automatically include all of the
                    # boilerplate data (e.g `platform`, `machine`, `signature_info`, etc.)
                    if isinstance(getattr(self, 'scanner_metadata', None), EngineInfo):
                        scan.metadata.set_scanner(**self.info.dict())
                    scan.metadata = scan.metadata.json()

                # `with statsd.timer` ctxmgr does not function correctly with (some) async functions
                statsd.timing(SCAN_TIME, time.time() - start)

                return scan

        return driver


class EngineInfo:
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
    def __init__(self):
        self.version = version
        self.operating_system = None
        self.architecture = None
        self.signatures_version = None
        self.vendor_version = None

    def dict(self, include_none=False):
        return {k: v for k, v in self.__dict__.items() if (include_none or v is not None)}
