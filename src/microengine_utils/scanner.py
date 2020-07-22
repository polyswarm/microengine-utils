import asyncio
import functools
import os
from contextlib import suppress
from operator import attrgetter, itemgetter
from time import perf_counter
import datadog
from typing import Callable, Mapping, Optional

from polyswarmartifact import ArtifactType
from polyswarmartifact.schema.verdict import Verdict
from polyswarmclient import ScanResult

from .datadog import SCAN_FAIL, SCAN_NO_RESULT, SCAN_SUCCESS, SCAN_TIME, SCAN_TYPE_INVALID, SCAN_VERDICT
from .errors import BaseScanError, CalledProcessScanError


async def create_scanner_exec(
    *cmd: 'str',
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
    stdin=asyncio.subprocess.DEVNULL,
    check: 'bool' = False,
):
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
        sout, serr = (s.decode(errors='ignore') for s in streams)
        return proc.returncode, sout, serr
    except (FileNotFoundError, BrokenPipeError, ConnectionResetError) as e:  # noqa
        proc.kill()
        raise CalledProcessScanError(cmd, str(type(e)))


def scanalytics(statsd: 'datadog.DogStatsd' = datadog.statsd,
                engine_info: 'Optional[EngineInfo]' = None):
    """Decorator for `async_scan` to automatically handle errors and boilerplate scanner metadata

    - Record and send timing data to Datadog
    - Read the `ScanResult`'s fields to automatically figure out which metrics should be collected
    - Merges `ScanResult` `metadata` with boilerplate scanner information from `EngineInfo`
    """
    verbose: 'bool' = os.getenv('MICROENGINE_VERBOSE_METRICS', False)

    def wrapper(scan_fn: 'Callable') -> 'Callable':
        @functools.wraps(scan_fn)
        async def driver(
                self: 'AbstractScanner',
                guid: 'str',
                artifact_type: 'ArtifactType',
                content: 'bytes',
                metadata: 'Dict',
                chain: 'str',
        ) -> 'ScanResult':
            tags = [f'type:{ ArtifactType.to_string(artifact_type) }'
                    ]  # e.g 'type:file' or 'type:url'

            try:
                start = perf_counter()
                scan = await scan_fn(self, guid, artifact_type, content, metadata, chain)
                statsd.timing(SCAN_TIME, perf_counter() - start)

                # invalid bit or verdict
                if type(scan.verdict) is not bool or type(scan.bit) is not bool:
                    statsd.increment(SCAN_TYPE_INVALID, tags=tags)

                # successful scan, verdict reported
                elif scan.bit:
                    with suppress(AttributeError, KeyError):
                        getter = itemgetter if isinstance(scan.metadata,
                                                          Mapping) else attrgetter
                        tags.append(
                            f'malware_family:{getter("scan.metadata.malware_family")}')

                    # malicious/benign metrics
                    if verbose:
                        statsd.increment(
                            SCAN_VERDICT,
                            tags=[
                                *tags,
                                'verdict:malicious' if scan.verdict else 'verdict:benign'
                            ])

                    statsd.increment(SCAN_SUCCESS, tags=tags)
                # no result reported
                elif not scan.bit:
                    if verbose:
                        statsd.increment(SCAN_NO_RESULT, tags=tags)

            except BaseScanError as e:
                if isinstance(e, BaseScanError):
                    event = e.event_name
                else:
                    raise e

                # If we encountered a scan error, we still return a scan result with `scan_error`
                # documenting the error which occurred
                v = Verdict().set_malware_family('').add_extra('scan_error', event)
                scan = ScanResult(bit=False, verdict=False, metadata=v)

                # e.g 'scan_error:fileskippedscanerror'
                tags.append(f'scan_error:{event}')
                statsd.increment(SCAN_FAIL, tags=tags)

            # If engines define `scanner_metadata`, we'll automatically include all of the
            # boilerplate data (e.g `platform`, `machine`, `signature_info`, etc.)
            if engine_info is not None:
                engine_info.graft(scan)

            return scan

        return driver

    return wrapper

