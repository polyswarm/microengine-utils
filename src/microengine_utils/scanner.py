import asyncio
import functools
import os
import re
from contextlib import suppress
from operator import attrgetter, itemgetter
from time import perf_counter
from typing import Callable, Mapping, Optional, Sequence, List

import datadog
from polyswarmartifact import ArtifactType
from polyswarmartifact.schema.verdict import Verdict
from polyswarmclient.abstractscanner import AbstractScanner, ScanResult

from .config import EngineInfo
from .constants import (SCAN_FAIL, SCAN_NO_RESULT, SCAN_SUCCESS, SCAN_TIME, SCAN_TYPE_INVALID, SCAN_VERDICT)
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


def scanalytics(
    statsd: 'datadog.DogStatsd' = datadog.statsd,
    engine_info: 'Optional[EngineInfo]' = None,
    verbose: 'bool' = False
):
    """Decorator for `async_scan` to automatically handle errors and boilerplate scanner metadata

    - Record and send timing data to Datadog
    - Read the `ScanResult`'s fields to automatically figure out which metrics should be collected
    - Merges `ScanResult` `metadata` with boilerplate scanner information from `EngineInfo`
    """
    verbose: 'bool' = bool(verbose or os.getenv('MICROENGINE_VERBOSE_METRICS', False))

    def wrapper(scan_fn: 'Callable') -> 'Callable':
        def extract_verdict(scan: 'ScanResult') -> 'Optional[Verdict]':
            meta = getattr(scan, 'metadata', None)
            if isinstance(meta, str):
                return Verdict.parse_raw(meta)
            elif isinstance(meta, Mapping):
                return Verdict.parse_obj(meta)
            return meta

        def collect_metrics(scan: 'ScanResult', tags: 'List[str]'):
            # invalid bit or verdict
            if type(scan.verdict) is not bool or type(scan.bit) is not bool:
                statsd.increment(SCAN_TYPE_INVALID, tags=tags)

            # successful scan, verdict reported
            elif scan.bit:
                with suppress(AttributeError):
                    family = extract_verdict(scan).malware_family
                    if family:
                        tags.append(f'malware_family:{family}')

                # malicious/benign metrics
                if verbose:
                    statsd.increment(
                        SCAN_VERDICT,
                        tags=[*tags, 'verdict:malicious' if scan.verdict else 'verdict:benign'],
                    )

                statsd.increment(SCAN_SUCCESS, tags=tags)

            # no result reported
            elif not scan.bit:
                try:
                    # If scan returns a ScanResult w/ bit=False & Verdict equipped with
                    # `scan_error`, we'll treat it as an error, regardless of if a BaseScanError
                    # was raised in scan's function body.
                    statsd.increment(
                        SCAN_FAIL,
                        tags=[*tags, 'scan_error:{scan_error!s}'.format_map(extract_verdict(scan).__dict__)],
                    )
                except KeyError:
                    # otherwise, the engine is just reporting no result
                    statsd.increment(SCAN_NO_RESULT, tags=tags)

        def attach_siginfo(scan: 'ScanResult') -> 'ScanResult':
            # If engines define `scanner_metadata`, we'll automatically include all of the
            # boilerplate data (e.g `platform`, `machine`, `signature_info`, etc.)
            if engine_info is not None:
                engine_info.graft(scan)

            return scan

        def jsonify(scan: 'ScanResult') -> 'ScanResult':
            if isinstance(getattr(scan, 'metadata', None), Verdict):
                scan.metadata = scan.metadata.json()

            return scan

        driver: 'Callable[[AbstractScanner, str, ArtifactType, bytes, Mapping, str], ScanResult]'

        if asyncio.iscoroutinefunction(scan_fn):

            @functools.wraps(scan_fn)
            async def driver(self, guid, artifact_type, content, metadata, chain):
                tags = [f'type:{ ArtifactType.to_string(artifact_type) }']  # e.g 'type:file' or 'type:url'
                start = perf_counter()
                try:
                    scan = await scan_fn(self, guid, artifact_type, content, metadata, chain)
                except BaseScanError as e:
                    scan = ScanResult(
                        bit=False,
                        verdict=False,
                        metadata=Verdict().set_malware_family('').add_extra('scan_error', e.event_name)
                    )
                statsd.timing(SCAN_TIME, perf_counter() - start)
                collect_metrics(scan, tags)
                return jsonify(attach_siginfo(scan))

        else:

            @functools.wraps(scan_fn)
            def driver(self, guid, artifact_type, content, metadata, chain):
                tags = [f'type:{ ArtifactType.to_string(artifact_type) }']  # e.g 'type:file' or 'type:url'
                start = perf_counter()
                try:
                    scan = scan_fn(self, guid, artifact_type, content, metadata, chain)
                except BaseScanError as e:
                    scan = ScanResult(
                        bit=False,
                        verdict=False,
                        metadata=Verdict().set_malware_family('').add_extra('scan_error', e.event_name)
                    )
                statsd.timing(SCAN_TIME, perf_counter() - start)
                collect_metrics(scan, tags)
                return jsonify(attach_siginfo(scan))

        return driver

    return wrapper


def each_match(string: 'str', patterns: 'Sequence[str]', in_order=False):
    """
    Return an iterator yielding (GROUP NAME, MATCH STRING) tuples of all non-overlapping matches
    for the regex patterns (``patterns``) found in ``string``

    If `in_order` is true, each of the patterns only match if they occur *after* any (matched)
    patterns prior in the ``patterns`` list (however, these earlier patterns aren't required
    to have matched for subsequent patterns to matcharen't actually
    required for subsequent patterns to match)
    """
    pat = re.compile('|'.join(patterns), re.MULTILINE)
    idx = -1
    for m in pat.finditer(string):
        for k, v in m.groupdict(None).items():
            if v is not None:
                if in_order:
                    if pat.groupindex[k] < idx:
                        continue
                    idx = pat.groupindex[k]
                yield (k, v)
