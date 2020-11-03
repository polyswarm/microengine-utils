import asyncio
from contextlib import suppress
import functools
import json
import os
import re
from time import perf_counter
from typing import Callable, List, Mapping, Optional, Sequence, cast

import datadog

from polyswarmartifact import ArtifactType
from polyswarmartifact.schema.verdict import Verdict
from polyswarmclient.abstractscanner import AbstractScanner, ScanResult

from .config import EngineInfo
from .constants import (
    SCAN_FAIL,
    SCAN_NO_RESULT,
    SCAN_SUCCESS,
    SCAN_TIME,
    SCAN_TYPE_INVALID,
    SCAN_VERDICT,
)
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
    verbose: 'bool' = bool(os.getenv('MICROENGINE_VERBOSE_METRICS', False))
):
    """Decorator for `async_scan` to automatically handle errors and boilerplate scanner metadata

    - Record and send timing data to Datadog
    - Read the `ScanResult`'s fields to automatically figure out which metrics should be collected
    - Merges `ScanResult` `metadata` with boilerplate scanner information from `EngineInfo`
    """
    def wrapper(scan_fn: 'Callable') -> 'Callable':
        def extract_verdict(scan: 'ScanResult') -> 'Optional[Verdict]':
            """Try to parse ``scan.metadata`` as a Verdict"""
            meta = getattr(scan, 'metadata', None)
            if isinstance(meta, str):
                return Verdict.parse_raw(meta)
            elif isinstance(meta, Mapping):
                return Verdict.parse_obj(meta)
            return meta

        def attach_siginfo(scan: 'ScanResult') -> 'ScanResult':
            """Attach shared engine metadata to ``scan`` metadata"""
            with suppress(AttributeError):
                scanner_info = engine_info.scanner_info()
                if scanner_info:
                    meta = extract_verdict(scan) or Verdict().set_malware_family('')
                    scan.metadata = meta.set_scanner(**scanner_info)
            return scan

        def jsonify_metadata(scan: 'ScanResult') -> 'ScanResult':
            """Ensure we emit a JSON-encoded metadata"""
            meta = getattr(scan, 'metadata', None)
            if isinstance(meta, Verdict):
                scan.metadata = scan.metadata.json()
            elif isinstance(meta, Mapping):
                scan.metadata = json.dumps(meta)
            return scan

        def scan_error_result(e: 'BaseScanError') -> 'ScanResult':
            return ScanResult(
                bit=False,
                verdict=False,
                metadata=Verdict().set_malware_family('').add_extra('scan_error', e.event_name)
            )

        def collect_metrics(scan: 'ScanResult', start: 'float', artifact_type: 'ArtifactType'):
            """Collect application metrics from this scan"""
            # Collect timing information
            statsd.timing(SCAN_TIME, perf_counter() - start)

            type_tag = 'type:%s' % ArtifactType.to_string(artifact_type)

            if scan.bit is True:
                if scan.verdict is True:
                    verdict_tag = 'verdict:malicious'
                elif scan.verdict is False:
                    verdict_tag = 'verdict:benign'
                elif scan.verdict is None:
                    verdict_tag = 'verdict:none'
                else:
                    verdict_tag = 'verdict:invalid.%s' % type(scan.verdict).__name__

                if verbose:
                    statsd.increment(SCAN_VERDICT, tags=[type_tag, verdict_tag])

                statsd.increment(SCAN_SUCCESS, tags=[type_tag, verdict_tag])

            elif scan.bit is False:
                try:
                    # Treat any scan result w/ bit=False & 'scan_error' in metadata as an error
                    statsd.increment(SCAN_FAIL, tags=[
                        type_tag,
                        'scan_error:%s' % extract_verdict(scan).__dict__['scan_error']
                    ])
                except (AttributeError, KeyError):
                    # otherwise, the engine is just reporting no result
                    statsd.increment(SCAN_NO_RESULT, tags=[type_tag])

            else:
                statsd.increment(SCAN_TYPE_INVALID, tags=[type_tag])

        if asyncio.iscoroutinefunction(scan_fn):
            async def driver(self, guid, artifact_type, content, metadata, chain):
                start: float = perf_counter()
                try:
                    scan = await scan_fn(self, guid, artifact_type, content, metadata, chain)
                except BaseScanError as e:
                    scan = scan_error_result(e)
                collect_metrics(scan, start, artifact_type)
                return jsonify_metadata(attach_siginfo(scan))

        else:
            def driver(self, guid, artifact_type, content, metadata, chain):
                start: float = perf_counter()
                try:
                    scan = scan_fn(self, guid, artifact_type, content, metadata, chain)
                except BaseScanError as e:
                    scan = scan_error_result(e)
                collect_metrics(scan, start, artifact_type)
                return jsonify_metadata(attach_siginfo(scan))

        functools.wraps(scan_fn)
        return cast('Callable[[AbstractScanner, str, ArtifactType, bytes, Mapping, str], ScanResult]', driver)

    return wrapper


def each_match(string: 'str', patterns: 'Sequence[str]', in_order=False):
    """
    Return an iterator yielding (GROUP NAME, MATCH STRING) for each non-overlapping pattern
    (``patterns``) found in ``string``

    If `in_order` is ``True``, each of the patterns only match if they occur *after* a previously
    matched pattern (earlier patterns are yielded regardless of if a later pattern matches)
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
