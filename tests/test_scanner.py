import asyncio
from sys import version_info
import unittest.mock
from uuid import uuid4

from microengine_utils.config import EngineInfo
from microengine_utils.constants import (
    SCAN_FAIL,
    SCAN_NO_RESULT,
    SCAN_SUCCESS,
    SCAN_VERDICT,
)
from microengine_utils.errors import UnprocessableScanError
from microengine_utils.scanner import each_match, scanalytics
import pytest
import itertools

from polyswarmartifact import ArtifactType
from polyswarmartifact.schema.verdict import Verdict
from polyswarmclient.abstractscanner import ScanResult
from contextlib import suppress


@pytest.fixture()
def engine_info():
    einfo = EngineInfo(version='version')
    # use of both the alias and underlying property name
    einfo.update(
        engine_version='vendorver1',
        signatures_version='sigversion',
        definitions_timestamp='now',
    )
    return einfo


@pytest.fixture(scope='function')
def statsd():
    o = unittest.mock.Mock()
    o.increment = unittest.mock.Mock()
    o.timing = unittest.mock.Mock()
    return o


@pytest.fixture(params=[None, *itertools.product((True, False), ('MALWARE', ''))])
def scan_metadata(request):
    if request.param is None:
        return None
    as_json, family = request.param
    v = Verdict().set_malware_family(family)
    return v.json() if as_json else v


@pytest.fixture(scope='function', params=[UnprocessableScanError(), (True, True), (True, False), (False, False)])
def scan_result(request, scan_metadata):
    if isinstance(request.param, Exception):
        return request.param
    bit, verdict = request.param
    return ScanResult(bit=bit, verdict=verdict, metadata=scan_metadata)


@pytest.mark.parametrize('verbose_metrics', [True, False], ids=['verbose', 'quiet'])
@pytest.mark.parametrize('artifact_kind', [ArtifactType.FILE, ArtifactType.URL])
@pytest.mark.parametrize('use_async', [False] if version_info < (3, 7) else [False, True], ids=lambda p: 'async' if p else 'sync')
def test_scanalytics(statsd, engine_info, use_async, scan_result, verbose_metrics, artifact_kind):
    is_error = isinstance(scan_result, Exception)
    args = (None, str(uuid4()), artifact_kind, b'content', {}, 'home')
    tags = ['type:%s' % ArtifactType.to_string(artifact_kind)]
    if use_async:

        @scanalytics(statsd=statsd, engine_info=engine_info, verbose=verbose_metrics)
        async def scanfn(self, guid, artifact_type, content, metadata, chain):
            if is_error:
                raise scan_result
            return scan_result

        result = asyncio.run(scanfn(*args))
    else:

        @scanalytics(statsd=statsd, engine_info=engine_info, verbose=verbose_metrics)
        def scanfn(self, guid, artifact_type, content, metadata, chain):
            if is_error:
                raise scan_result
            return scan_result

        result = scanfn(*args)

    statsd.timing.assert_called_once()

    assert isinstance(result.metadata, str)
    result_meta = Verdict.parse_raw(result.metadata)
    assert result_meta.scanner.signatures_version == engine_info.definitions_version
    assert result_meta.scanner.vendor_version == engine_info.engine_version

    if is_error:
        assert result_meta.__dict__['scan_error'] == scan_result.event_name
        assert result.bit is False
        statsd.increment.assert_called_once_with(
            SCAN_FAIL, tags=[*tags, f'scan_error:{scan_result.event_name}']
        )
    else:
        assert result.verdict is scan_result.verdict
        assert result.bit is scan_result.bit

        if scan_result.bit is True:
            if result_meta.malware_family:
                tags.append(f'malware_family:{result_meta.malware_family}')

            statsd.increment.assert_any_call(SCAN_SUCCESS, tags=tags)

            if verbose_metrics:
                statsd.increment.assert_any_call(
                    SCAN_VERDICT,
                    tags=tags + ['verdict:malicious' if scan_result.verdict else 'verdict:benign'],
                )
                assert statsd.increment.call_count == 2
            else:
                assert statsd.increment.call_count == 1

        elif scan_result.bit is False:
            if verbose_metrics:
                statsd.increment.assert_called_once_with(SCAN_NO_RESULT, tags=tags)


@pytest.mark.parametrize(
    'expect', (
        (
            'Nothing',
            tuple(),
            tuple(),
            tuple(),
        ),
        (
            '',
            ('(?P<nomatch>nomatch)', ),
            tuple(),
            tuple(),
        ),
        (
            'First comes love, then comes marriage, then comes the baby in the baby carriage',
            ('(?P<marriage>marriage)', '(?P<love>love)', '(?P<baby>baby)'),
            (('love', 'love'), ('marriage', 'marriage'), ('baby', 'baby'), ('baby', 'baby')),
            (('love', 'love'), ('baby', 'baby'), ('baby', 'baby')),
        ),
        (
            'correctly formulated, the law of fives is that all observable phenomena are directly or indirectly related to the number five',
            ('(?P<law>law)', '(?P<five>five)', '(?P<direct>direct)'),
            (
                ('law', 'law'),
                ('five', 'five'),
                ('direct', 'direct'),
                ('direct', 'direct'),
                ('five', 'five'),
            ),
            (('law', 'law'), ('five', 'five'), ('direct', 'direct'), ('direct', 'direct')),
        ),
        (
            'If you have any answers, We will be glad to provide full and detailed questions.',
            ('(?P<question>question)', '(?P<answer>answer)'),
            (('answer', 'answer'), ('question', 'question')),
            (('answer', 'answer'), ),
        ),
    )
)
def test_each_match_ordered(expect):
    string, patterns, expected_unordered, expected_ordered = expect
    assert expected_unordered == tuple(each_match(string, patterns, in_order=False))
    assert expected_ordered == tuple(each_match(string, patterns, in_order=True))
