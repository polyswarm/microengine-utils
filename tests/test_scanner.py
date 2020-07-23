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

from polyswarmartifact import ArtifactType
from polyswarmartifact.schema.verdict import Verdict
from polyswarmclient.abstractscanner import ScanResult


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


@pytest.mark.parametrize('is_async', [True, False])
@pytest.mark.parametrize('scan_error', [None, UnprocessableScanError])
@pytest.mark.parametrize('json_metadata', [True, False])
@pytest.mark.parametrize(
    'scan_value', [
        (True, True, 'MALWARE'),
        (True, False, ''),
        (True, False, ''),
        (True, False, None),
    ]
)
@pytest.mark.parametrize('verbose_metrics', [True, False])
@pytest.mark.parametrize(
    'scan_args', [
        (None, str(uuid4()), ArtifactType.FILE, b'content', {}, 'home'),
        (None, str(uuid4()), ArtifactType.URL, b'content', {}, 'home'),
    ]
)
def test_scanalytics(
    statsd, engine_info, is_async, scan_error, json_metadata, scan_value, verbose_metrics, scan_args
):
    bit, verdict, family = scan_value
    src_meta = None if family is None else Verdict().set_malware_family(family)
    scan_result = ScanResult(
        bit=bit,
        verdict=verdict,
        metadata=src_meta.json() if json_metadata and src_meta is not None else src_meta
    )

    if is_async:
        if version_info < (3, 7):
            return

        @scanalytics(statsd=statsd, engine_info=engine_info, verbose=verbose_metrics)
        async def scanfn(self, guid, artifact_type, content, metadata, chain):
            if scan_error is not None:
                raise scan_error
            return scan_result

        result = asyncio.run(scanfn(*scan_args))
    else:

        @scanalytics(statsd=statsd, engine_info=engine_info, verbose=verbose_metrics)
        def scanfn(self, guid, artifact_type, content, metadata, chain):
            if scan_error is not None:
                raise scan_error
            return scan_result

        result = scanfn(*scan_args)

    statsd.timing.assert_called_once()

    tags = ['type:%s' % ArtifactType.to_string(scan_args[2])]

    if scan_error is None:
        assert result.verdict is verdict
        assert result.bit is bit

        if bit is True:
            if family:
                tags.append(f'malware_family:{family}')

            statsd.increment.assert_any_call(SCAN_SUCCESS, tags=tags)

            if verbose_metrics:
                statsd.increment.assert_any_call(
                    SCAN_VERDICT,
                    tags=[*tags, 'verdict:malicious' if verdict else 'verdict:benign'],
                )
                assert statsd.increment.call_count == 2
            else:
                assert statsd.increment.call_count == 1

        elif bit is False:
            if verbose_metrics:
                statsd.increment.assert_called_once_with(SCAN_NO_RESULT, tags=tags)

    else:
        tags.append(f'scan_error:{scan_error.event_name}')
        statsd.increment.assert_called_once_with(SCAN_FAIL, tags=tags)

    assert isinstance(result.metadata, str)
    result_meta = Verdict.parse_raw(result.metadata)
    assert result_meta.scanner.signatures_version == engine_info.definitions_version
    assert result_meta.scanner.vendor_version == engine_info.engine_version
    if scan_error:
        assert result_meta.__dict__['scan_error'] == scan_error.event_name


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
