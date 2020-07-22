import unittest.mock
import asyncio
from sys import version_info

import pytest
from microengine_utils.config import EngineInfo
from microengine_utils.constants import SCAN_FAIL, SCAN_SUCCESS
from microengine_utils.errors import UnprocessableScanError
from microengine_utils.scanner import each_match, scanalytics
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


def check_verdict(json):
    assert isinstance(json, str)
    meta = Verdict.parse_raw(json)
    assert meta.scanner.signatures_version == 'sigversion'
    assert meta.scanner.vendor_version == 'vendorver1'
    return meta


if version_info >= (3, 7):
    def test_scanalytics_error(statsd, engine_info):
        @scanalytics(statsd=statsd, engine_info=engine_info)
        async def scan_fn(*args, **kwargs):
            raise UnprocessableScanError

        result = asyncio.run(scan_fn(None, None, ArtifactType.FILE, b'content', {}, 'home'))
        assert result.bit is False
        meta = check_verdict(result.metadata)
        assert meta.__dict__['scan_error'] == 'unprocessable'
        statsd.increment.assert_called_once_with(SCAN_FAIL, tags=['type:file', 'scan_error:unprocessable'])


    def test_scanalytics(statsd, engine_info):
        @scanalytics(statsd=statsd, engine_info=engine_info)
        async def scan_fn(*args, **kwargs):
            return ScanResult(bit=True, verdict=True, metadata=Verdict().set_malware_family('123'))

        result = asyncio.run(scan_fn(None, None, ArtifactType.FILE, b'content', {}, 'home'))
        assert result.bit is True
        assert result.verdict is True
        check_verdict(result.metadata)
        statsd.increment.assert_called_once_with(SCAN_SUCCESS, tags=['type:file', 'malware_family:123'])


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
