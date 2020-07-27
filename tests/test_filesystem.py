import asyncio
import os
from pathlib import Path

from microengine_utils import (
    ArtifactTempfile,
    as_wine_path,
    each_match,
    scanalytics,
)
from microengine_utils.errors import (
    CalledProcessScanError,
    UnprocessableScanError,
)
from microengine_utils.filesystem import winepath
import pytest


@pytest.mark.parametrize('expect', (('/tmp/test', 'Z:\\tmp\\test'), ('/hello/world/', 'Z:\\hello\\world')))
def test_as_wine_path(expect):
    path, expected = expect
    assert str(as_wine_path(path)) == expected


def test_artifacttempfile():
    p = None
    with ArtifactTempfile(b'data') as filename:
        p = Path(filename)
        assert p.exists()
    assert not p.exists()
