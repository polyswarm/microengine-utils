# microengine-utils

Utility package for [PolySwarm Engines](https://docs.polyswarm.io/suppliers/roles-in-the-marketplace#engines)

Supports Python 3.6 and greater.

## Installation

From PyPI:

    pip install microengine-utils

From source:

    python3 setup.py install

    OR

    pip3 install .


> If you get an error about a missing package named `wheel`, that means your version of pip or setuptools is too old.
> You need pip >= 19.0 and setuptools >= 40.8.0. 
> To update pip, run `pip install -U pip`.
> To update setuptools, run `pip install -U setuptools`

## Usage

Here is an example for how to use the `datadog` metrics utility in an Engine.

```python
import asgiref.sync as asgiref_sync
import logging
import os
import platform
import polyswarm_myengine

from polyswarmartifact.schema.verdict import Verdict
from polyswarmclient.abstractscanner import AbstractScanner, ScanResult
from microengine_utils.constants import SCAN_VERDICT, SCAN_FAIL, SCAN_TIME
from microengine_utils.datadog import configure_metrics

logger = logging.getLogger(__name__)

DATADOG_API_KEY = 'my_api_key'
DATADOG_APP_KEY = 'my_app_key'

# Configure Datadog metric keys for use in the application
ENGINE_NAME = 'myengine'
SCANNER_TYPE = 'file'
OS_TYPE = 'windows'
# Set the environment name, "local" is used for testing
POLY_WORK = os.getenv('POLY_WORK', 'local') 
# Set the hostname, "local" is used for testing
SOURCE = os.getenv("HOSTNAME", "localhost")

class Scanner(AbstractScanner):

    def __init__(self):
        self.datadog_api_key = os.getenv('DATADOG_API_KEY', None)
        self.datadog_app_key = os.getenv('DATADOG_APP_KEY', None)
        self.metrics_collector = configure_metrics(self.datadog_api_key,
                                                   self.datadog_app_key,
                                                   ENGINE_NAME,
                                                   OS_TYPE,
                                                   POLY_WORK,
                                                   SOURCE)

    async def scan(self, guid, artifact_type, content, metadata, chain):
        version = await Scanner._get_my_engine_version()
        metadata = Verdict().set_malware_family('')\
                            .set_scanner(operating_system=platform.system(),
                                         architecture=platform.machine(),
                                         vendor_version=version,
                                         version=polyswarm_myengine.__version__)

        artifact_name = await asgiref_sync.sync_to_async(self._create_temp_file)(content)

        with self.metrics_collector.timer(SCAN_TIME):
            try:
                exit_code, scan_output = await Scanner._run_system_cmd(Scanner._get_full_command(artifact_name))
                logger.info("myengine scan result: %s", scan_output)
            finally:
                await asgiref_sync.sync_to_async(os.unlink)(artifact_name)
            if exit_code != 0:
                self.metrics_collector.increment(SCAN_FAIL)
                return ScanResult(metadata=metadata.json())

            infected_bool, malware_family = Scanner._process_output(scan_output)
            metadata.set_malware_family(malware_family)
            confidence = 0.8
            if infected_bool:
                self.metrics_collector.increment(SCAN_VERDICT,
                                                 tags=['verdict:malicious',
                                                       f'malware_family:{metadata.malware_family}',
                                                       'type:file'])
            else:
                self.metrics_collector.increment(SCAN_VERDICT, tags=['verdict:benign', 'type:file'])
            return ScanResult(bit=True, verdict=infected_bool, confidence=confidence, metadata=metadata.json())

```

Here is an example for using the `malwarerepoclient` utility in Engine unit tests

```python
import asyncio
import pytest
import sys

from microengine_utils.malwarerepoclient import DummyMalwareRepoClient
from polyswarm_myengine import Scanner
from polyswarmartifact import ArtifactType


@pytest.yield_fixture()
def event_loop():
    loop = asyncio.get_event_loop()
    if sys.platform == 'win32':
        loop = asyncio.ProactorEventLoop()
    yield loop
    loop.close()


@pytest.mark.asyncio
async def test_scan_random_malicious_and_not():
    scanner = Scanner()

    for t in [True, False]:
        mal_md, mal_content = DummyMalwareRepoClient().get_random_file(malicious_filter=t)
        result = await scanner.scan("nocare", ArtifactType.FILE, mal_content, None, "home")
        assert result.verdict == t
```

## Testing

    git clone https://github.com/polyswarm/microengine-utils.git
    cd microengine-utils
    pip3 install -r requirements.txt
    pip3 install .
    pytest -s -v
    
## Questions? Problems?

File a ticket or email us at `info@polyswarm.io`.
