import os
from time import sleep
from unittest import TestCase

from datadog import ThreadStats
from microengine_utils.constants import SCAN_TIME, SCAN_VERDICT
from microengine_utils.datadog import configure_metrics

DATADOG_API_KEY = 'my_api_key'
DATADOG_APP_KEY = 'my_app_key'

# Configure Datadog metric keys for use in the application
ENGINE_NAME = 'myengine'
SCANNER_TYPE = 'file'
OS_TYPE = 'windows'
# Set the environment name, "local" is used for testing
POLY_WORK = 'local'
# Set the hostname, "localhost" is used for testing
SOURCE = 'localhost'


class TestDatadog(TestCase):

    def setUp(self):
        self.collector = configure_metrics(DATADOG_API_KEY,
                                           None,
                                           ENGINE_NAME,
                                           OS_TYPE,
                                           POLY_WORK,
                                           SOURCE)

    def tearDown(self):
        # Flush all pending message to Datadog (the ether) after each test to they exit immediately
        self.collector.flush()
        self.collector = None

    def test_datadog_collector_config(self):
        assert self.collector is not None
        assert isinstance(self.collector, ThreadStats)

    def test_datadog_context_manager(self):
        with self.collector.timer(SCAN_TIME):
            sleep(1)
            self.collector.increment(SCAN_VERDICT, tags=['verdict:benign', 'type:file'])
            sleep(1)
