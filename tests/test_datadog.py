from unittest import TestCase

from microengineutils.datadog import configure_metrics

DATADOG_API_KEY = 'api-key'


class TestDatadog(TestCase):

    def test_datadog_collector_config(self):
        collector = configure_metrics(DATADOG_API_KEY,
                                      None,
                                      'test',
                                      'docker',
                                      'ci',
                                      'gitlab')

        assert collector is not None