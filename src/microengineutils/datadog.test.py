from .datadog import configure_metrics


def test_datadog():
    DATADOG_API_KEY = 'api-key'
    collector = configure_metrics(DATADOG_API_KEY,
                      None,
                      'test',
                      'docker',
                      'ci',
                      'gitlab')

    assert collector is not None