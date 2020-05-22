from datadog import initialize, ThreadStats


def configure_metrics(datadog_api_key,
                      datadog_app_key,
                      engine_name,
                      os_type,
                      poly_work,
                      source,
                      tags=None,
                      disabled=False) -> ThreadStats:
    """
    Initialize Datadog metric collectors when the datadog env keys are set
    :return: datadog.ThreadStats
    """
    if datadog_api_key or datadog_app_key:
        if tags is None:
            tags = [
                f'poly_work:{poly_work}',
                f'engine_name:{engine_name}',
                f'pod_name:{source}',
                f'os:{os_type}',
                'testing' if poly_work == 'local' else '',
            ]
        options = {
            'api_key': datadog_api_key,
            'app_key': datadog_app_key,
            'host_name': source,
        }

        initialize(**options)

    else:
        disabled = True

    metrics_collector = ThreadStats(namespace='polyswarm', constant_tags=tags)
    metrics_collector.start(disabled=disabled)
    return metrics_collector
