from datadog import initialize, ThreadStats


def configure_metrics(datadog_api_key, datadog_app_key, engine_name, os_type, poly_work, source, tags=None):
    """
            Initialize Datadog metric collectors when the datadog env keys are set
            :return:
            """

    if datadog_api_key is not None or datadog_app_key is not None:
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
        }

        initialize(**options)

        metrics_collector = ThreadStats(namespace='polyswarm', constant_tags=tags)
        metrics_collector.start()
        return metrics_collector
    else:
        return None