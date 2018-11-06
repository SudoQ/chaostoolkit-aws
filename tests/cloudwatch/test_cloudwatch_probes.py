# -*- coding: utf-8 -*-
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from chaoslib.exceptions import FailedActivity

from chaosaws.cloudwatch.probes import (get_alarm_state_value,
                                        get_metric_statistic_value)


@patch('chaosaws.cloudwatch.probes.aws_client', autospec=True)
def test_cloudwatch_get_alarm_state_value_ok(aws_client):
    client = MagicMock()
    aws_client.return_value = client
    alarm_name = 'my-alarm'
    client.describe_alarms.return_value = {
        'MetricAlarms': [
            {
                'AlarmName': alarm_name,
                'StateValue': 'OK'
            }
        ]
    }
    result = get_alarm_state_value(alarm_name)
    assert result == 'OK'
    client.describe_alarms.assert_called_with(AlarmNames=[alarm_name])


@patch('chaosaws.cloudwatch.probes.aws_client', autospec=True)
def test_cloudwatch_get_alarm_state_value_not_found(aws_client):
    client = MagicMock()
    aws_client.return_value = client
    alarm_name = 'my-alarm'
    client.describe_alarms.return_value = {
        'MetricAlarms': []
    }
    with pytest.raises(FailedActivity):
        get_alarm_state_value(alarm_name)
    client.describe_alarms.assert_called_with(AlarmNames=[alarm_name])


@patch('chaosaws.cloudwatch.probes.datetime', autospec=True)
@patch('chaosaws.cloudwatch.probes.aws_client', autospec=True)
def test_cloudwatch_get_metric_statistic_value_statistic_ok(aws_client,
                                                            mock_datetime):
    client = MagicMock()
    aws_client.return_value = client
    mock_datetime.utcnow.return_value = datetime(2015, 1, 1, 15, 15,
                                                 tzinfo=timezone.utc)

    namespace = 'AWS/Lambda'
    metric_name = 'Invocations'
    dimension_name = 'FunctionName'
    dimension_value = 'MyFunction'
    period = 120
    statistic = 'Sum'
    extended_statistic = None
    unit = 'Count'
    client.get_metric_statistics.return_value = {
        'Datapoints': [{statistic: '4753.0'}]
    }

    result = get_metric_statistic_value(
        namespace=namespace,
        metric_name=metric_name,
        dimension_name=dimension_name,
        dimension_value=dimension_value,
        period=period,
        statistic=statistic,
        extended_statistic=extended_statistic,
        unit=unit
    )

    assert result == '4753.0'
    client.get_metric_statistics.assert_called_with(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=[{'Name': dimension_name, 'Value': dimension_value}],
        Period=period,
        StartTime=datetime(2015, 1, 1, 15, 13, tzinfo=timezone.utc),
        EndTime=datetime(2015, 1, 1, 15, 15, tzinfo=timezone.utc),
        Statistics=[statistic],
        Unit=unit
    )


@patch('chaosaws.cloudwatch.probes.datetime', autospec=True)
@patch('chaosaws.cloudwatch.probes.aws_client', autospec=True)
def test_cloudwatch_get_metric_statistic_value_extended_statistic_ok(
        aws_client,
        mock_datetime):
    client = MagicMock()
    aws_client.return_value = client
    mock_datetime.utcnow.return_value = datetime(2015, 1, 1, 15, 15,
                                                 tzinfo=timezone.utc)

    namespace = 'AWS/Lambda'
    metric_name = 'Invocations'
    dimension_name = 'FunctionName'
    dimension_value = 'MyFunction'
    period = 120
    statistic = None
    extended_statistic = 'p99'
    client.get_metric_statistics.return_value = {
        'Datapoints': [{'ExtendedStatistics': {extended_statistic: '4753.0'}}]
    }
    unit = None

    result = get_metric_statistic_value(
        namespace=namespace,
        metric_name=metric_name,
        dimension_name=dimension_name,
        dimension_value=dimension_value,
        period=period,
        statistic=statistic,
        extended_statistic=extended_statistic,
        unit=unit
    )

    assert result == '4753.0'
    client.get_metric_statistics.assert_called_with(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=[{'Name': dimension_name, 'Value': dimension_value}],
        Period=period,
        StartTime=datetime(2015, 1, 1, 15, 13, tzinfo=timezone.utc),
        EndTime=datetime(2015, 1, 1, 15, 15, tzinfo=timezone.utc),
        ExtendedStatistics=[extended_statistic],
    )


@patch('chaosaws.cloudwatch.probes.datetime', autospec=True)
@patch('chaosaws.cloudwatch.probes.aws_client', autospec=True)
def test_cloudwatch_get_metric_statistic_value_no_datapoints(
        aws_client, mock_datetime):
    client = MagicMock()
    aws_client.return_value = client
    mock_datetime.utcnow.return_value = datetime(2015, 1, 1, 15, 15,
                                                 tzinfo=timezone.utc)

    namespace = 'AWS/Lambda'
    metric_name = 'Invocations'
    dimension_name = 'FunctionName'
    dimension_value = 'MyFunction'
    period = 120
    statistic = 'Sum'
    extended_statistic = None
    unit = 'Count'
    client.get_metric_statistics.return_value = {
        'Datapoints': []
    }

    with pytest.raises(FailedActivity):
        get_metric_statistic_value(
            namespace=namespace,
            metric_name=metric_name,
            dimension_name=dimension_name,
            dimension_value=dimension_value,
            period=period,
            statistic=statistic,
            extended_statistic=extended_statistic,
            unit=unit
        )

    client.get_metric_statistics.assert_called_with(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=[{'Name': dimension_name, 'Value': dimension_value}],
        Period=period,
        StartTime=datetime(2015, 1, 1, 15, 13, tzinfo=timezone.utc),
        EndTime=datetime(2015, 1, 1, 15, 15, tzinfo=timezone.utc),
        Statistics=[statistic],
        Unit=unit
    )
