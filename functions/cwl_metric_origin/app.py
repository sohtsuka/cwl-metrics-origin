import boto3
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote_plus
from urllib.request import Request, urlopen

from cwl_metric_origin.util import get_logger, get_secure_param


REGION = os.environ['AWS_REGION']
SLACK_CHANNEL = os.environ['SLACK_CHANNEL']
SLACK_TOKEN = get_secure_param('/' + os.environ['SLACK_TOKEN_PARAM'])

logger = get_logger(__name__, os.environ.get('LOG_LEVEL'))
cloudwatch = boto3.client('cloudwatch')
cwlogs = boto3.client('logs')


def lambda_handler(event, context):
    logger.info('Event: %s', event)
    
    message = json.loads(event['Records'][0]['Sns']['Message'])
    if message['NewStateValue'] == 'ALARM':
        try:
            alarm_detail = get_alarm_detail(message)
        except UnexpectedMessageException:
            logger.warn('Unexpected message format', exc_info=True)
        else:
            notify(alarm_detail, context)
            search_logs(alarm_detail)
    else:
        logger.debug('NewStateValue is not `ALARM`')


def get_alarm_detail(message):
    alarm_name = message['AlarmName']

    alarms = cloudwatch.describe_alarms(AlarmNames=[alarm_name])
    logger.info('describe_alarms: %s', alarms)
    if len(alarms['MetricAlarms']) <= 0:
        raise UnexpectedMessageException(f'Not a metric alarm: alarm={alarm_name}')
    alarm = alarms['MetricAlarms'][0]

    filters = cwlogs.describe_metric_filters(
        metricName=alarm['MetricName'],
        metricNamespace=alarm['Namespace']
    )
    logger.info('describe_metric_filters: %s', filters)
    if len(filters['metricFilters']) <= 0:
        raise UnexpectedMessageException(f'MetricFilter not found for this alarm: alarm={alarm_name}')
    filters = filters['metricFilters']

    datapoints = get_datapoints(message)
    logger.info('Datapoints: %s', datapoints)
    if len(datapoints) <= 0:
        raise UnexpectedMessageException('Datapoints not found in Sns Message')

    return AlarmDetail(
        name=alarm_name,
        datapoints=datapoints,
        period=message['Trigger']['Period'],
        filters = [
            FilterDetail(name=f['filterName'], log_group=f['logGroupName'], pattern=f['filterPattern'])
            for f in filters
        ]
    )


def get_datapoints(message):
    times = re.findall(r'\((\d\d/\d\d/\d\d \d\d:\s*\d\d:\s*\d\d)\)', message['NewStateReason'])
    logger.debug('Times: %s', times)

    fixed_times = [re.sub(r':\s+', ':', t) for t in times]
    logger.debug('Fixed times: %s', fixed_times)
    
    datapoints = [datetime.strptime(t, '%d/%m/%y %H:%M:%S').replace(tzinfo=timezone.utc) for t in fixed_times]
    return datapoints


def notify(alarm_detail, context):
    log_url = cw_log_url(
        log_group=context.log_group_name,
        log_stream=context.log_stream_name,
        pattern=f'"EVENT:" "{context.aws_request_id}"'
    )
    blocks = [
        {
            'type': 'header',
            'text': {
                'type': 'plain_text',
                'text': f'ALARM: {alarm_detail.name}'
            }
        },
        {'type': 'divider'},
        {
            'type': 'section',
            'fields': [
                slack_field('Datapoints', [dp.isoformat() for dp in alarm_detail.datapoints]),
                slack_field('Origin Logs', f'<{log_url}|Link>')
            ]
        }
    ]
    
    for filter in alarm_detail.filters:
        search_url = cw_log_url(
            log_group=filter.log_group,
            start_millis=alarm_detail.start_millis,
            end_millis=alarm_detail.end_millis,
            pattern=filter.pattern
        )
        blocks.extend([
            {'type': 'divider'},
            {
                'type': 'section',
                'fields': [
                    slack_field('Filter Name', filter.name),
                    slack_field('Log Group', filter.log_group),
                    slack_field('Filter Pattern', f'`{filter.pattern}`'),
                    slack_field('Search Logs', f'<{search_url}|Link>')
                ]
            }
        ])
    
    send_slack({
        'channel': SLACK_CHANNEL,
        'text': 'fallback',
        'blocks': blocks
    })


def slack_field(title, content):
    return {
        'type': 'mrkdwn',
        'text': f'*{title}*\n{content}'
    }


def cw_log_url(log_group, log_stream=None, pattern=None, start_millis=None, end_millis=None):
    queries = []
    if pattern:
        queries.append(f'filterPattern={cw_quote(pattern)}')
    if start_millis:
        queries.append(f'start={start_millis}')
    if end_millis:
        queries.append(f'end={end_millis}')

    params = f'log-groups/log-group/{cw_escape(cw_quote(log_group))}/log-events'
    if log_stream:
        params += f'/{cw_escape(cw_quote(log_stream))}'
    if queries:
        params += cw_escape(f'?{"&".join(queries)}')

    return f'https://{REGION}.console.aws.amazon.com/cloudwatch/home?region={REGION}#logsV2:{params}'


def cw_quote(s):
    return quote_plus(s, safe='-_')


def cw_escape(s):
    # '%' => '$25', '=' => '$3D'
    return re.sub(r'[^0-9A-Za-z_-]', lambda v: '${:0>2X}'.format(ord(v.group(0))), s)


def send_slack(message):
    req = Request('https://slack.com/api/chat.postMessage', json.dumps(message).encode('utf-8'), {
        'Authorization': f'Bearer {SLACK_TOKEN}',
        'Content-Type': 'application/json;charset=utf-8'
    })
    try:
        response = urlopen(req)
        logger.debug('Message posted to Slack')
        body = response.read()
        logger.debug('Response: %s', body)
    except HTTPError as e:
        logger.exception('Failed to request to Slack: %d %s', e.code, e.reason)
    except URLError as e:
        logger.exception('Failed to connect to Slack: %s', e.reason)


def search_logs(alarm_detail):
    for filter in alarm_detail.filters:
        filter_args = {
            'logGroupName': filter.log_group,
            'startTime': alarm_detail.start_millis,
            'endTime': alarm_detail.end_millis,
            'filterPattern': filter.pattern
        }
        logger.info('EVENT: Started searching logs: logGroup=%s, pattern=%s, time=%d-%d',
            filter.log_group, filter.pattern, alarm_detail.start_millis, alarm_detail.end_millis)

        next_token = None
        while True:
            response = cwlogs.filter_log_events(**filter_args)
            logger.debug('Logs: %s', response)
            for event in response['events']:
                logger.info('EVENT: Found log: %s', event)
            next_token = response.get('nextToken')
            if next_token:
                logger.debug('NextToken: %s', next_token)
                filter_args['nextToken'] = next_token
            else:
                break
    
    logger.info('EVENT: Finished searching logs')


@dataclass(frozen=True)
class FilterDetail:
    name: str
    log_group: str
    pattern: str


@dataclass(frozen=True)
class AlarmDetail:
    name: str
    datapoints: list[datetime]
    period: int
    filters: list[FilterDetail]
    start_millis: int = None
    end_millis: int = None

    def __post_init__(self):
        if self.datapoints:
            object.__setattr__(self, 'start_millis', int(self.datapoints[0].timestamp()) * 1000)
            object.__setattr__(self, 'end_millis', int(self.datapoints[-1].timestamp() + self.period) * 1000)


class UnexpectedMessageException(Exception):
    pass
