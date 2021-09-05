import boto3
import logging


ssm = boto3.client('ssm')


def get_logger(name, level_name):
    logger = logging.getLogger(name)
    level = logging.getLevelName(level_name)
    if not isinstance(level, int):
        level = logging.INFO
    logger.setLevel(level)
    return logger


def get_secure_param(name):
    response = ssm.get_parameter(
        Name=name,
        WithDecryption=True
    )
    return response['Parameter']['Value']
