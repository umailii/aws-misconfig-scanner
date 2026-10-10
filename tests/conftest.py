import os

import boto3
import pytest
from moto import mock_aws


@pytest.fixture(autouse=True)
def aws_env():
    """Fake credentials so tests can never touch a real account."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    with mock_aws():
        yield


@pytest.fixture
def session():
    return boto3.Session(region_name="us-east-1")
