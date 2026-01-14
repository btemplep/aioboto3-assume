
import time
import datetime

import aioboto3
from botocore.config import Config
import pytest
import pytz

from aioboto3_assume import assume_role, ForbiddenKWArgError, MissingKWArgError
from aioboto3_assume.aio_assume_refresh import AIOAssumeRefresh


@pytest.mark.asyncio
async def test_assume_role_no_extra_kwargs(
    moto_server: str,
    role_arn: str,
    session_name: str
) -> None:
    sess = aioboto3.Session()
    assume_sess = assume_role(
        source_session=sess,
        assume_role_kwargs={
            "RoleArn": role_arn, 
            "RoleSessionName": session_name
        }
    )
    assert assume_sess._session._credentials._refresh_using.__self__._assume_role_kwargs == {
        "RoleArn": role_arn, 
        "RoleSessionName": session_name
    }
    assert assume_sess._session._credentials._refresh_using.__self__._sts_client_kwargs == {}
    

@pytest.mark.asyncio
async def test_assume_role(
    moto_server: str,
    role_arn: str,
    session_name: str,
    sts_arn: str
) -> None:
    sess = aioboto3.Session()
    assume_sess = assume_role(
        source_session=sess,
        assume_role_kwargs={
            "RoleArn": role_arn, 
            "RoleSessionName": session_name
        },
        sts_client_kwargs={
            "endpoint_url": moto_server,
            "region_name": "us-east-1"
        }
    )
    # credentials should only be retrieved once an API call is made
    creds = await assume_sess.get_credentials()
    assert creds._expiry_time == None
    async with assume_sess.client("sts", endpoint_url=moto_server, region_name="us-east-1") as sts_client:
        identity = await sts_client.get_caller_identity()
        creds = await assume_sess.get_credentials()
        assert identity['Arn'] == sts_arn
        assert creds._expiry_time != None
        assert isinstance(creds._refresh_using.__self__, AIOAssumeRefresh)
        assert creds._refresh_using.__self__._source_session == sess
        assert creds._refresh_using.__self__._sts_client_kwargs == {
            "endpoint_url": "http://localhost:5000", 
            "region_name": "us-east-1"
        }
        assert creds._refresh_using.__self__._assume_role_kwargs == {
            "RoleArn": role_arn, 
            "RoleSessionName": session_name
        }
        

@pytest.mark.asyncio
async def test_assume_role_extra_kwargs(
    moto_server: str,
    role_arn: str,
    session_name: str
) -> None:
    sess = aioboto3.Session()
    boto_config = Config(
        retries={
            "total_max_attempts": 10,
            "mode": "adaptive"
        }
    )
    assume_sess = assume_role(
        source_session=sess,
        assume_role_kwargs={
            "RoleArn": role_arn, 
            "RoleSessionName": session_name,
            "DurationSeconds": 900
        },
        sts_client_kwargs={
            "endpoint_url": moto_server,
            "region_name": "us-east-1",
            "config": boto_config
        },
        target_session_kwargs={
            "region_name": "us-east-1"
        }
    )
    async with assume_sess.client("sts", region_name="us-east-1", endpoint_url=moto_server)as sts_client:
        await sts_client.get_caller_identity()
        creds = await assume_sess.get_credentials()
        expires_at: datetime.datetime = creds._expiry_time.astimezone(pytz.UTC).replace(tzinfo=None)
        until_expire = - (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - expires_at)
        # test to make sure that the variables were passed so the duration should be 900
        assert until_expire.total_seconds() < 900
        assert until_expire.total_seconds() > 880

        assert creds._refresh_using.__self__._source_session == sess
        assert creds._refresh_using.__self__._sts_client_kwargs == {
            "endpoint_url": "http://localhost:5000", 
            "region_name": "us-east-1",
            "config": boto_config
        }
        assert creds._refresh_using.__self__._assume_role_kwargs == {
            "RoleArn": role_arn, 
            "RoleSessionName": session_name,
            "DurationSeconds": 900
        }
        assert assume_sess.region_name == "us-east-1"


@pytest.mark.asyncio
async def test_refresh_creds(
    moto_server: str,
    role_arn: str,
    session_name: str,
    sts_arn: str
) -> None:
    sess = aioboto3.Session()
    assume_sess = assume_role(
        source_session=sess,
        assume_role_kwargs={
            "RoleArn": role_arn, 
            "RoleSessionName": session_name,
            "DurationSeconds": 900
        },
        sts_client_kwargs={
            "endpoint_url": moto_server,
            "region_name": "us-east-1"
        }
    )
    async with assume_sess.client("sts", endpoint_url=moto_server, region_name="us-east-1") as sts_client:
        identity = await sts_client.get_caller_identity()
        assert identity['Arn'] == sts_arn
        # save the original expire ~ 900 seconds from now
        original_expire = assume_sess._session._credentials._expiry_time
        # create a new one that expires now
        assume_sess._session._credentials._expiry_time = pytz.UTC.localize(datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None))
        assert assume_sess._session._credentials._expiry_time < original_expire
        # then sleep so there is a difference
        time.sleep(2)
        # call again so creds refresh
        identity = await sts_client.get_caller_identity()
        assert identity['Arn'] == sts_arn
        # the new expire time should be slightly more than the original !2 seconds
        assert assume_sess._session._credentials._expiry_time > original_expire
    

@pytest.mark.asyncio  
async def test_assume_role_missing_kwargs(
    moto_server: str,
    role_arn: str,
    session_name: str,
    sts_arn: str
) -> None:
    with pytest.raises(MissingKWArgError):
        assume_role(
            source_session=aioboto3.Session(),
            assume_role_kwargs={
                "RoleSessionName": session_name
            }
        )

    with pytest.raises(MissingKWArgError):
        assume_role(
            source_session=aioboto3.Session(),
            assume_role_kwargs={
                "RoleArn": role_arn
            }
        )


@pytest.mark.asyncio  
async def test_assume_role_sts_client_forbidden_keys(
    moto_server: str,
    role_arn: str,
    session_name: str,
    sts_arn: str
) -> None:
    fk = [
        "service_name",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token"
    ]
    sess = aioboto3.Session()
    for k in fk:
        with pytest.raises(ForbiddenKWArgError):
            assume_role(
                source_session=sess,
                assume_role_kwargs={
                    "RoleArn": role_arn,
                    "RoleSessionName": session_name
                },
                sts_client_kwargs={
                    k: "idc"
                }
            )


@pytest.mark.asyncio  
async def test_assume_role_target_session_forbidden_keys(
    moto_server: str,
    role_arn: str,
    session_name: str,
    sts_arn: str
) -> None:
    fk = [
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "botocore_session",
        "profile_name"
    ]
    sess = aioboto3.Session()
    for k in fk:
        with pytest.raises(ForbiddenKWArgError):
            assume_role(
                source_session=sess,
                assume_role_kwargs={
                    "RoleArn": role_arn,
                    "RoleSessionName": session_name
                },
                target_session_kwargs={
                    k: "idc"
                }
            )


def test__serialize_if_needed() -> None:
    refresh = AIOAssumeRefresh(
        source_session=aioboto3.Session(),
        sts_client_kwargs={},
        assume_role_kwargs={}
    )
    dt_str = "2023-06-27T00:00:00"
    result = refresh._serialize_if_needed(dt_str)
    assert result == dt_str