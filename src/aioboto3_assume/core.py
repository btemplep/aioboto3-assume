
from typing import Any, Dict

import aioboto3
from aiobotocore.credentials import AioDeferredRefreshableCredentials

from aioboto3_assume.aio_assume_refresh import AIOAssumeRefresh
from aioboto3_assume.exceptions import ForbiddenKWArgError, MissingKWArgError


def _check_forbidden_keys(name: str, kwargs: dict, forbidden_keys: list) -> None:
    for key in kwargs:
        if key in forbidden_keys:
            raise ForbiddenKWArgError(f"{name} cannot contain the '{key}' key when used with aioboto3-assume.")


def assume_role(
    source_session: aioboto3.Session,
    assume_role_kwargs: Dict[str, Any],
    sts_client_kwargs: Dict[str, Any] = None,
    target_session_kwargs: Dict[str, Any] = None
) -> aioboto3.Session:
    """Generate an assume role ``aioboto3`` session, that will automatically refresh credentials.

    Parameters
    ----------
    source_session : aioboto3.Session
        Source session to assume the role from. Must be a session that will automatically refresh its own credentials.
    assume_role_kwargs : Dict[str, Any], default=None
        Keyword arguments to pass when calling `assume_role <https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sts/client/assume_role.html>`_. with an aioboto3 STS client.
        Must at least provide ``RoleArn`` and ``RoleSessionName`` as outlined in the boto3 docs.
    sts_client_kwargs : Dict[str, Any], default=None
        Extra kwargs to pass when creating the `aioboto3 low level client <https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html#boto3.session.Session.client>`_. for `STS client <https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sts.html>`_.
        By default only the service argument will be passed as ``"sts"``
        Note that you should not pass in the credentials here. 
    target_session_kwargs : Dict[str, Any], default=None
        Keyword arguments to pass when creating a the new target `aioboto3 Session <https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html>`_.
        By default no arguments are passed. 
        Note that you should only pass in `region_name` or `aws_account_id` or other variables that will not effect credentials or credential refreshing. 

    Returns
    -------
    aioboto3.Session
        The assumed role session with automatic credential refreshing.

    Raises
    ------
    ForbiddenKWArgError
        One of the kwargs function parameters includes a keyword argument that is not allowed for aioboto3-assume.
    MissingKWArgError
        One of the kwargs function parameters is missing a necessary keyword argument.
    
    Examples
    --------
    A minimum example to assume a role:

    .. code-block:: python

        import aioboto3
        from aioboto3_assume import assume_role

        assume_session = assume_role(
            source_session=aioboto3.Session(), # You must pass in an aioboto3 session that automatically refreshes!
            assume_role_kwargs={
                "RoleArn": "arn:aws:iam::123412341234:role/my_role",
                "RoleSessionName": "my-role-session"
            }
        )
    """
    if "RoleArn" not in assume_role_kwargs or "RoleSessionName" not in assume_role_kwargs:
        raise MissingKWArgError("assume_role_kwargs must include the RoleArn and RoleSessionName keys.")

    if sts_client_kwargs is None:
        sts_client_kwargs = {}
    else:
        _check_forbidden_keys(
            name="sts_client_kwargs", 
            kwargs=sts_client_kwargs, 
            forbidden_keys=[
                "service_name",
                "aws_access_key_id",
                "aws_secret_access_key",
                "aws_session_token"
            ]
        )
    
    if target_session_kwargs is None:
        target_session_kwargs = {}
    else:
        _check_forbidden_keys(
            name="target_session_kwargs",
            kwargs=target_session_kwargs,
            forbidden_keys=[
                "aws_access_key_id",
                "aws_secret_access_key",
                "aws_session_token",
                "botocore_session",
                "profile_name"
            ]
        )
    
    assume_sess = aioboto3.Session(**target_session_kwargs)
    assume_sess._session._credentials = AioDeferredRefreshableCredentials(
        refresh_using=AIOAssumeRefresh(
            source_session=source_session,
            sts_client_kwargs=sts_client_kwargs,
            assume_role_kwargs=assume_role_kwargs
        ).refresh,
        method="sts-assume-role"
    )
    
    return assume_sess
