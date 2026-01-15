"""Easily create ``aioboto3`` assume role sessions with automatic credential refreshing.

Examples
--------

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

__version__ = "0.1.2"
__all__ = [
    "assume_role",
    "Boto3AssumeError",
    "ForbiddenKWArgError",
    "MissingKWArgError"
]

from aioboto3_assume.core import assume_role
from aioboto3_assume.exceptions import Boto3AssumeError, ForbiddenKWArgError, MissingKWArgError
