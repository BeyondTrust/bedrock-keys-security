"""AWS session factory for boto3 client creation"""

import sys
import boto3
from typing import Optional
from botocore.exceptions import ClientError, NoCredentialsError

from bedrock_keys_security.utils import output


class AWSSession:
    """Encapsulates AWS session and client creation"""

    def __init__(self, profile: Optional[str] = None, region: Optional[str] = None, verbose: bool = False):
        self.region = region or "us-east-1"

        try:
            session = boto3.Session(profile_name=profile, region_name=self.region)
            self._setup_clients(session)

            identity = self.sts.get_caller_identity()
            self.account_id = identity["Account"]
            self.caller_arn = identity["Arn"]

            if verbose:
                output.info(f"Connected to AWS Account: {self.account_id}")
                output.info(f"Caller Identity: {self.caller_arn}")

        except NoCredentialsError:
            output.error("No AWS credentials found. Configure AWS CLI or set environment variables.")
            sys.exit(1)
        except ClientError as e:
            output.error(f"Failed to initialize AWS session: {e}")
            sys.exit(1)

    def _setup_clients(self, session: boto3.Session) -> None:
        """Bind the boto3 clients used by every bks command to `self`.

        Single source of truth so both constructors stay in sync when a new
        AWS service is added.
        """
        self.session = session
        self.iam = session.client("iam")
        self.sts = session.client("sts")
        self.cloudtrail = session.client("cloudtrail", region_name=self.region)

    @classmethod
    def from_credentials(
        cls,
        access_key: str,
        secret_key: str,
        session_token: str,
        region: str,
        account_id: str,
        caller_arn: str,
        verbose: bool = False,
    ) -> "AWSSession":
        """Build an AWSSession from already-resolved temporary credentials.

        Used by org-wide scan after sts:AssumeRole into a member account.
        Skips profile lookup and the redundant GetCallerIdentity call (the
        AssumeRole response already carries the assumed-role ARN).
        """
        inst = cls.__new__(cls)
        inst.region = region or "us-east-1"
        inst._setup_clients(boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=inst.region,
        ))
        inst.account_id = account_id
        inst.caller_arn = caller_arn
        if verbose:
            output.info(f"Assumed role into account: {account_id}")
            output.info(f"Caller Identity: {caller_arn}")
        return inst
