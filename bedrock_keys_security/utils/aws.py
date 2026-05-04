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
            self.session = session
            self.iam = session.client("iam")
            self.sts = session.client("sts")
            self.cloudtrail = session.client("cloudtrail", region_name=self.region)

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
