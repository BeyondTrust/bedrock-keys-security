"""AWS session factory for boto3 client creation"""

import sys
import boto3
import click
from typing import Optional
from botocore.exceptions import ClientError, NoCredentialsError


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
                click.echo(click.style(f"[INFO] Connected to AWS Account: {self.account_id}", fg="cyan"))
                click.echo(click.style(f"[INFO] Caller Identity: {self.caller_arn}", fg="cyan"))

        except NoCredentialsError:
            click.echo(click.style("[ERROR] No AWS credentials found. Please configure AWS CLI or set environment variables.", fg="red"), err=True)
            sys.exit(1)
        except ClientError as e:
            click.echo(click.style(f"[ERROR] Failed to initialize AWS session: {e}", fg="red"), err=True)
            sys.exit(1)
