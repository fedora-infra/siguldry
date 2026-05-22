# SPDX-License-Identifier: MIT
# Copyright (c) Microsoft Corporation.

"""
A small shim to deal with CoreOS and S3.

Fedora doesn't package AWS's Rust SDK and I cannot be bothered since I would
like to migrate the CoreOS folks away from this workflow that requires AWS credentials.
"""

import boto3
from botocore import exceptions as boto_exceptions
from botocore.config import Config as BotoConfig


class S3Client:

    def __init__(self, region: str, bucket: str, access_key: str, access_secret: str):
        config = BotoConfig(
            connect_timeout=30,
            read_timeout=60,
            retries={
                "max_attempts": 10,
                "mode": "standard",
            },
        )
        self.bucket = bucket
        self.s3_client = boto3.client(
            "s3",
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=access_secret,
            config=config,
        )

    def upload(self, object_key: str, data: bytes):
        """
        Upload a (small) object to the given key.

        If the object exists, do nothing. There's no point checking the digest since
        OpenPGP can salt the signature and it'll be different every time.
        """
        try:
            self.s3_client.head_object(Bucket=self.bucket, Key=object_key)
            return
        except boto_exceptions.ClientError as e:
            if e.response.get("Error", {}).get("Code") not in ("404", "NoSuchKey"):
                raise
        self.s3_client.put_object(Bucket=self.bucket, Key=object_key, Body=data)
