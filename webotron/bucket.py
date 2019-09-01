# -*- coding: utf-8 -*-

"""Classes for S3 Buckets."""
import boto3

from pathlib import Path
from functools import reduce
import mimetypes

from hashlib import md5
from botocore.client import ClientError

from webotron import util

POLICY = """{
    "Version":"2012-10-17",
    "Statement":[{
        "Sid":"PublicS3ReadGetObject",
        "Effect":"Allow",
        "Principal": "*",
        "Action":["s3:GetObject"],
        "Resource":["arn:aws:s3:::%s/*" ]
    }]
}"""


class BucketManager:
    """Manage an S3 Bucket."""

    CHUNK_SIZE = 8388608

    def __init__(self, session):
        """Create a BucketManager object."""
        self.s3_service = session.resource('s3')
        self.manifest = {}
        self.tranfer_config = boto3.s3.transfer.TransferConfig(
            multipart_chunksize=self.CHUNK_SIZE,
            multipart_threshold=self.CHUNK_SIZE
        )

    @staticmethod
    def hash_data(data):
        """Generate MD5 hash for data."""
        hash = md5()
        hash.update(data)
        return hash

    def gen_etag(self, path):
        """Generate etag for file."""
        hashes = []

        with open(path, 'rb') as f:
            while True:
                data = f.read(self.CHUNK_SIZE)
                if not data:
                    break
                hashes.append(self.hash_data(data))

        if not hashes:
            return
        elif len(hashes) == 1:
            return '"{}"'.format(hashes[0].hexdigest())
        else:
            hash = self.hash_data(
                reduce(lambda x, y: x + y, (h.digest() for h in hashes))
            )
            return '"{}-{}"'.format(hash.hexdigest(), len(hashes))

    def load_manifest(self, bucket):
        """Load manifest for caching purposes."""
        paginator = self.s3_service.meta.client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket.name):
            for obj in page.get('Contents', []):
                self.manifest[obj['Key']] = obj['ETag']

    def get_bucket(self, bucket_name):
        """Get a bucket by name."""
        return self.s3_service.Bucket(bucket_name)

    def all_buckets(self):
        """Get an iterator for all buckets."""
        return self.s3_service.buckets.all()

    def all_objects(self, bucket_name):
        """Get an iterator for all objects in a bucket."""
        return self.s3_service.Bucket(bucket_name).objects.all()

    def get_region_name(self, bucket):
        """Get region name for this bucket."""
        bucket_location = self.s3_service.meta.client.get_bucket_location(
            Bucket=bucket.name
        )
        return bucket_location['LocationConstraint'] or 'us-east-1'

    def get_bucket_url(self, bucket):
        """Get Websit URL for this bucket."""
        return "http://{}.{}".format(
            bucket.name,
            util.get_endpoint(self.get_region_name(bucket)).host
        )

    def init_bucket(self, bucket_name, region='us-east-1'):
        """Create a bucket in S3."""
        s3_bucket = None
        try:
            # Raise Exception if buckets exists.
            self.s3_service.meta.client.head_bucket(Bucket=bucket_name)
            raise Exception(
                "Bucket name %s already exists in the S3." % bucket_name
            )
        except ClientError as error:
            if error.response['Error']['Message'] == 'Not Found':
                # Create bucket if bucket_name does not exist.
                if region == 'us-east-1':
                    s3_bucket = self.s3_service.create_bucket(
                        Bucket=bucket_name
                    )
                else:
                    s3_bucket = self.s3_service.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={
                            'LocationConstraint': region
                        }
                    )
            else:
                raise error
        return s3_bucket

    def set_policy(self, bucket):
        """Set bucket policy to public."""
        pol = bucket.Policy()
        pol.put(Policy=POLICY % bucket.name)

    def configure_website(self, bucket):
        """Set bucket to Static Host."""
        bucket.Website().put(WebsiteConfiguration={
            'ErrorDocument': {
                'Key': 'error.html'
            },
            'IndexDocument': {
                'Suffix': 'index.html'
            }
        })

    def upload_file(self, s3_bucket, path, key):
        """Upload file to a S3 bucket."""
        content_type = mimetypes.guess_type(key)[0] or 'text/plain'

        etag = self.gen_etag(path)

        if self.manifest.get(key, '') == etag:
            print(etag)
            return

        return s3_bucket.upload_file(
            path,
            key,
            ExtraArgs={
                'ContentType': content_type
            },
            Config=self.tranfer_config
        )

    def sync(self, pathname, bucket_name):
        """Sync contents of PATHNAME to BUCKET."""
        bucket = self.s3_service.Bucket(bucket_name)
        self.load_manifest(bucket)

        root = Path(pathname).expanduser().resolve()

        def handle_directory(target):
            for path in target.iterdir():
                if path.is_dir():
                    handle_directory(path)
                if path.is_file():
                    self.upload_file(
                        bucket, str(path), str(path.relative_to(root))
                    )

        handle_directory(root)
