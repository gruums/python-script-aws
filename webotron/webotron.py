#!/usr/bin/python
# -*- coding: utf-8 -*-

"""Webotron: Deploy websites with aws.

Webotron automates the process of deploying static websites to AWS.
- Configure AWS S3 buckets
  - Create them
  - Set them up for static website hosting
  - Deploy local files to them
- Configure DNS with AWS Route 53
- Configure a Content Delivery Network and SSL with AWS CloudFront
"""
import boto3
import click

from webotron.bucket import BucketManager
from webotron.domain import DomainManager
from webotron.certificate import CertificateManager
from webotron.cdn import DistributionManager
from botocore.client import ClientError

from webotron import util

session = None
bucket_manager = None
domain_manager = None
cert_manager = None
dist_manager = None


@click.group()
@click.option(
    '--profile',
    default=None,
    help="Use a given AWS credential."
)
def cli(profile):
    """Webotron deploys websites to AWS."""
    global session, bucket_manager, domain_manager, cert_manager, dist_manager
    session_cfg = {}
    if profile:
        session_cfg['profile_name'] = profile

    session = boto3.Session(**session_cfg)
    bucket_manager = BucketManager(session)
    domain_manager = DomainManager(session)
    cert_manager = CertificateManager(session)
    dist_manager = DistributionManager(session)


@cli.command('create-bucket')
@click.argument('bucket_name')
def create_buckets(bucket_name):
    """Create a s3 bucket."""
    # s3.create_bucket(Bucket=bucket_name)
    bucket_manager.init_bucket(bucket_name, 'us-east-2')


@cli.command('list-buckets')
def list_buckets():
    """List all s3 buckets."""
    for bucket in bucket_manager.all_buckets():
        print(bucket)


@cli.command('list-bucket-objects')
@click.argument('bucket')
def list_bucket_objects(bucket):
    """List objects in an s3 bucket."""
    for obj in bucket_manager.all_objects(bucket):
        print(obj)


@cli.command('setup-dummy-web')
@click.argument('bucket')
def setup_bucket(bucket):
    """Create a dummy s3 Static website hosting."""
    s3_bucket = None
    s3_bucket = bucket_manager.init_bucket(bucket, 'us-east-2')
    bucket_manager.set_policy(s3_bucket)
    bucket_manager.configure_website(s3_bucket)


@cli.command('sync')
@click.argument('pathname', type=click.Path(exists=True))
@click.argument('bucket_name')
def sync(pathname, bucket_name):
    """Sync contents of PATHNAME to BUCKET."""
    bucket_manager.sync(pathname, bucket_name)


@cli.command('setup-domain')
@click.argument('domain_name')
def setup_domain(domain_name):
    """Configure DOMAIN to point to BUCKET."""
    bucket = bucket_manager.get_bucket(domain_name)
    zone = domain_manager.find_hosted_zone(domain_name) \
        or domain_manager.create_hosted_zone(domain_name)
    endpint = util.get_endpoint(bucket_manager.get_region_name(bucket))
    record = domain_manager.create_s3_domain_record(zone, domain_name, endpint)
    print(record)


@cli.command('find-cert')
@click.argument('domain')
def find_cert(domain):
    """List certification for given domain name."""
    print(cert_manager.find_matching_cert(domain))


@cli.command('setup-cdn')
@click.argument('domain_name')
@click.argument('bucket_name')
def setup_cdn(domain_name, bucket_name):
    """Set up CDN."""
    dist = dist_manager.find_matching_dist(domain_name)
    print(dist)
    if not dist:
        cert = cert_manager.find_matching_cert(domain_name)
        if not cert:
            print("Error: No matching cert found.")
            return

        dist = dist_manager.create_dist(domain_name, cert)
        print("Waiting for distribution deployment...")
        dist_manager.await_deploy(dist)

    zone = domain_manager.find_hosted_zone(domain_name) \
        or domain_manager.create_hosted_zone(domain_name)

    domain_manager.create_cf_domain_record(zone, dist['DomainName'])
    print("Domain configured: https://{}".format(domain_name))
    return


if __name__ == '__main__':
    cli()
