# -*- coding: utf-8 -*-
"""Classes for AWS domain."""

import uuid


class DomainManager:
    """Manage a Rout53 Domain."""

    def __init__(self, session):
        """Create a DomainManager object."""
        self.session = session
        self.client = self.session.client('route53')

    def find_hosted_zone(self, domain_name):
        """Find Host zone by given domain name."""
        paginator = self.client.get_paginator('list_hosted_zones')

        for page in paginator.paginate():
            for zone in page['HostedZones']:
                if domain_name.endswith(zone['Name'][:-1]):
                    return zone

        return None

    def create_hosted_zone(self, domain_name):
        """Create a Host Zone use given domain name."""
        zone_name = '.'.join(domain_name.split('.')[-2:]) + '.'
        return self.client.create_hosted_zone(
            Name=zone_name,
            CallerReference=str(uuid.uuid4())
        )

    def create_s3_domain_record(self, zone, domain_name, endpoint):
        """Create Record Sets for the domain name."""
        # endpoint = util.get_endpoint(bucket.get_region_name())
        return self.client.change_resource_record_sets(
            HostedZoneId=zone['Id'],
            ChangeBatch={
                'Comment': 'Create by webotron',
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': domain_name,
                            'Type': 'A',
                            'AliasTarget': {
                                'HostedZoneId': endpoint.zone,
                                'DNSName': endpoint.host,
                                'EvaluateTargetHealth': False
                            }
                        }
                    }
                ]
            }
        )

    def create_cf_domain_record(self, zone, domain_name, cf_domain):
        """Create a Record Set for CloudFront domain."""
        return self.client.change_resource_record_sets(
            HostedZoneId=zone['Id'],
            ChangeBatch={
                'Comment': 'Create by webotron',
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': domain_name,
                            'Type': 'A',
                            'AliasTarget': {
                                'HostedZoneId': 'Z2FDTNDATAQYW2',
                                'DNSName': cf_domain,
                                'EvaluateTargetHealth': False
                            }
                        }
                    }
                ]
            }
        )
