#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to create an EC2 instance."""

import boto3

class InstanceManager:
    """Class to manage EC2 instance."""

    def __init__(self, session):
        """Create InstanceManager object."""
        self.ec2_service = session.resource('ec2')
    
    def create_pem(self, key_name):
        """Create a ssh key for EC2 instance."""
        return self.ec2_service.create_key_pair(KeyName=key_name)

    #TODO: move this function to util.
    def save_pem_local(self, key_pair):
        """Save pem to current fold."""
        file_path = key_pair.key_name + '.pem'

        with open(file_path, 'w') as key_file:
            key_file.write(key_pair.key_material)

    def list_amazon_images(self, filters=[]):
        """List amazon images."""
        return self.ec2_service.images.filter(Owners=['amazon'], Filters=filters)
    
    def launch_instance(self, image_id, key_pair):
        """Launch an ec2 instance with given image and key."""
        return self.ec2_service.create_instances(
            ImageId=image_id,
            MinCount=1,
            MaxCount=1,
            InstanceType='t2.micro',
            KeyName=key_pair
        )


if __name__ == '__main__':
    session = boto3.Session(profile_name="xwu")
    key_name = 'mykey'
    instanceMananger = InstanceManager(session)
    ami_name = 'amzn-ami-hvm-2018.03.0.20180508-x86_64-gp2'
    images = list(instanceMananger.list_amazon_images([{'Name': 'name', 'Values': [ami_name]}]))
    instance = instanceMananger.launch_instance(images[0].id, key_name)[0]
    instance.wait_until_running()
    instance.reload()
    # add sercurity group to ec2
    sg = instanceMananger.ec2_service.SecurityGroup(instance.security_groups[0]['GroupId'])
    sg.authorize_ingress(IpPermissions=[{'FromPort': 22, 'ToPort': 22, 'IpProtocol': 'TCP', 'IpRanges': [{'CidrIp': '162.233.171.126/32'}]}])
    sg.authorize_ingress(IpPermissions=[{'FromPort': 80, 'ToPort': 80, 'IpProtocol': 'TCP', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}])

    print("Instance complete: {}".format(instance))

