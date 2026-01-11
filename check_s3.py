#!/usr/bin/env python3
"""S3 bucket security checks

checks:
- public access block configuration
- encryption at rest
- versioning (TODO)
"""

import boto3
from botocore.exceptions import ClientError

def check_s3_public_access(session):
    """check all buckets for public access block settings"""
    s3 = session.client('s3')
    results = []
    
    try:
        buckets = s3.list_buckets()['Buckets']
    except ClientError as e:
        return [{'check': 'S3 Access', 'status': 'ERROR', 'detail': str(e)}]
    
    for bucket in buckets:
        name = bucket['Name']
        try:
            pab = s3.get_public_access_block(Bucket=name)
            config = pab['PublicAccessBlockConfiguration']
            all_blocked = all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False),
            ])
            results.append({
                'check': 'S3 Public Access',
                'resource': name,
                'status': 'PASS' if all_blocked else 'FAIL',
                'severity': 'CRITICAL' if not all_blocked else None,
                'detail': f"{'blocked' if all_blocked else 'NOT blocked'}",
            })
        except ClientError as e:
            if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                results.append({
                    'check': 'S3 Public Access',
                    'resource': name,
                    'status': 'FAIL',
                    'severity': 'CRITICAL',
                    'detail': 'No public access block config',
                })
    
    return results

# TODO: check_encryption, check_versioning, check_logging
