#!/usr/bin/env python3
"""quick IAM security check - prototype

just checking for root access keys for now.
root account should never have access keys.
"""

import boto3
from botocore.exceptions import ClientError

def check_root_access_keys(session):
    """check if root account has access keys (it shouldn't)"""
    iam = session.client('iam')
    try:
        summary = iam.get_account_summary()['SummaryMap']
        root_keys = summary.get('AccountAccessKeysPresent', 0)
        root_mfa = summary.get('AccountMFAEnabled', 0)
        
        results = []
        if root_keys > 0:
            results.append({
                'check': 'Root Access Keys',
                'status': 'FAIL',
                'severity': 'CRITICAL',
                'detail': f'Root account has {root_keys} access key(s) - remove them',
            })
        else:
            results.append({
                'check': 'Root Access Keys', 
                'status': 'PASS',
                'detail': 'No root access keys found',
            })
        
        if root_mfa != 1:
            results.append({
                'check': 'Root MFA',
                'status': 'FAIL', 
                'severity': 'CRITICAL',
                'detail': 'Root account MFA is NOT enabled',
            })
        else:
            results.append({
                'check': 'Root MFA',
                'status': 'PASS',
                'detail': 'Root MFA is enabled',
            })
        
        return results
    except ClientError as e:
        return [{'check': 'Root Access Keys', 'status': 'ERROR', 'detail': str(e)}]

if __name__ == '__main__':
    session = boto3.Session()
    for result in check_root_access_keys(session):
        status = result['status']
        print(f"[{status}] {result['check']}: {result['detail']}")
