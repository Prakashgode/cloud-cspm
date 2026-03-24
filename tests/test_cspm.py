from unittest.mock import MagicMock, patch

from cspm import build_scan_session


def test_build_scan_session_without_role_returns_base_session():
    base_session = MagicMock()
    base_sts = MagicMock()
    base_session.client.return_value = base_sts
    base_sts.get_caller_identity.return_value = {
        "Arn": "arn:aws:iam::111111111111:user/security-audit",
        "Account": "111111111111",
    }

    with patch("cspm.boto3.Session", return_value=base_session) as session_cls:
        session, identity, source_identity = build_scan_session(
            profile="audit",
            region="us-east-1",
            role_arn=None,
            external_id=None,
            session_name="cloud-cspm",
        )

    session_cls.assert_called_once_with(profile_name="audit", region_name="us-east-1")
    assert session is base_session
    assert identity["Account"] == "111111111111"
    assert source_identity is None


def test_build_scan_session_assumes_role_when_role_arn_is_provided():
    base_session = MagicMock()
    base_sts = MagicMock()
    base_session.client.return_value = base_sts
    base_sts.get_caller_identity.return_value = {
        "Arn": "arn:aws:iam::111111111111:user/security-audit",
        "Account": "111111111111",
    }
    base_sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "ASIAEXAMPLE",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
        }
    }

    assumed_session = MagicMock()
    assumed_sts = MagicMock()
    assumed_session.client.return_value = assumed_sts
    assumed_sts.get_caller_identity.return_value = {
        "Arn": "arn:aws:sts::222222222222:assumed-role/SecurityAudit/cloud-cspm",
        "Account": "222222222222",
    }

    with patch("cspm.boto3.Session", side_effect=[base_session, assumed_session]) as session_cls:
        session, identity, source_identity = build_scan_session(
            profile="audit",
            region="us-west-2",
            role_arn="arn:aws:iam::222222222222:role/SecurityAudit",
            external_id="cspm-demo",
            session_name="cloud-cspm",
        )

    session_cls.assert_any_call(profile_name="audit", region_name="us-west-2")
    session_cls.assert_any_call(
        aws_access_key_id="ASIAEXAMPLE",
        aws_secret_access_key="secret",
        aws_session_token="token",
        region_name="us-west-2",
    )
    base_sts.assume_role.assert_called_once_with(
        RoleArn="arn:aws:iam::222222222222:role/SecurityAudit",
        RoleSessionName="cloud-cspm",
        ExternalId="cspm-demo",
    )
    assert session is assumed_session
    assert identity["Account"] == "222222222222"
    assert source_identity["Account"] == "111111111111"
