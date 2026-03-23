import json

from botocore.exceptions import ClientError

from .base_scanner import BaseScanner, Finding, Severity, Status


class LambdaScanner(BaseScanner):
    def scan(self) -> list[Finding]:
        regions = self._get_regions()
        for region in regions:
            lambda_client = self.session.client("lambda", region_name=region)
            ec2_client = self.session.client("ec2", region_name=region)

            for function in self._list_functions(lambda_client, region):
                function_name = function["FunctionName"]
                configuration = self._get_function_configuration(
                    lambda_client,
                    function_name,
                    region,
                )
                if configuration is None:
                    continue

                self._check_public_access(lambda_client, configuration, region)
                self._check_environment_encryption(configuration, region)
                self._check_vpc_configuration(configuration, region)
                self._check_multi_az(configuration, ec2_client, region)
                self._check_tags(lambda_client, configuration, region)
                self._check_xray_tracing(configuration, region)

        return self.findings

    def _get_regions(self) -> list[str]:
        ec2 = self.session.client("ec2")
        try:
            regions = ec2.describe_regions()["Regions"]
            return [region["RegionName"] for region in regions]
        except ClientError:
            return ["us-east-1"]

    def _list_functions(self, lambda_client, region: str) -> list[dict]:
        try:
            paginator = lambda_client.get_paginator("list_functions")
            functions: list[dict] = []
            for page in paginator.paginate():
                functions.extend(page.get("Functions", []))
            return functions
        except ClientError as error:
            self.add_finding(
                check_id="LAMBDA-0",
                check_name="Lambda Service Access",
                status=Status.ERROR,
                severity=Severity.HIGH,
                resource_id=f"lambda:{region}",
                resource_type="AWS::Lambda::Service",
                region=region,
                description=f"Unable to list Lambda functions in {region}: {error}",
            )
            return []

    def _get_function_configuration(
        self, lambda_client, function_name: str, region: str
    ) -> dict | None:
        try:
            return lambda_client.get_function_configuration(FunctionName=function_name)
        except ClientError as error:
            self.add_finding(
                check_id="LAMBDA-0",
                check_name="Lambda Function Access",
                status=Status.ERROR,
                severity=Severity.HIGH,
                resource_id=function_name,
                resource_type="AWS::Lambda::Function",
                region=region,
                description=f"Unable to read configuration for Lambda function '{function_name}': {error}",
            )
            return None

    def _check_public_access(self, lambda_client, function: dict, region: str) -> None:
        function_name = function["FunctionName"]
        issues: list[str] = []

        try:
            url_config = lambda_client.get_function_url_config(FunctionName=function_name)
            if url_config.get("AuthType") == "NONE":
                issues.append("Function URL allows unauthenticated access")
        except ClientError as error:
            if not self._is_not_found(error):
                self._add_lambda_error(
                    check_id="LAMBDA-1",
                    check_name="Lambda Public Access",
                    function_name=function_name,
                    region=region,
                    description=f"Unable to inspect function URL configuration: {error}",
                    severity=Severity.CRITICAL,
                )
                return

        try:
            policy_response = lambda_client.get_policy(FunctionName=function_name)
            policy_document = json.loads(policy_response["Policy"])
            for statement in self._get_policy_statements(policy_document):
                if self._is_public_invoke_statement(statement):
                    sid = statement.get("Sid", "unknown")
                    issues.append(f"Resource policy statement '{sid}' allows public invoke access")
                elif self._is_s3_invoke_without_source_account(statement):
                    sid = statement.get("Sid", "unknown")
                    issues.append(
                        f"Resource policy statement '{sid}' allows S3 invoke without AWS:SourceAccount"
                    )
        except ClientError as error:
            if not self._is_not_found(error):
                self._add_lambda_error(
                    check_id="LAMBDA-1",
                    check_name="Lambda Public Access",
                    function_name=function_name,
                    region=region,
                    description=f"Unable to inspect Lambda resource policy: {error}",
                    severity=Severity.CRITICAL,
                )
                return

        self.add_finding(
            check_id="LAMBDA-1",
            check_name="Lambda Public Access",
            status=Status.FAIL if issues else Status.PASS,
            severity=Severity.CRITICAL,
            resource_id=function_name,
            resource_type="AWS::Lambda::Function",
            region=region,
            description=("; ".join(issues) if issues else "No public Lambda invoke paths detected"),
            remediation=(
                "Remove public invoke permissions, require fixed AWS:SourceAccount conditions for S3 "
                "triggers, and set Function URLs to AWS_IAM unless anonymous access is explicitly needed"
            ),
        )

    def _check_environment_encryption(self, function: dict, region: str) -> None:
        function_name = function["FunctionName"]
        environment_variables = function.get("Environment", {}).get("Variables", {})
        kms_key_arn = function.get("KMSKeyArn")

        has_variables = bool(environment_variables)
        uses_customer_kms = bool(kms_key_arn)

        if has_variables and not uses_customer_kms:
            description = f"Lambda function '{function_name}' has environment variables but no customer-managed KMS key"
            status = Status.FAIL
        elif has_variables and uses_customer_kms:
            description = f"Lambda function '{function_name}' encrypts environment variables with a customer-managed KMS key"
            status = Status.PASS
        else:
            description = (
                f"Lambda function '{function_name}' has no custom environment variables configured"
            )
            status = Status.PASS

        self.add_finding(
            check_id="LAMBDA-2",
            check_name="Lambda Environment Encryption",
            status=status,
            severity=Severity.HIGH,
            resource_id=function_name,
            resource_type="AWS::Lambda::Function",
            region=region,
            description=description,
            remediation=(
                "Configure a customer-managed KMS key for Lambda environment variables when storing "
                "configuration or sensitive values"
            ),
        )

    def _check_vpc_configuration(self, function: dict, region: str) -> None:
        function_name = function["FunctionName"]
        subnet_ids = function.get("VpcConfig", {}).get("SubnetIds", [])
        in_vpc = bool(function.get("VpcConfig", {}).get("VpcId")) and bool(subnet_ids)

        self.add_finding(
            check_id="LAMBDA-3",
            check_name="Lambda VPC Configuration",
            status=Status.PASS if in_vpc else Status.FAIL,
            severity=Severity.LOW,
            resource_id=function_name,
            resource_type="AWS::Lambda::Function",
            region=region,
            description=(
                f"Lambda function '{function_name}' is attached to a VPC"
                if in_vpc
                else f"Lambda function '{function_name}' is not attached to a VPC"
            ),
            remediation="Attach the function to private subnets in a VPC when network isolation is required",
        )

    def _check_multi_az(self, function: dict, ec2_client, region: str) -> None:
        function_name = function["FunctionName"]
        subnet_ids = function.get("VpcConfig", {}).get("SubnetIds", [])
        if not subnet_ids:
            return

        try:
            subnets = ec2_client.describe_subnets(SubnetIds=subnet_ids)["Subnets"]
        except ClientError as error:
            self._add_lambda_error(
                check_id="LAMBDA-4",
                check_name="Lambda Multi-AZ VPC",
                function_name=function_name,
                region=region,
                description=f"Unable to inspect Lambda subnets: {error}",
                severity=Severity.MEDIUM,
            )
            return

        availability_zones = {subnet["AvailabilityZone"] for subnet in subnets}
        multi_az = len(availability_zones) >= 2

        self.add_finding(
            check_id="LAMBDA-4",
            check_name="Lambda Multi-AZ VPC",
            status=Status.PASS if multi_az else Status.FAIL,
            severity=Severity.MEDIUM,
            resource_id=function_name,
            resource_type="AWS::Lambda::Function",
            region=region,
            description=(
                f"Lambda function '{function_name}' uses subnets in {len(availability_zones)} Availability Zones"
            ),
            remediation="Select subnets from at least two Availability Zones for VPC-connected Lambda functions",
        )

    def _check_tags(self, lambda_client, function: dict, region: str) -> None:
        function_name = function["FunctionName"]
        function_arn = function["FunctionArn"]

        try:
            tag_response = lambda_client.list_tags(Resource=function_arn)
        except ClientError as error:
            self._add_lambda_error(
                check_id="LAMBDA-5",
                check_name="Lambda Resource Tags",
                function_name=function_name,
                region=region,
                description=f"Unable to inspect Lambda tags: {error}",
                severity=Severity.LOW,
            )
            return

        tags = tag_response.get("Tags", {})
        user_tags = {key: value for key, value in tags.items() if not key.startswith("aws:")}

        self.add_finding(
            check_id="LAMBDA-5",
            check_name="Lambda Resource Tags",
            status=Status.PASS if user_tags else Status.FAIL,
            severity=Severity.LOW,
            resource_id=function_name,
            resource_type="AWS::Lambda::Function",
            region=region,
            description=(
                f"Lambda function '{function_name}' has user-defined tags"
                if user_tags
                else f"Lambda function '{function_name}' has no user-defined tags"
            ),
            remediation="Add ownership, environment, and service tags to Lambda functions",
        )

    def _check_xray_tracing(self, function: dict, region: str) -> None:
        function_name = function["FunctionName"]
        tracing_mode = function.get("TracingConfig", {}).get("Mode", "PassThrough")
        active_tracing = tracing_mode == "Active"

        self.add_finding(
            check_id="LAMBDA-6",
            check_name="Lambda X-Ray Tracing",
            status=Status.PASS if active_tracing else Status.FAIL,
            severity=Severity.LOW,
            resource_id=function_name,
            resource_type="AWS::Lambda::Function",
            region=region,
            description=(
                f"Lambda function '{function_name}' has X-Ray active tracing enabled"
                if active_tracing
                else f"Lambda function '{function_name}' does not have X-Ray active tracing enabled"
            ),
            remediation="Enable AWS X-Ray active tracing to improve visibility into Lambda execution paths",
        )

    def _add_lambda_error(
        self,
        check_id: str,
        check_name: str,
        function_name: str,
        region: str,
        description: str,
        severity: Severity,
    ) -> None:
        self.add_finding(
            check_id=check_id,
            check_name=check_name,
            status=Status.ERROR,
            severity=severity,
            resource_id=function_name,
            resource_type="AWS::Lambda::Function",
            region=region,
            description=description,
        )

    def _get_policy_statements(self, policy_document: dict) -> list[dict]:
        statements = policy_document.get("Statement", [])
        if isinstance(statements, dict):
            return [statements]
        return statements

    def _is_public_invoke_statement(self, statement: dict) -> bool:
        return self._allows_invoke(statement) and self._has_public_principal(
            statement.get("Principal")
        )

    def _is_s3_invoke_without_source_account(self, statement: dict) -> bool:
        return (
            self._allows_invoke(statement)
            and self._has_service_principal(statement.get("Principal"), "s3.amazonaws.com")
            and not self._has_fixed_source_account(statement.get("Condition", {}))
        )

    def _allows_invoke(self, statement: dict) -> bool:
        if statement.get("Effect") != "Allow":
            return False

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        normalized_actions = {action.lower() for action in actions}
        return bool(
            normalized_actions.intersection(
                {"*", "lambda:*", "lambda:invokefunction", "lambda:invokefunctionurl"}
            )
        )

    def _has_public_principal(self, principal) -> bool:
        if principal == "*":
            return True
        if isinstance(principal, list):
            return any(self._has_public_principal(item) for item in principal)
        if isinstance(principal, dict):
            return any(self._has_public_principal(value) for value in principal.values())
        return False

    def _has_service_principal(self, principal, service: str) -> bool:
        if isinstance(principal, dict):
            service_principal = principal.get("Service")
            if isinstance(service_principal, str):
                return service_principal == service
            if isinstance(service_principal, list):
                return service in service_principal
        return False

    def _has_fixed_source_account(self, condition: dict) -> bool:
        for key, value in condition.items():
            if key.lower() == "aws:sourceaccount":
                return self._is_fixed_condition_value(value)
            if isinstance(value, dict) and self._has_fixed_source_account(value):
                return True
        return False

    def _is_fixed_condition_value(self, value) -> bool:
        if isinstance(value, str):
            return "*" not in value and "${" not in value
        if isinstance(value, list):
            return all(self._is_fixed_condition_value(item) for item in value)
        return False

    def _is_not_found(self, error: ClientError) -> bool:
        error_code = error.response.get("Error", {}).get("Code")
        return error_code in {"ResourceNotFoundException", "ResourceNotFound"}
