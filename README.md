## AWS WAF Automation Using Terraform

[WAF Automation on AWS](https://aws.amazon.com/solutions/implementations/aws-waf-security-automations/) solution is developed using Terraform which automatically deploys a set of [AWS WAF](https://aws.amazon.com/waf/) rules that filter common web-based attacks. Users can select from preconfigured protective features that define the rules included in an AWS WAF web access control list (web ACL). Once deployed, AWS WAF protects your [Amazon CloudFront](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html) distributions or [Application Load Balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html) by inspecting web requests.


## Target Architecture

<img width="951" alt="image" src="https://user-images.githubusercontent.com/111126012/184378602-b8feebb5-e5db-41d9-a296-0580d21f73fc.png">


## Prerequisites

1. An active AWS account.
2. AWS Command Line Interface (AWS CLI) installed and configured with necessary permissions. For more information about this , refer [this documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html). 
3. Terraform installed and configured. For more information about this , refer [this documentation](https://learn.hashicorp.com/tutorials/terraform/install-cli).

## Deployment

```
terraform init
terraform plan -var-file="testing.tfvars"
terraform apply -var-file="testing.tfvars"
```
## Types of inputs:

```
ActivateHttpFloodProtectionParam = yes - AWS Lambda log parser, yes - Amazon Athena log parser,yes - AWS WAF rate based rule
ActivateScannersProbesProtectionParam =yes - AWS Lambda log parser, yes - Amazon Athena log parser
ENDPOINT = ALB , cloudfront
```

## Existing issue:

Error: Error deleting WAFv2 IPSet: WAFOptimisticLockException: AWS WAF couldn’t save your changes because someone changed the resource after you started to edit it. Re-apply your changes.

## Workaround:

Delete the IPsets manually and retry the terraform destroy command. 
Reference : https://github.com/hashicorp/terraform-provider-aws/issues/21136 

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 3.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | ~> 3.0 |
| <a name="provider_random"></a> [random](#provider\_random) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_api_gateway_account.ApiGatewayBadBotAccount](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_account) | resource |
| [aws_api_gateway_deployment.deployment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_deployment) | resource |
| [aws_api_gateway_integration.integration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_integration) | resource |
| [aws_api_gateway_integration.integrationroot](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_integration) | resource |
| [aws_api_gateway_method.ApiGatewayBadBotMethod](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method) | resource |
| [aws_api_gateway_method.ApiGatewayBadBotMethodRoot](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method) | resource |
| [aws_api_gateway_method_settings.path_specific](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method_settings) | resource |
| [aws_api_gateway_resource.resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_resource) | resource |
| [aws_api_gateway_rest_api.api](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_rest_api) | resource |
| [aws_api_gateway_stage.stage](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage) | resource |
| [aws_athena_workgroup.WAFAddPartitionAthenaQueryWorkGroup](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup) | resource |
| [aws_athena_workgroup.WAFAppAccessLogAthenaQueryWorkGroup](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup) | resource |
| [aws_athena_workgroup.WAFLogAthenaQueryWorkGroup](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup) | resource |
| [aws_cloudformation_stack.trigger_codebuild_stack](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudformation_stack) | resource |
| [aws_cloudwatch_dashboard.main](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_dashboard) | resource |
| [aws_cloudwatch_event_rule.LambdaAddAthenaPartitionsEventsRule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.LambdaAthenaAppLogParserrule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.LambdaAthenaWAFLogParserrule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.ReputationListsParserEventsRule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.SetIPRetentionEventsRule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_target.LambdaAddAthenaPartitionstarget](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.LogParsertarget](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.LogParsertarget1](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.ReputationListsParsertarget](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.SetIPRetentionEventstarget](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_log_group.ApiGatewayBadBotStageAccessLogGroup](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_dynamodb_table.IPRetentionDDBTable](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table) | resource |
| [aws_glue_catalog_database.mydatabase](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/glue_catalog_database) | resource |
| [aws_glue_catalog_table.ALBGlueAppAccessLogsTable](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/glue_catalog_table) | resource |
| [aws_glue_catalog_table.cloudfrontGlueAppAccessLogsTable](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/glue_catalog_table) | resource |
| [aws_glue_catalog_table.waf_access_logs_table](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/glue_catalog_table) | resource |
| [aws_iam_policy.replication](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.replicationaccesslog](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_role.ApiGatewayBadBotCloudWatchRole](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.FirehoseWAFLogsDeliveryStreamRole](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.LambdaRoleAddAthenaPartitions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.LambdaRoleBadBot](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.LambdaRoleCustomResource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.LambdaRoleCustomTimer](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.LambdaRoleHelper](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.LambdaRoleLogParser](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.LambdaRolePartitionS3Logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.LambdaRoleRemoveExpiredIP](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.LambdaRoleReputationListsParser](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.LambdaRoleSetIPRetention](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.replication](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.replicationaccesslog](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.s3bucketaccessrole](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.AddAthenaPartitionsForAppAccessLog](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.AddAthenaPartitionsForWAFLog](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.ApiGatewayBadBotCloudWatchploicy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.CloudWatchAccess](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.CloudWatchAccessListsParser](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.CloudWatchAccessbadbot](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.CloudWatchLogsListsParser](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.CloudWatchLogstimer](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.CustomResourceLambdaAccess](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.CustomResourceLogsAccess](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.CustomResourceS3BucketLoggingAccess](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.DDBAccess](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.DDBStreamAccess](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.HttpFloodAthenaLogParser](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.HttpFloodAthenaLogParserLogsAccess](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.HttpFloodProtectionLogParser](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.IPSetAccess](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.InvokeLambda](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.KinesisAccess](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.LambdaRoleCloudWatchAccess](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.LambdaRoleLogsAccess1](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.LogsAccessLambdaRoleRemoveExpiredIP](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.LogsAccessSetIPRetention](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.LogsAccessbadbot](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.LogsAccesshelper](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.LogsAccesshelperPartitions3](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.PartitionS3LogsAccess](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.S3Access](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.S3AccessFirehoseWAFLogs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.S3AccessGeneralAppAccessLog](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.S3AccessGeneralWafLog](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.S3Accesshelper](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.S3AppAccessPut](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.S3LogParser](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.S3WafAccessPut](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.SNSPublishPolicy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.ScannersProbesAthenaLogParser](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.WAFAccess](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.WAFAccessLambdaRoleRemoveExpiredIP](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.WAFAccesshelper](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.WAFGetAndUpdateIPListsParser](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.WAFGetAndUpdateIPSetbadbot](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.WAFLogsAccess](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.ec2Partition](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.ec2athena](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.ec2badbot](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.ec2customresource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.ec2customtimer](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.ec2expired](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.ec2helper](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.ec2logparser](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.ec2reputation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.ec2retention](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.sqsathena](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.sqsbadbot](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.sqscustomresource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.sqscustomtimer](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.sqsexpired](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.sqshelper](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.sqslogparser](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.sqspartition](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.sqsreputation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.sqsretention](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy_attachment.s3bucketaccessrole-policy-attach](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.test-attach](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.test-attach-log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_kinesis_firehose_delivery_stream.extended_s3_stream](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kinesis_firehose_delivery_stream) | resource |
| [aws_kms_key.wafkey](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_lambda_function.AddAthenaPartitions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.BadBotParser](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.CustomResource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.CustomTimer](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.LogParser](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.MoveS3LogsForPartition](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.RemoveExpiredIP](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.ReputationListsParser](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.SetIPRetention](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.helper](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_permission.LambdaInvokePermissionAppLogParserCloudWatch](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.LambdaInvokePermissionAppLogParserS3](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.LambdaInvokePermissionBadBot](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.LambdaInvokePermissionMoveS3LogsForPartition](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.LambdaInvokePermissionReputationListsParser](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.LambdaInvokePermissionSetIPRetention](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.LambdaInvokePermissionWafLogParserCloudWatch](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.LambdaPermissionAddAthenaPartitions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_s3_bucket.WafLogBucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket.accesslogbucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_policy.b](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_policy.wafbucketpolicy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_public_access_block.WafLogBucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_public_access_block.accesslogbucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_sns_topic.user_updates](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic_policy.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_policy) | resource |
| [aws_sns_topic_subscription.user_updates_sqs_target](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_subscription) | resource |
| [aws_wafv2_ip_set.WAFBadBotSetV4](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_ip_set.WAFBadBotSetV6](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_ip_set.WAFBlacklistSetV4](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_ip_set.WAFBlacklistSetV6](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_ip_set.WAFHttpFloodSetV4](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_ip_set.WAFHttpFloodSetV6](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_ip_set.WAFReputationListsSetV4](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_ip_set.WAFReputationListsSetV6](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_ip_set.WAFScannersProbesSetV4](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_ip_set.WAFScannersProbesSetV6](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_ip_set.WAFWhitelistSetV4](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_ip_set.WAFWhitelistSetV6](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_web_acl.wafacl](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl) | resource |
| [random_id.server](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/id) | resource |
| [random_uuid.test](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/uuid) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy.s3Access](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy) | data source |
| [aws_iam_policy_document.sns_topic_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_ActivateAWSManagedRulesParam"></a> [ActivateAWSManagedRulesParam](#input\_ActivateAWSManagedRulesParam) | n/a | `string` | `"no"` | no |
| <a name="input_ActivateBadBotProtectionParam"></a> [ActivateBadBotProtectionParam](#input\_ActivateBadBotProtectionParam) | n/a | `string` | `"yes"` | no |
| <a name="input_ActivateCrossSiteScriptingProtectionParam"></a> [ActivateCrossSiteScriptingProtectionParam](#input\_ActivateCrossSiteScriptingProtectionParam) | n/a | `string` | `"yes"` | no |
| <a name="input_ActivateHttpFloodProtectionParam"></a> [ActivateHttpFloodProtectionParam](#input\_ActivateHttpFloodProtectionParam) | n/a | `string` | `"yes - AWS WAF rate based rule"` | no |
| <a name="input_ActivateReputationListsProtectionParam"></a> [ActivateReputationListsProtectionParam](#input\_ActivateReputationListsProtectionParam) | n/a | `string` | `"yes"` | no |
| <a name="input_ActivateScannersProbesProtectionParam"></a> [ActivateScannersProbesProtectionParam](#input\_ActivateScannersProbesProtectionParam) | n/a | `string` | `""` | no |
| <a name="input_ActivateSqlInjectionProtectionParam"></a> [ActivateSqlInjectionProtectionParam](#input\_ActivateSqlInjectionProtectionParam) | n/a | `string` | `"yes"` | no |
| <a name="input_AppAccessLogBucket"></a> [AppAccessLogBucket](#input\_AppAccessLogBucket) | Application Access Log Bucket Name | `string` | `"myownbucket-tam"` | no |
| <a name="input_BadBotProtectionActivated"></a> [BadBotProtectionActivated](#input\_BadBotProtectionActivated) | n/a | `string` | `"yes"` | no |
| <a name="input_DeliveryStreamName"></a> [DeliveryStreamName](#input\_DeliveryStreamName) | Name of the Delivery stream value | `string` | `"terraform-kinesis-firehose-extended-s3-test-stream"` | no |
| <a name="input_ENDPOINT"></a> [ENDPOINT](#input\_ENDPOINT) | cloudfront or ALB | `string` | `"cloudFront"` | no |
| <a name="input_ErrorThreshold"></a> [ErrorThreshold](#input\_ErrorThreshold) | error threshold for Log Monitoring Settings | `number` | `50` | no |
| <a name="input_IPRetentionPeriod"></a> [IPRetentionPeriod](#input\_IPRetentionPeriod) | n/a | `string` | `"no"` | no |
| <a name="input_IPRetentionPeriodAllowedParam"></a> [IPRetentionPeriodAllowedParam](#input\_IPRetentionPeriodAllowedParam) | IP Retention Settings allowed value | `number` | `-1` | no |
| <a name="input_IPRetentionPeriodDeniedParam"></a> [IPRetentionPeriodDeniedParam](#input\_IPRetentionPeriodDeniedParam) | IP Retention Settings denied value | `number` | `-1` | no |
| <a name="input_KEEP_ORIGINAL_DATA"></a> [KEEP\_ORIGINAL\_DATA](#input\_KEEP\_ORIGINAL\_DATA) | S3 original data | `string` | `"No"` | no |
| <a name="input_KeyPrefix"></a> [KeyPrefix](#input\_KeyPrefix) | Keyprefix values for the lambda source code | `string` | `"aws-waf-security-automations/v3.2.0"` | no |
| <a name="input_LOG_LEVEL"></a> [LOG\_LEVEL](#input\_LOG\_LEVEL) | Log level | `string` | `"INFO"` | no |
| <a name="input_MetricsURL"></a> [MetricsURL](#input\_MetricsURL) | Metrics URL | `string` | `"https://metrics.awssolutionsbuilder.com/generic"` | no |
| <a name="input_ReputationListsProtectionActivated"></a> [ReputationListsProtectionActivated](#input\_ReputationListsProtectionActivated) | n/a | `string` | `"yes"` | no |
| <a name="input_RequestThreshold"></a> [RequestThreshold](#input\_RequestThreshold) | request threshold for Log Monitoring Settings | `number` | `100` | no |
| <a name="input_SEND_ANONYMOUS_USAGE_DATA"></a> [SEND\_ANONYMOUS\_USAGE\_DATA](#input\_SEND\_ANONYMOUS\_USAGE\_DATA) | Data collection parameter | `string` | `"yes"` | no |
| <a name="input_SNSEmailParam"></a> [SNSEmailParam](#input\_SNSEmailParam) | SNS notification value | `string` | `""` | no |
| <a name="input_ScannersProbesProtectionActivated"></a> [ScannersProbesProtectionActivated](#input\_ScannersProbesProtectionActivated) | n/a | `string` | `"yes"` | no |
| <a name="input_SendAnonymousUsageData"></a> [SendAnonymousUsageData](#input\_SendAnonymousUsageData) | Data collection parameter | `string` | `"yes"` | no |
| <a name="input_SolutionID"></a> [SolutionID](#input\_SolutionID) | UserAgent id value | `string` | `"SO0006"` | no |
| <a name="input_SourceBucket"></a> [SourceBucket](#input\_SourceBucket) | Lambda source code bucket | `string` | `"solutions"` | no |
| <a name="input_USER_AGENT_EXTRA"></a> [USER\_AGENT\_EXTRA](#input\_USER\_AGENT\_EXTRA) | UserAgent | `string` | `"AwsSolution/SO0006/v3.2.0"` | no |
| <a name="input_WAFBlockPeriod"></a> [WAFBlockPeriod](#input\_WAFBlockPeriod) | block period for Log Monitoring Settings | `number` | `240` | no |
| <a name="input_app_access_logs_columns"></a> [app\_access\_logs\_columns](#input\_app\_access\_logs\_columns) | n/a | `map` | <pre>{<br>  "actions_executed": "string",<br>  "chosen_cert_arn": "string",<br>  "client_ip": "string",<br>  "client_port": "int",<br>  "domain_name": "string",<br>  "elb": "string",<br>  "elb_status_code": "string",<br>  "lambda_error_reason": "string",<br>  "matched_rule_priority": "string",<br>  "new_field": "string",<br>  "received_bytes": "bigint",<br>  "redirect_url": "string",<br>  "request_creation_time": "string",<br>  "request_processing_time": "double",<br>  "request_proto": "string",<br>  "request_url": "string",<br>  "request_verb": "string",<br>  "response_processing_time": "double",<br>  "sent_bytes": "bigint",<br>  "ssl_cipher": "string",<br>  "ssl_protocol": "string",<br>  "target_group_arn": "string",<br>  "target_ip": "string",<br>  "target_port": "int",<br>  "target_processing_time": "double",<br>  "target_status_code": "string",<br>  "time": "string",<br>  "trace_id": "string",<br>  "type": "string",<br>  "user_agent": "string"<br>}</pre> | no |
| <a name="input_cloudfront_app_access_logs_columns"></a> [cloudfront\_app\_access\_logs\_columns](#input\_cloudfront\_app\_access\_logs\_columns) | n/a | `map` | <pre>{<br>  "bytes": "bigint",<br>  "cookie": "string",<br>  "date": "date",<br>  "encryptedfields": "int",<br>  "filestatus": "string",<br>  "host": "string",<br>  "hostheader": "string",<br>  "httpversion": "string",<br>  "location": "string",<br>  "method": "string",<br>  "querystring": "string",<br>  "referrer": "string",<br>  "requestbytes": "bigint",<br>  "requestid": "string",<br>  "requestip": "string",<br>  "requestprotocol": "string",<br>  "responseresulttype": "string",<br>  "resulttype": "string",<br>  "sslcipher": "string",<br>  "sslprotocol": "string",<br>  "status": "int",<br>  "time": "string",<br>  "timetaken": "float",<br>  "uri": "string",<br>  "useragent": "string",<br>  "xforwardedfor": "string"<br>}</pre> | no |
| <a name="input_sse_algorithm"></a> [sse\_algorithm](#input\_sse\_algorithm) | sse\_algorithm | `string` | `"aws:kms"` | no |
| <a name="input_waf_access_logs_columns"></a> [waf\_access\_logs\_columns](#input\_waf\_access\_logs\_columns) | n/a | `map` | <pre>{<br>  "action": "string",<br>  "formatversion": "int",<br>  "httprequest": "struct<clientip:string,country:string,headers:array<struct<name:string,value:string>>,uri:string,args:string,httpversion:string,httpmethod:string,requestid:string>",<br>  "httpsourceid": "string",<br>  "httpsourcename": "string",<br>  "nonterminatingmatchingrules": "array<string>",<br>  "ratebasedrulelist": "array<string>",<br>  "rulegrouplist": "array<string>",<br>  "terminatingruleid": "string",<br>  "terminatingruletype": "string",<br>  "timestamp": "bigint",<br>  "webaclid": "string"<br>}</pre> | no |

## Outputs

No outputs.
