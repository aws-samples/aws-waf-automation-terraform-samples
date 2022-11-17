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

Check out this APG Pattern for detailed deployment instructions: [Deploy the Security Automations for AWS WAF solution by using Terraform](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/deploy-the-security-automations-for-aws-waf-solution-by-using-terraform.html)

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
