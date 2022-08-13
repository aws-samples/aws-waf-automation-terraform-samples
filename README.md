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

