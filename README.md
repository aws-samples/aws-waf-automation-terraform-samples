## Terraform-aws-waf-automation Samples

AWS Web Application Firewall (AWS WAF) helps protect web applications from common exploits that can affect application availability, compromise security, or consume excessive resources.AWS WAF allows you to define customisable web security rules and control which traffic to allow to web applications and APIs deployed on Amazon CloudFront, an Application LoadBalancer, or Amazon API Gateway.

https://aws.amazon.com/solutions/implementations/aws-waf-security-automations/

## Target Architecture

## Prerequisites

1. An active AWS account.
2. AWS Command Line Interface (AWS CLI) installed and configured with necessary permissions. For more information about this , refer this documentation 
3. Terraform installed and configured. For more information about this , refer this documentation

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

Error: Error deleting WAFv2 IPSet: WAFOptimisticLockException: AWS WAF couldn’t save your changes because someone changed the resource after you started to edit it. Reapply your changes.

## Workaround:

Delete the IPsets manually and retry the terraform destroy command. 
Reference : https://github.com/hashicorp/terraform-provider-aws/issues/21136 

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

