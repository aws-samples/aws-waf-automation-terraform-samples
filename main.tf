data "aws_partition" "current" {}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

resource "random_uuid" "test" {
}

resource "random_id" "server" {
  byte_length = 8
}

locals {
  AppLogBucket = "${var.AppAccessLogBucket}-${random_id.server.hex}"
}


resource "aws_kms_key" "wafkey" {
  description         = "KMS key 1"
  enable_key_rotation = true
  policy              = <<EOF
{
  "Version" : "2012-10-17",
  "Id" : "key-default-1",
  "Statement" : [ {
      "Sid" : "Enable IAM User Permissions",
      "Effect" : "Allow",
      "Principal" : {
        "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      },
        "Action": [ 
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:GenerateDataKey*",
          "kms:Get*",
          "kms:Delete*",
          "kms:ScheduleKeyDeletion",
          "kms:ListAliases",
          "kms:CreateGrant",
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:CancelKeyDeletion"
      ],
      "Resource" : "*"
    },
    {
      "Effect": "Allow",
      "Principal": { "Service": "logs.${data.aws_region.current.name}.amazonaws.com" },
      "Action": [ 
        "kms:Encrypt*",
        "kms:Decrypt*",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:Describe*"
      ],
      "Resource": "*"
    }  
  ]
}
EOF
}

resource "aws_sns_topic" "user_updates" {
  count             = local.SNSEmail == "yes" ? 1 : 0
  name              = join("-", ["AWS-WAF-Security-Automations-IP-Expiration-Notification", "${aws_cloudformation_stack.trigger_codebuild_stack.outputs.UUID}"])
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "user_updates_sqs_target" {
  count     = local.SNSEmail == "yes" ? 1 : 0
  topic_arn = aws_sns_topic.user_updates[0].arn
  protocol  = "email"
  endpoint  = var.SNSEmailParam
  depends_on = [
    aws_sns_topic.user_updates
  ]
}

resource "aws_sns_topic_policy" "default" {
  count  = local.SNSEmail == "yes" ? 1 : 0
  arn    = aws_sns_topic.user_updates[0].arn
  policy = data.aws_iam_policy_document.sns_topic_policy[0].json
  depends_on = [
    aws_sns_topic.user_updates
  ]
}

data "aws_iam_policy_document" "sns_topic_policy" {
  count     = local.SNSEmail == "yes" ? 1 : 0
  policy_id = "__default_policy_ID"

  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
      "SNS:RemovePermission",
      "SNS:Receive",
      "SNS:Publish",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:AddPermission",
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"

      values = [
        data.aws_caller_identity.current.account_id,
      ]
    }

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      aws_sns_topic.user_updates[0].arn,
    ]

    sid = "__default_statement_ID"
  }
}



### S3 bucket Creation

resource "aws_s3_bucket" "WafLogBucket" {
  count         = local.HttpFloodProtectionLogParserActivated == "yes" ? 1 : 0
  bucket        = "${random_id.server.hex}-waflogbucket"
  acl           = "private"
  force_destroy = true
  versioning {
    enabled = true
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = var.sse_algorithm
      }
    }
  }
  logging {
    target_bucket = aws_s3_bucket.accesslogbucket[0].bucket
    target_prefix = "WAF_Logs/"
  }
}

resource "aws_s3_bucket_public_access_block" "WafLogBucket" {
  count                   = local.HttpFloodProtectionLogParserActivated == "yes" ? 1 : 0
  bucket                  = aws_s3_bucket.WafLogBucket[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  depends_on = [
    aws_s3_bucket.WafLogBucket
  ]
}

resource "aws_s3_bucket_policy" "wafbucketpolicy" {
  count         = local.HttpFloodProtectionLogParserActivated == "yes" ? 1 : 0
  bucket = aws_s3_bucket.WafLogBucket[0].id

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${aws_iam_role.s3bucketaccessrole.name}"
                ]
            },
            "Action": "s3:*",
            "Resource": [
                "${aws_s3_bucket.WafLogBucket[0].arn}",
                "${aws_s3_bucket.WafLogBucket[0].arn}/*"
            ]
        },
        {
            "Sid": "HttpsOnly",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                "${aws_s3_bucket.WafLogBucket[0].arn}",
                "${aws_s3_bucket.WafLogBucket[0].arn}/*"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }
    ]
}
POLICY
  depends_on = [
    aws_s3_bucket.WafLogBucket
  ]
}


data "aws_iam_policy" "s3Access" {
  arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_role" "s3bucketaccessrole" {
  name  = "s3-bucket-role-${random_id.server.hex}"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "s3.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "s3bucketaccessrole-policy-attach" {
  role       = "${aws_iam_role.s3bucketaccessrole.name}"
  policy_arn = "${data.aws_iam_policy.s3Access.arn}"
}

resource "aws_iam_role" "replication" {
  count = local.HttpFloodProtectionLogParserActivated == "yes" ? 1 : 0
  name  = "tf-iam-role-${random_id.server.hex}"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "s3.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_policy" "replication" {
  count = local.HttpFloodProtectionLogParserActivated == "yes" ? 1 : 0
  name  = "tf-iam-role-policy-${random_id.server.hex}"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:GetReplicationConfiguration",
        "s3:ListBucket"
      ],
      "Effect": "Allow",
      "Resource": [
        "${aws_s3_bucket.WafLogBucket[0].arn}"
      ]
    },
    {
      "Action": [
        "s3:GetObjectVersionForReplication",
        "s3:GetObjectVersionAcl",
         "s3:GetObjectVersionTagging"
      ],
      "Effect": "Allow",
      "Resource": [
        "${aws_s3_bucket.WafLogBucket[0].arn}/*"
      ]
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "test-attach" {
  count = local.HttpFloodProtectionLogParserActivated == "yes" ? 1 : 0
  role       = aws_iam_role.replication[0].name
  policy_arn = aws_iam_policy.replication[0].arn
}

###AccessLoggingBucket

resource "aws_s3_bucket" "accesslogbucket" {
  count         = local.LogParser == "yes" ? 1 : 0
  bucket        = "${random_id.server.hex}-accesslogging"
  acl           = "log-delivery-write"
  force_destroy = true
  versioning {
    enabled = true
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = var.sse_algorithm
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "accesslogbucket" {
  count                   = local.LogParser == "yes" ? 1 : 0
  bucket                  = aws_s3_bucket.accesslogbucket[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  depends_on = [
    aws_s3_bucket.accesslogbucket
  ]
}

resource "aws_s3_bucket_policy" "b" {
  count  = local.LogParser == "yes" ? 1 : 0
  bucket = aws_s3_bucket.accesslogbucket[0].id

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
            {
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${aws_iam_role.s3bucketaccessrole.name}"
                ]
            },
            "Action": "s3:*",
            "Resource": [
                "${aws_s3_bucket.accesslogbucket[0].arn}",
                "${aws_s3_bucket.accesslogbucket[0].arn}/*"
            ]
        },
        {
            "Sid": "HttpsOnly",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                "${aws_s3_bucket.accesslogbucket[0].arn}",
                "${aws_s3_bucket.accesslogbucket[0].arn}/*"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }
    ]
}
POLICY
  depends_on = [
    aws_s3_bucket.accesslogbucket
  ]
}

resource "aws_iam_role" "replicationaccesslog" {
  count = local.LogParser == "yes" ? 1 : 0
  name  = "tf-iam-role-replication-${random_id.server.hex}"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "s3.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_policy" "replicationaccesslog" {
  count  = local.LogParser == "yes" ? 1 : 0
  name   = "tf-iam-role-policy-repl-${random_id.server.hex}"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:GetReplicationConfiguration",
        "s3:ListBucket"
      ],
      "Effect": "Allow",
      "Resource": [
        "${aws_s3_bucket.accesslogbucket[0].arn}"
      ]
    },
    {
      "Action": [
        "s3:GetObjectVersionForReplication",
        "s3:GetObjectVersionAcl",
         "s3:GetObjectVersionTagging"
      ],
      "Effect": "Allow",
      "Resource": [
        "${aws_s3_bucket.accesslogbucket[0].arn}/*"
      ]
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "test-attach-log" {
  count  = local.LogParser == "yes" ? 1 : 0
  role       = aws_iam_role.replicationaccesslog[0].name
  policy_arn = aws_iam_policy.replicationaccesslog[0].arn
}

# ----------------------------------------------------------------------------------------------------------------------
# IP set Creation for WAF
# ----------------------------------------------------------------------------------------------------------------------

#IPV4 sets

resource "aws_wafv2_ip_set" "WAFWhitelistSetV4" {
  name               = "WAFWhitelistSetV41"
  description        = "Block Bad Bot IPV4 addresses"
  scope              = local.SCOPE
  ip_address_version = "IPV4"
  addresses          = []
}

resource "aws_wafv2_ip_set" "WAFBlacklistSetV4" {
  name               = "WAFBlacklistSetV41"
  description        = "Block Bad Bot IPV6 addresses"
  scope              = local.SCOPE
  ip_address_version = "IPV6"
  addresses          = []
}

resource "aws_wafv2_ip_set" "WAFBadBotSetV4" {
  count              = var.BadBotProtectionActivated == "yes" ? 1 : 0
  name               = "WAFBadBotSetV41"
  description        = "Block Bad Bot IPV4 addresses"
  scope              = local.SCOPE
  ip_address_version = "IPV4"
  addresses          = []
}

resource "aws_wafv2_ip_set" "WAFReputationListsSetV4" {
  count              = var.ReputationListsProtectionActivated == "yes" ? 1 : 0
  name               = "WAFReputationListsSetV41"
  description        = "Block Reputation List IPV4 addresses"
  scope              = local.SCOPE
  ip_address_version = "IPV4"
  addresses          = []
  lifecycle {
    ignore_changes = [
      addresses
    ]
  }
}

resource "aws_wafv2_ip_set" "WAFHttpFloodSetV4" {
  name               = "WAFHttpFloodSetV41"
  description        = "Block HTTP Flood IPV4 addresses"
  scope              = local.SCOPE
  ip_address_version = "IPV4"
  addresses          = []
}

resource "aws_wafv2_ip_set" "WAFScannersProbesSetV4" {
  count              = var.ScannersProbesProtectionActivated == "yes" ? 1 : 0
  name               = "WAFScannersProbesSetV41"
  description        = "Block HTTP Flood IPV4 addresses"
  scope              = local.SCOPE
  ip_address_version = "IPV4"
  addresses          = []
}

#IPV6 sets

resource "aws_wafv2_ip_set" "WAFWhitelistSetV6" {
  name               = "WAFWhitelistSetV61"
  description        = "Block Bad Bot IPV4 addresses"
  scope              = local.SCOPE
  ip_address_version = "IPV4"
  addresses          = []
}

resource "aws_wafv2_ip_set" "WAFBlacklistSetV6" {
  name               = "WAFBlacklistSetV61"
  description        = "Block Bad Bot IPV6 addresses"
  scope              = local.SCOPE
  ip_address_version = "IPV6"
  addresses          = []
}

resource "aws_wafv2_ip_set" "WAFBadBotSetV6" {
  count              = var.BadBotProtectionActivated == "yes" ? 1 : 0
  name               = "WAFBadBotSetV61"
  description        = "Block Bad Bot IPV6 addresses"
  scope              = local.SCOPE
  ip_address_version = "IPV6"
  addresses          = []
}

resource "aws_wafv2_ip_set" "WAFReputationListsSetV6" {
  count              = var.ReputationListsProtectionActivated == "yes" ? 1 : 0
  name               = "WAFReputationListsSetV61"
  description        = "Block Reputation List IPV6 addresses"
  scope              = local.SCOPE
  ip_address_version = "IPV4"
  addresses          = []
  lifecycle {
    ignore_changes = [
      addresses
    ]
  }
}

resource "aws_wafv2_ip_set" "WAFHttpFloodSetV6" {
  name               = "WAFHttpFloodSetV61"
  description        = "Block HTTP Flood IPV6 addresses"
  scope              = local.SCOPE
  ip_address_version = "IPV6"
  addresses          = []
}

resource "aws_wafv2_ip_set" "WAFScannersProbesSetV6" {
  count              = var.ScannersProbesProtectionActivated == "yes" ? 1 : 0
  name               = "WAFScannersProbesSetV61"
  description        = "Block HTTP Flood IPV6 addresses"
  scope              = local.SCOPE
  ip_address_version = "IPV6"
  addresses          = []
}



# ----------------------------------------------------------------------------------------------------------------------
#   WAFWebACL:
# ----------------------------------------------------------------------------------------------------------------------

resource "aws_wafv2_web_acl" "wafacl" {
  name        = "wafwebacl-rules-${random_id.server.hex}"
  description = "Custom WAFWebACL"
  scope       = local.SCOPE
  default_action {
    allow {}
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "WAFWebACL-metric"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "WAFWebACL-metric"
      sampled_requests_enabled   = true
    }
  }
  rule {
    name     = "aws-AWSManagedRulesCommonRuleSet"
    priority = 0
    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "MetricForAMRCRS"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "WAFWhitelistRule1"
    priority = 1
    action {
      allow {}
    }

    statement {
      or_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.WAFWhitelistSetV4.arn
          }
        }
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.WAFWhitelistSetV4.arn
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "MetricForWhitelistRule"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "WAFBlacklistRule1"
    priority = 2
    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.WAFBlacklistSetV4.arn
          }
        }
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.WAFBlacklistSetV4.arn
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "MetricForBlacklistRule"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "HttpFloodRegularRule"
    priority = 3
    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          ip_set_reference_statement {
            arn = local.WAFHttpFloodSetIPV4arn
          }
        }
        statement {
          ip_set_reference_statement {
            arn = local.WAFHttpFloodSetIPV6arn
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "MetricForHttpFloodRegularRule"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "HttpFloodRateBasedRule"
    priority = 4
    action {
      block {}
    }

    statement {
      rate_based_statement {
        aggregate_key_type = "IP"
        limit              = var.RequestThreshold
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "MetricForHttpFloodRateBasedRule"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "ScannersAndProbesRule"
    priority = 5
    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.WAFScannersProbesSetV4[0].arn
          }
        }
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.WAFScannersProbesSetV6[0].arn
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "MetricForScannersProbesRulee"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "IPReputationListsRule"
    priority = 6
    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.WAFReputationListsSetV4[0].arn
          }
        }
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.WAFReputationListsSetV6[0].arn
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "MetricForIPReputationListsRule"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "BadBotRule"
    priority = 7
    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.WAFBadBotSetV4[0].arn
          }
        }
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.WAFBadBotSetV6[0].arn
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "MetricForBadBotRule"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "SqlInjectionRule"
    priority = 20
    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          sqli_match_statement {
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
        statement {
          sqli_match_statement {
            field_to_match {
              body {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
        statement {
          sqli_match_statement {
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
        statement {
          sqli_match_statement {
            field_to_match {
              single_header {
                name = "authorization"
              }
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
        statement {
          sqli_match_statement {
            field_to_match {
              single_header {
                name = "cookie"
              }
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "MetricForSqlInjectionRule"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "XssRule"
    priority = 30
    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          xss_match_statement {
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
        statement {
          xss_match_statement {
            field_to_match {
              body {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
        statement {
          xss_match_statement {
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
        statement {
          xss_match_statement {
            field_to_match {
              single_header {
                name = "cookie"
              }
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }

            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "MetricForXssRule"
      sampled_requests_enabled   = true
    }
  }
}

# ----------------------------------------------------------------------------------------------------------------------
# Dynamo DB table -This DynamoDB table constains transactional ip retention data that will be expired by DynamoDB TTL. The data doesn't need to be retained after its lifecycle ends.
# ----------------------------------------------------------------------------------------------------------------------

resource "aws_dynamodb_table" "IPRetentionDDBTable" {
  count            = var.IPRetentionPeriod == "yes" ? 1 : 0
  name             = "IPRetentionDDBTable-${random_id.server.hex}"
  billing_mode     = "PAY_PER_REQUEST"
  stream_enabled   = true
  stream_view_type = "OLD_IMAGE"
  hash_key         = "IPSetId"
  range_key        = "ExpirationTime"
  attribute {
    name = "IPSetId"
    type = "S"
  }

  attribute {
    name = "ExpirationTime"
    type = "N"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.wafkey.arn
  }

  ttl {
    attribute_name = "ExpirationTime"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }
}

# ----------------------------------------------------------------------------------------------------------------------
# Role Creation for Lambda functions
# ----------------------------------------------------------------------------------------------------------------------

#Role 1 - LambdaRoleHelper

resource "aws_iam_role" "LambdaRoleHelper" {
  name = "LambdaRoleHelper1-${random_id.server.hex}"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "S3Accesshelper" {
  name   = "S3Access1"
  role   = aws_iam_role.LambdaRoleHelper.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${local.AppLogBucket}"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleHelper
  ]
}

resource "aws_iam_role_policy" "ec2helper" {
  name   = "ec2helper"
  role   = aws_iam_role.LambdaRoleHelper.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ec2:CreateNetworkInterface"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:/*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleHelper
  ]
}

resource "aws_iam_role_policy" "sqshelper" {
  name   = "sqshelper"
  role   = aws_iam_role.LambdaRoleHelper.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sqs:SendMessage"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:sqs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleHelper
  ]
}

resource "aws_iam_role_policy" "WAFAccesshelper" {
  name   = "WAFAccess1"
  role   = aws_iam_role.LambdaRoleHelper.id
  policy = <<EOT
{
    "Statement": [
        {
            "Action": [
                "wafv2:ListWebACLs"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:wafv2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:regional/webacl/*",
                "arn:${data.aws_partition.current.partition}:wafv2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:global/webacl/*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleHelper
  ]
}

resource "aws_iam_role_policy" "LogsAccesshelper" {
  name   = "LogsAccess1"
  role   = aws_iam_role.LambdaRoleHelper.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*Helper*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleHelper
  ]
}

#Role 2 - LambdaRoleBadBot

resource "aws_iam_role" "LambdaRoleBadBot" {
  count = var.BadBotProtectionActivated == "yes" ? 1 : 0
  name  = "LambdaRoleBadBot1-${random_id.server.hex}"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "ec2badbot" {
  count  = var.BadBotProtectionActivated == "yes" ? 1 : 0
  name   = "ec2badbot"
  role   = aws_iam_role.LambdaRoleBadBot[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ec2:CreateNetworkInterface"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:/*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleBadBot
  ]
}

resource "aws_iam_role_policy" "sqsbadbot" {
  count  = var.BadBotProtectionActivated == "yes" ? 1 : 0
  name   = "sqsbadbot"
  role   = aws_iam_role.LambdaRoleBadBot[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sqs:SendMessage"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:sqs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleBadBot
  ]
}

resource "aws_iam_role_policy" "LogsAccessbadbot" {
  name   = "LogsAccess1"
  role   = aws_iam_role.LambdaRoleBadBot[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*BadBotParser*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleBadBot
  ]
}

resource "aws_iam_role_policy" "CloudWatchAccessbadbot" {
  name   = "CloudWatchAccess1"
  role   = aws_iam_role.LambdaRoleBadBot[0].id
  policy = <<EOT
{
    "Statement": [
        {
            "Action": "cloudwatch:GetMetricStatistics",
            "Resource": [
                "*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleBadBot
  ]
}

resource "aws_iam_role_policy" "WAFGetAndUpdateIPSetbadbot" {
  name   = "WAFGetAndUpdateIPSet1"
  role   = aws_iam_role.LambdaRoleBadBot[0].id
  policy = <<EOT
{
    "Statement": [
        {
            "Action": [
                "wafv2:GetIPSet",
                "wafv2:UpdateIPSet"
            ],
            "Resource": [
                "${aws_wafv2_ip_set.WAFBadBotSetV4[0].arn}",
                "${aws_wafv2_ip_set.WAFBadBotSetV6[0].arn}"
                ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleBadBot
  ]
}

#Role 3 - LambdaRolePartitionS3Logs

resource "aws_iam_role" "LambdaRolePartitionS3Logs" {
  count              = local.ScannersProbesAthenaLogParser == "yes" ? 1 : 0
  name               = "LambdaRolePartitionS3Logs1-${random_id.server.hex}"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "ec2Partition" {
  count  = local.ScannersProbesAthenaLogParser == "yes" ? 1 : 0
  name   = "ec2Partition"
  role   = aws_iam_role.LambdaRolePartitionS3Logs[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ec2:CreateNetworkInterface"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:/*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRolePartitionS3Logs
  ]
}

resource "aws_iam_role_policy" "sqspartition" {
  count  = local.ScannersProbesAthenaLogParser == "yes" ? 1 : 0
  name   = "sqspartition"
  role   = aws_iam_role.LambdaRolePartitionS3Logs[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sqs:SendMessage"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:sqs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRolePartitionS3Logs
  ]
}


resource "aws_iam_role_policy" "PartitionS3LogsAccess" {
  count  = local.ScannersProbesAthenaLogParser == "yes" ? 1 : 0
  name   = "PartitionS3LogsAccess1"
  role   = aws_iam_role.LambdaRolePartitionS3Logs[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:GetObject",
                "s3:DeleteObject",
                "s3:PutObject"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${local.AppLogBucket}/*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRolePartitionS3Logs
  ]
}

resource "aws_iam_role_policy" "LogsAccesshelperPartitions3" {
  count  = local.ScannersProbesAthenaLogParser == "yes" ? 1 : 0
  name   = "LogsAccess1"
  role   = aws_iam_role.LambdaRolePartitionS3Logs[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*MoveS3LogsForPartition*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRolePartitionS3Logs
  ]
}

#Role 4 - LambdaRoleSetIPRetention

resource "aws_iam_role" "LambdaRoleSetIPRetention" {
  count = var.IPRetentionPeriod == "yes" ? 1 : 0
  name  = "LambdaRoleSetIPRetention1-${random_id.server.hex}"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "ec2retention" {
  count  = var.IPRetentionPeriod == "yes" ? 1 : 0
  name   = "ec2retention"
  role   = aws_iam_role.LambdaRoleSetIPRetention[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ec2:CreateNetworkInterface"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:/*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleSetIPRetention
  ]
}

resource "aws_iam_role_policy" "sqsretention" {
  count  = var.IPRetentionPeriod == "yes" ? 1 : 0
  name   = "sqsretention"
  role   = aws_iam_role.LambdaRoleSetIPRetention[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sqs:SendMessage"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:sqs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleSetIPRetention
  ]
}

resource "aws_iam_role_policy" "LogsAccessSetIPRetention" {
  count  = var.IPRetentionPeriod == "yes" ? 1 : 0
  name   = "LogsAccess1"
  role   = aws_iam_role.LambdaRoleSetIPRetention[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*SetIPRetention*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleSetIPRetention
  ]
}

resource "aws_iam_role_policy" "DDBAccess" {
  count  = var.IPRetentionPeriod == "yes" ? 1 : 0
  name   = "DDBAccess1"
  role   = aws_iam_role.LambdaRoleSetIPRetention[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "dynamodb:PutItem"
            ],
            "Resource": [
               "${aws_dynamodb_table.IPRetentionDDBTable[0].arn}"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleSetIPRetention
  ]
}

#Role 5 - LambdaRoleRemoveExpiredIP

resource "aws_iam_role" "LambdaRoleRemoveExpiredIP" {
  count = var.IPRetentionPeriod == "yes" ? 1 : 0
  name  = "LambdaRoleRemoveExpiredIP1-${random_id.server.hex}"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "ec2expired" {
  count  = var.IPRetentionPeriod == "yes" ? 1 : 0
  name   = "ec2expired"
  role   = aws_iam_role.LambdaRoleRemoveExpiredIP[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ec2:CreateNetworkInterface"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:/*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleRemoveExpiredIP
  ]
}

resource "aws_iam_role_policy" "SNSPublishPolicy" {
  count  = var.IPRetentionPeriod == "yes" ? 1 : 0
  name   = "LogsAccess1"
  role   = aws_iam_role.LambdaRoleRemoveExpiredIP[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "SNS:Publish"
            ],
            "Resource": [
                "${aws_sns_topic.user_updates[0].arn}"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleRemoveExpiredIP
  ]
}

resource "aws_iam_role_policy" "LogsAccessLambdaRoleRemoveExpiredIP" {
  count  = var.IPRetentionPeriod == "yes" ? 1 : 0
  name   = "LogsAccess1"
  role   = aws_iam_role.LambdaRoleRemoveExpiredIP[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*RemoveExpiredIP*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleRemoveExpiredIP
  ]
}

resource "aws_iam_role_policy" "WAFAccessLambdaRoleRemoveExpiredIP" {
  count  = var.IPRetentionPeriod == "yes" ? 1 : 0
  name   = "WAFAccess1"
  role   = aws_iam_role.LambdaRoleRemoveExpiredIP[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "dynamodb:GetShardIterator",
                "dynamodb:DescribeStream",
                "dynamodb:GetRecords",
                "dynamodb:ListStreams"
            ],
            "Resource": [
                "${aws_wafv2_ip_set.WAFWhitelistSetV4.arn}",
                "${aws_wafv2_ip_set.WAFBlacklistSetV6.arn}",
                "${aws_wafv2_ip_set.WAFWhitelistSetV6.arn}",
                "${aws_wafv2_ip_set.WAFBlacklistSetV6.arn}"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleRemoveExpiredIP
  ]
}

resource "aws_iam_role_policy" "sqsexpired" {
  count  = var.IPRetentionPeriod == "yes" ? 1 : 0
  name   = "sqsexpired"
  role   = aws_iam_role.LambdaRoleRemoveExpiredIP[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sqs:SendMessage"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:sqs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleRemoveExpiredIP
  ]
}

resource "aws_iam_role_policy" "DDBStreamAccess" {
  count  = var.IPRetentionPeriod == "yes" ? 1 : 0
  name   = "DDBStreamAccess"
  role   = aws_iam_role.LambdaRoleRemoveExpiredIP[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "wafv2:GetIPSet",
                "wafv2:UpdateIPSet"
            ],
            "Resource": [
               "${aws_dynamodb_table.IPRetentionDDBTable[0].arn}"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleRemoveExpiredIP
  ]
}
resource "aws_iam_role_policy" "InvokeLambda" {
  count  = var.IPRetentionPeriod == "yes" ? 1 : 0
  name   = "InvokeLambda1"
  role   = aws_iam_role.LambdaRoleRemoveExpiredIP[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "lambda:InvokeFunction"
            ],
            "Resource": [
               "${aws_dynamodb_table.IPRetentionDDBTable[0].arn}"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleRemoveExpiredIP
  ]
}

#ROLE6  LambdaRoleReputationListsParser

resource "aws_iam_role" "LambdaRoleReputationListsParser" {
  count = var.ReputationListsProtectionActivated == "yes" ? 1 : 0
  name  = "LambdaRoleReputParser1-${random_id.server.hex}"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "ec2reputation" {
  count  = var.ReputationListsProtectionActivated == "yes" ? 1 : 0
  name   = "ec2reputation"
  role   = aws_iam_role.LambdaRoleReputationListsParser[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ec2:CreateNetworkInterface"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:/*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleReputationListsParser
  ]
}

resource "aws_iam_role_policy" "CloudWatchLogsListsParser" {
  count  = var.ReputationListsProtectionActivated == "yes" ? 1 : 0
  name   = "CloudWatchLogs1"
  role   = aws_iam_role.LambdaRoleReputationListsParser[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*ReputationListsParser*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleReputationListsParser
  ]
}

resource "aws_iam_role_policy" "sqsreputation" {
  count  = var.ReputationListsProtectionActivated == "yes" ? 1 : 0
  name   = "sqsreputation"
  role   = aws_iam_role.LambdaRoleReputationListsParser[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sqs:SendMessage"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:sqs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleReputationListsParser
  ]
}

resource "aws_iam_role_policy" "CloudWatchAccessListsParser" {
  count  = var.ReputationListsProtectionActivated == "yes" ? 1 : 0
  name   = "CloudWatchAccess1"
  role   = aws_iam_role.LambdaRoleReputationListsParser[0].id
  policy = <<EOT
{
    "Statement": [
        {
            "Action": "cloudwatch:GetMetricStatistics",
            "Resource": [
                "*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleReputationListsParser
  ]
}

resource "aws_iam_role_policy" "WAFGetAndUpdateIPListsParser" {
  name   = "WAFGetAndUpdateIPSet1"
  role   = aws_iam_role.LambdaRoleReputationListsParser[0].id
  policy = <<EOT
{
    "Statement": [
        {
            "Action": [
                "wafv2:GetIPSet",
                "wafv2:UpdateIPSet"
            ],
            "Resource": [
                "${aws_wafv2_ip_set.WAFReputationListsSetV4[0].arn}",
                "${aws_wafv2_ip_set.WAFReputationListsSetV6[0].arn}"
                ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleReputationListsParser
  ]
}

#Role 7 - LambdaRoleCustomResource

resource "aws_iam_role" "LambdaRoleCustomResource" {
  name = "LambdaRoleCustomResource1-${random_id.server.hex}"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "ec2customresource" {
  name   = "ec2customresource"
  role   = aws_iam_role.LambdaRoleCustomResource.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ec2:CreateNetworkInterface"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:/*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleCustomResource
  ]
}

resource "aws_iam_role_policy" "sqscustomresource" {
  name   = "sqscustomresource"
  role   = aws_iam_role.LambdaRoleCustomResource.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sqs:SendMessage"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:sqs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleCustomResource
  ]
}

resource "aws_iam_role_policy" "S3AccessGeneralAppAccessLog" {
  name   = "S3AccessGeneralAppAccessLog1"
  role   = aws_iam_role.LambdaRoleCustomResource.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:CreateBucket",
                "s3:GetBucketNotification",
                "s3:PutBucketNotification",
                "s3:PutEncryptionConfiguration",
                "s3:PutBucketPublicAccessBlock"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${local.AppLogBucket}"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleCustomResource
  ]
}

resource "aws_iam_role_policy" "S3AccessGeneralWafLog" {
  count  = local.HttpFloodProtectionLogParserActivated == "yes" ? 1 : 0
  name   = "S3AccessGeneralWafLog1"
  role   = aws_iam_role.LambdaRoleCustomResource.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:CreateBucket",
                "s3:GetBucketNotification",
                "s3:PutBucketNotification"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.WafLogBucket[0].bucket}"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleCustomResource
  ]
}

resource "aws_iam_role_policy" "S3Access" {
  name   = "S3Access1"
  role   = aws_iam_role.LambdaRoleCustomResource.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${local.AppLogBucket}"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleCustomResource
  ]
}

resource "aws_iam_role_policy" "S3AppAccessPut" {
  count  = local.ScannersProbesLambdaLogParser == "yes" ? 1 : 0
  name   = "S3AppAccessPut1"
  role   = aws_iam_role.LambdaRoleCustomResource.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:PutObject"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${local.AppLogBucket}/*app_log_conf.json"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleCustomResource
  ]
}

resource "aws_iam_role_policy" "S3WafAccessPut" {
  count  = local.HttpFloodLambdaLogParser == "yes" ? 1 : 0
  name   = "S3WafAccessPut1"
  role   = aws_iam_role.LambdaRoleCustomResource.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:PutObject"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${local.AppLogBucket}/*waf_log_conf.json"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleCustomResource
  ]
}

resource "aws_iam_role_policy" "CustomResourceLambdaAccess" {
  count  = local.CustomResourceLambdaAccess == "yes" ? 1 : 0
  name   = "LambdaAccess1"
  role   = aws_iam_role.LambdaRoleCustomResource.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "lambda:InvokeFunction"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:*AddAthenaPartitions*",
                "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:*ReputationListsParser*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleCustomResource
  ]
}

resource "aws_iam_role_policy" "WAFAccess" {
  count  = local.HttpFloodProtectionLogParserActivated == "yes" ? 1 : 0
  name   = "WAFAccess1"
  role   = aws_iam_role.LambdaRoleCustomResource.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "wafv2:GetWebACL",
                "wafv2:UpdateWebACL",
                "wafv2:DeleteLoggingConfiguration"
            ],
            "Resource": [
                "${aws_wafv2_web_acl.wafacl.arn}"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleCustomResource
  ]
}

resource "aws_iam_role_policy" "IPSetAccess" {
  name   = "IPSetAccess1"
  role   = aws_iam_role.LambdaRoleCustomResource.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "wafv2:GetIPSet",
                "wafv2:UpdateIPSet"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:wafv2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:regional/ipset/*",
                "arn:${data.aws_partition.current.partition}:wafv2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:global/ipset/*"
                ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleCustomResource
  ]
}

resource "aws_iam_role_policy" "WAFLogsAccess" {
  name   = "WAFLogsAccess1"
  role   = aws_iam_role.LambdaRoleCustomResource.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "wafv2:PutLoggingConfiguration"
            ],
            "Resource": [
                "${aws_wafv2_web_acl.wafacl.arn}"
                ],
            "Effect": "Allow"
        },
        {
            "Effect": "Allow",
            "Action": "iam:CreateServiceLinkedRole",
            "Resource": "arn:${data.aws_partition.current.partition}:iam::*:role/aws-service-role/wafv2.amazonaws.com/AWSServiceRoleForWAFV2Logging",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "iam:AWSServiceName": "wafv2.amazonaws.com"
                }
            }
        }        
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleCustomResource
  ]
}

resource "aws_iam_role_policy" "CustomResourceLogsAccess" {
  name   = "LogsAccess1"
  role   = aws_iam_role.LambdaRoleCustomResource.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*CustomResource*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleCustomResource
  ]
}

resource "aws_iam_role_policy" "CustomResourceS3BucketLoggingAccess" {
  count  = var.ScannersProbesProtectionActivated == "yes" ? 1 : 0
  name   = "S3BucketLoggingAccess1"
  role   = aws_iam_role.LambdaRoleCustomResource.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:GetBucketLogging",
                "s3:PutBucketLogging"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${local.AppLogBucket}"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleCustomResource
  ]
}

#Role 8 - LambdaRoleLogParser

resource "aws_iam_role" "LambdaRoleLogParser" {
  count = local.LogParser == "yes" ? 1 : 0
  name  = "LambdaRoleLogParser1-${random_id.server.hex}"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "ec2logparser" {
  name   = "ec2logparser"
  role   = aws_iam_role.LambdaRoleLogParser[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ec2:CreateNetworkInterface"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:/*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleLogParser
  ]
}

resource "aws_iam_role_policy" "sqslogparser" {
  count  = local.LogParser == "yes" ? 1 : 0
  name   = "sqslogparser"
  role   = aws_iam_role.LambdaRoleLogParser[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sqs:SendMessage"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:sqs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleLogParser
  ]
}
resource "aws_iam_role_policy" "S3LogParser" {
  count  = var.ScannersProbesProtectionActivated == "yes" ? 1 : 0
  name   = "ScannersProbesProtectionActivatedAccess"
  role   = aws_iam_role.LambdaRoleLogParser[0].id
  policy = <<EOT
{
    "Statement": [
        {
            "Action": "s3:GetObject",
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${local.AppLogBucket}/*"
            ],
            "Effect": "Allow"
        },
        {
            "Action": "s3:PutObject",
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${local.AppLogBucket}/*app_log_out.json",
                "arn:${data.aws_partition.current.partition}:s3:::${local.AppLogBucket}/*app_log_conf.json"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
                "wafv2:GetIPSet",
                "wafv2:UpdateIPSet"
            ],
            "Resource": [
                "${aws_wafv2_ip_set.WAFScannersProbesSetV4[0].arn}",
                "${aws_wafv2_ip_set.WAFScannersProbesSetV6[0].arn}"
            ],
            "Effect": "Allow"
        }
    ]
}

EOT
  depends_on = [
    aws_iam_role.LambdaRoleLogParser
  ]
}

resource "aws_iam_role_policy" "ScannersProbesAthenaLogParser" {
  count  = local.ScannersProbesAthenaLogParser == "yes" ? 1 : 0
  name   = "ScannersProbesAthenaLogParserAccess1"
  role   = aws_iam_role.LambdaRoleLogParser[0].id
  policy = <<EOT
{
    "Statement": [
        {
            "Action": [
            "athena:GetNamedQuery",
            "athena:StartQueryExecution"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:athena:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:workgroup/WAF*"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:ListBucket",
            "s3:ListBucketMultipartUploads",
            "s3:ListMultipartUploadParts",
            "s3:AbortMultipartUpload",
            "s3:CreateBucket",
            "s3:PutObject"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${local.AppLogBucket}/athena_results/*",
                "arn:${data.aws_partition.current.partition}:s3:::${local.AppLogBucket}"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
                "glue:GetTable",
                "glue:GetPartitions"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:catalog",
                "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:database/*",
                "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/*"
            ],
            "Effect": "Allow"
        }
    ]
}

EOT
  depends_on = [
    aws_iam_role.LambdaRoleLogParser
  ]
}

resource "aws_iam_role_policy" "HttpFloodProtectionLogParser" {
  count  = local.HttpFloodProtectionLogParserActivated == "yes" ? 1 : 0
  name   = "HttpFloodProtectionLogParserActivatedAccess1"
  role   = aws_iam_role.LambdaRoleLogParser[0].id
  policy = <<EOT
{
    "Statement": [
        {
            "Action": [
            "s3:GetObject"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.WafLogBucket[0].bucket}"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
            "s3:PutObject"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.WafLogBucket[0].bucket}/*log_out.json",
                "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.WafLogBucket[0].bucket}/*log_conf.json"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
                "wafv2:GetIPSet",
                "wafv2:UpdateIPSet"
            ],
            "Resource": [
                "${aws_wafv2_ip_set.WAFHttpFloodSetV4.arn}",
                "${aws_wafv2_ip_set.WAFHttpFloodSetV6.arn}"
            ],
            "Effect": "Allow"
        }
    ]
}

EOT
  depends_on = [
    aws_iam_role.LambdaRoleLogParser
  ]
}

resource "aws_iam_role_policy" "HttpFloodAthenaLogParser" {
  count  = local.HttpFloodAthenaLogParser == "yes" ? 1 : 0
  name   = "HttpFloodAthenaLogParserAccess1"
  role   = aws_iam_role.LambdaRoleLogParser[0].id
  policy = <<EOT
{
    "Statement": [
        {
            "Action": [
            "athena:GetNamedQuery",
            "athena:StartQueryExecution"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:athena:::${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:workgroup/WAF*"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:ListBucket",
            "s3:ListBucketMultipartUploads",
            "s3:ListMultipartUploadParts",
            "s3:AbortMultipartUpload",
            "s3:CreateBucket",
            "s3:PutObject"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.WafLogBucket[0].bucket}/athena_results/*",
                "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.WafLogBucket[0].bucket}"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
                "glue:GetTable",
                "glue:GetPartitions"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:catalog",
                "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:database/*",
                "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/*"
            ],
            "Effect": "Allow"
        }
    ]
}

EOT
  depends_on = [
    aws_iam_role.LambdaRoleLogParser
  ]
}

resource "aws_iam_role_policy" "LambdaRoleLogsAccess1" {
  name   = "LogsAccess1"
  role   = aws_iam_role.LambdaRoleLogParser[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*LogParser*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleLogParser
  ]
}

resource "aws_iam_role_policy" "LambdaRoleCloudWatchAccess" {
  name   = "CloudWatchAccess1"
  role   = aws_iam_role.LambdaRoleLogParser[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "cloudwatch:GetMetricStatistics"
            ],
            "Resource": [
                "*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleLogParser[0]
  ]
}

#Role 9 - LambdaRoleAddAthenaPartitions

resource "aws_iam_role" "LambdaRoleAddAthenaPartitions" {
  count = local.AthenaLogParser == "yes" ? 1 : 0
  name  = "LambdaRoleAddAthenaPartitions1-${random_id.server.hex}"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "AddAthenaPartitionsForAppAccessLog" {
  count  = local.ScannersProbesAthenaLogParser == "yes" ? 1 : 0
  name   = "AddAthenaPartitionsForAppAccessLog1"
  role   = aws_iam_role.LambdaRoleAddAthenaPartitions[0].id
  policy = <<EOT
{
    "Statement": [
        {
            "Action": [
            "athena:StartQueryExecution"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:athena:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:workgroup/WAF*"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:ListBucket",
            "s3:ListBucketMultipartUploads",
            "s3:ListMultipartUploadParts",
            "s3:AbortMultipartUpload",
            "s3:CreateBucket",
            "s3:PutObject"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${local.AppLogBucket}/athena_results/*",
                "arn:${data.aws_partition.current.partition}:s3:::${local.AppLogBucket}",
                "arn:${data.aws_partition.current.partition}:s3:::${local.AppLogBucket}/*"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
                "glue:GetTable",
                "glue:GetDatabase",
                "glue:UpdateDatabase",
                "glue:CreateDatabase",
                "glue:BatchCreatePartition"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:catalog",
                "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:database/default",
                "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:database/*",
                "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/*"
            ],
            "Effect": "Allow"
        }
    ]
}

EOT
  depends_on = [
    aws_iam_role.LambdaRoleAddAthenaPartitions
  ]
}

resource "aws_iam_role_policy" "AddAthenaPartitionsForWAFLog" {
  count  = local.HttpFloodAthenaLogParser == "yes" ? 1 : 0
  name   = "AddAthenaPartitionsForWAFLog1"
  role   = aws_iam_role.LambdaRoleAddAthenaPartitions[0].id
  policy = <<EOT
{
    "Statement": [
        {
            "Action": [
            "athena:StartQueryExecution"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:athena:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:workgroup/WAF*"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:ListBucket",
            "s3:ListBucketMultipartUploads",
            "s3:ListMultipartUploadParts",
            "s3:AbortMultipartUpload",
            "s3:CreateBucket",
            "s3:PutObject"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.WafLogBucket[0].bucket}/athena_results/*",
                "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.WafLogBucket[0].bucket}",
                "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.WafLogBucket[0].bucket}/*"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
                "glue:GetTable",
                "glue:GetDatabase",
                "glue:UpdateDatabase",
                "glue:CreateDatabase",
                "glue:BatchCreatePartition"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:catalog",
                "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:database/default",
                "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:database/*",
                "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/*"
            ],
            "Effect": "Allow"
        }
    ]
}

EOT
  depends_on = [
    aws_iam_role.LambdaRoleAddAthenaPartitions
  ]
}

resource "aws_iam_role_policy" "ec2athena" {
  count  = local.AthenaLogParser == "yes" ? 1 : 0
  name   = "ec2athena"
  role   = aws_iam_role.LambdaRoleAddAthenaPartitions[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ec2:CreateNetworkInterface"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:/*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleAddAthenaPartitions
  ]
}

resource "aws_iam_role_policy" "sqsathena" {
  count  = local.AthenaLogParser == "yes" ? 1 : 0
  name   = "sqsathena"
  role   = aws_iam_role.LambdaRoleAddAthenaPartitions[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sqs:SendMessage"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:sqs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleAddAthenaPartitions
  ]
}

resource "aws_iam_role_policy" "HttpFloodAthenaLogParserLogsAccess" {
  count  = local.AthenaLogParser == "yes" ? 1 : 0
  name   = "LogsAccess1"
  role   = aws_iam_role.LambdaRoleAddAthenaPartitions[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*AddAthenaPartitions*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleAddAthenaPartitions
  ]
}



#Role 10 - CustomTimerrole

resource "aws_iam_role" "LambdaRoleCustomTimer" {
  name = "LambdaRoleCustomTimer-${random_id.server.hex}"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "ec2customtimer" {
  name   = "ec2customtimer"
  role   = aws_iam_role.LambdaRoleCustomTimer.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ec2:CreateNetworkInterface"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:/*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleCustomTimer
  ]
}


resource "aws_iam_role_policy" "sqscustomtimer" {
  name   = "sqscustomtimer"
  role   = aws_iam_role.LambdaRoleCustomTimer.id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sqs:SendMessage"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:sqs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.LambdaRoleCustomTimer
  ]
}

resource "aws_iam_role_policy" "CloudWatchLogstimer" {
  name   = "CloudWatchLogstimerpolicy"
  role   = aws_iam_role.LambdaRoleCustomTimer.id
  policy = <<EOT
{
    "Statement": [
        {
            "Action": [
            "logs:CreateLogGroup",
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:athena:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*CustomTimer*"
            ],
            "Effect": "Allow"
        }
    ]
}

EOT
  depends_on = [
    aws_iam_role.LambdaRoleCustomTimer
  ]
}

# ----------------------------------------------------------------------------------------------------------------------
# CREATE A LAMBDA FUNCTIONS
# ----------------------------------------------------------------------------------------------------------------------


resource "aws_lambda_function" "helper" {
  function_name = "Helper-Lambda-${random_id.server.hex}"
  description                    = "This lambda function verifies the main project's dependencies, requirements and implement auxiliary functions"
  role                           = aws_iam_role.LambdaRoleHelper.arn
  handler                        = "helper.lambda_handler"
  s3_bucket                      = "${var.SourceBucket}-${data.aws_region.current.name}"
  s3_key                         = "${var.KeyPrefix}/helper.zip"
  runtime                        = "python3.8"
  timeout                        = 300
  memory_size                    = 128
  kms_key_arn                    = aws_kms_key.wafkey.arn
  reserved_concurrent_executions = 1
  tracing_config {
    mode = "Active"
  }
  environment {
    variables = {
      LOG_LEVEL        = var.LOG_LEVEL
      SCOPE            = local.SCOPE
      USER_AGENT_EXTRA = var.USER_AGENT_EXTRA
    }
  }
}

resource "aws_lambda_function" "BadBotParser" {
  count = var.BadBotProtectionActivated == "yes" ? 1 : 0
  function_name                  = "BadBotParser-Lambda-${random_id.server.hex}"
  description                    = "This lambda function verifies the main project's dependencies, requirements and implement auxiliary functions"
  role                           = aws_iam_role.LambdaRoleBadBot[0].arn
  handler                        = "BadBotParser.lambda_handler"
  s3_bucket                      = "${var.SourceBucket}-${data.aws_region.current.name}"
  s3_key                         = "${var.KeyPrefix}/access_handler.zip"
  runtime                        = "python3.8"
  timeout                        = 300
  memory_size                    = 128
  kms_key_arn                    = aws_kms_key.wafkey.arn
  reserved_concurrent_executions = 1
  tracing_config {
    mode = "Active"
  }
  environment {
    variables = {
      LOG_LEVEL                 = var.LOG_LEVEL
      SCOPE                     = local.SCOPE
      USER_AGENT_EXTRA          = var.USER_AGENT_EXTRA
      IP_SET_ID_BAD_BOTV4       = aws_wafv2_ip_set.WAFBadBotSetV4[0].arn
      IP_SET_ID_BAD_BOTV6       = aws_wafv2_ip_set.WAFBadBotSetV4[0].arn
      IP_SET_NAME_BAD_BOTV4     = aws_wafv2_ip_set.WAFBadBotSetV4[0].name
      IP_SET_NAME_BAD_BOTV6     = aws_wafv2_ip_set.WAFBadBotSetV4[0].name
      SEND_ANONYMOUS_USAGE_DATA = var.SEND_ANONYMOUS_USAGE_DATA
      REGION                    = data.aws_region.current.name
      LOG_TYPE                  = local.LOG_TYPE
      SOLUTION_ID               = var.SolutionID
      METRICS_URL               = var.MetricsURL
      STACK_NAME                = "custom-resources-stack-${random_id.server.hex}"
      METRIC_NAME_PREFIX        = "customresourcesstack"
      UUID                      = aws_cloudformation_stack.trigger_codebuild_stack.outputs.UUID
    }
  }
}

resource "aws_lambda_function" "MoveS3LogsForPartition" {
  count = local.ScannersProbesAthenaLogParser == "yes" ? 1 : 0
  function_name                  = "MoveS3LogsForPartition-Lambda-${random_id.server.hex}"
  description                    = "This function is triggered by S3 event to move log files(upon their arrival in s3) from their original location to a partitioned folder structure created per timestamps in file names, hence allowing the usage of partitioning within AWS Athena."
  role                           = aws_iam_role.LambdaRolePartitionS3Logs[0].arn
  handler                        = "partition_s3_logs.lambda_handler"
  s3_bucket                      = "${var.SourceBucket}-${data.aws_region.current.name}"
  s3_key                         = "${var.KeyPrefix}/log_parser.zip"
  runtime                        = "python3.8"
  timeout                        = 300
  memory_size                    = 512
  kms_key_arn                    = aws_kms_key.wafkey.arn
  reserved_concurrent_executions = 1
  tracing_config {
    mode = "Active"
  }
  environment {
    variables = {
      LOG_LEVEL          = var.LOG_LEVEL
      ENDPOINT           = var.ENDPOINT
      USER_AGENT_EXTRA   = var.USER_AGENT_EXTRA
      KEEP_ORIGINAL_DATA = var.KEEP_ORIGINAL_DATA
    }
  }
}

resource "aws_lambda_function" "SetIPRetention" {
  count         = var.IPRetentionPeriod == "yes" ? 1 : 0
  function_name = "SetIPRetention-Lambda-${random_id.server.hex}"
  description                    = "This lambda function processes CW events for WAF UpdateIPSet API calls. It writes relevant ip retention data into a DynamoDB table."
  role                           = aws_iam_role.LambdaRoleSetIPRetention[0].arn
  handler                        = "set_ip_retention.lambda_handler"
  s3_bucket                      = "${var.SourceBucket}-${data.aws_region.current.name}"
  s3_key                         = "${var.KeyPrefix}/ip_retention_handler.zip"
  runtime                        = "python3.8"
  timeout                        = 300
  memory_size                    = 128
  kms_key_arn                    = aws_kms_key.wafkey.arn
  reserved_concurrent_executions = 1
  tracing_config {
    mode = "Active"
  }
  environment {
    variables = {
      LOG_LEVEL                          = var.LOG_LEVEL
      USER_AGENT_EXTRA                   = var.USER_AGENT_EXTRA
      TABLE_NAME                         = aws_dynamodb_table.IPRetentionDDBTable[0].name
      IP_RETENTION_PEROID_ALLOWED_MINUTE = var.IPRetentionPeriodAllowedParam
      IP_RETENTION_PEROID_DENIED_MINUTE  = var.IPRetentionPeriodDeniedParam
      REMOVE_EXPIRED_IP_LAMBDA_ROLE_NAME = aws_iam_role.LambdaRoleRemoveExpiredIP[0].name
      STACK_NAME                         = "custom-resources-stack-${random_id.server.hex}"
      METRIC_NAME_PREFIX                 = "customresourcesstack"
    }
  }
}

resource "aws_lambda_function" "ReputationListsParser" {
  count = var.ReputationListsProtectionActivated == "yes" ? 1 : 0
  function_name                  = "ReputationListsParser-Lambda-${random_id.server.hex}"
  description                    = "This lambda function checks third-party IP reputation lists hourly for new IP ranges to block. These lists include the Spamhaus Dont Route Or Peer (DROP) and Extended Drop (EDROP) lists, the Proofpoint Emerging Threats IP list, and the Tor exit node list."
  role                           = aws_iam_role.LambdaRoleReputationListsParser[0].arn
  handler                        = "reputation-lists.lambda_handler"
  s3_bucket                      = "${var.SourceBucket}-${data.aws_region.current.name}"
  s3_key                         = "${var.KeyPrefix}/reputation_lists_parser.zip"
  runtime                        = "python3.8"
  timeout                        = 300
  memory_size                    = 512
  kms_key_arn                    = aws_kms_key.wafkey.arn
  reserved_concurrent_executions = 1
  tracing_config {
    mode = "Active"
  }
  environment {
    variables = {
      LOG_LEVEL                   = var.LOG_LEVEL
      USER_AGENT_EXTRA            = var.USER_AGENT_EXTRA
      IP_SET_ID_REPUTATIONV4      = aws_wafv2_ip_set.WAFReputationListsSetV4[0].arn
      IP_SET_ID_REPUTATIONV6      = aws_wafv2_ip_set.WAFReputationListsSetV6[0].arn
      IP_SET_NAME_REPUTATIONV4    = aws_wafv2_ip_set.WAFReputationListsSetV4[0].name
      IP_SET_NAME_REPUTATIONV6    = aws_wafv2_ip_set.WAFReputationListsSetV6[0].name
      SCOPE                       = local.SCOPE
      LOG_TYPE                    = local.LOG_TYPE
      SOLUTION_ID                 = var.SolutionID
      METRICS_URL                 = var.MetricsURL
      SEND_ANONYMOUS_USAGE_DATA   = var.SEND_ANONYMOUS_USAGE_DATA
      IPREPUTATIONLIST_METRICNAME = "MetricForIPReputationListsRule"
      STACK_NAME                  = "custom-resources-stack-${random_id.server.hex}"
      METRIC_NAME_PREFIX          = "customresourcesstack"
      URL_LIST                    = <<EOF
      [
                  {"url":"https://www.spamhaus.org/drop/drop.txt"},
                  {"url":"https://www.spamhaus.org/drop/edrop.txt"},
                  {"url":"https://check.torproject.org/exit-addresses", "prefix":"ExitAddress"},
                  {"url":"https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"}
                ]
                EOF
    }
  }
}


resource "aws_lambda_function" "CustomResource" {
  function_name = "CustomResource-Lambda-${random_id.server.hex}"
  description                    = "Log permissions are defined in the LambdaRoleCustomResource policies"
  role                           = aws_iam_role.LambdaRoleCustomResource.arn
  handler                        = "custom-resource.lambda_handler"
  s3_bucket                      = "${var.SourceBucket}-${data.aws_region.current.name}"
  s3_key                         = "${var.KeyPrefix}/custom_resource.zip"
  runtime                        = "python3.8"
  timeout                        = 300
  memory_size                    = 128
  kms_key_arn                    = aws_kms_key.wafkey.arn
  reserved_concurrent_executions = 1
  tracing_config {
    mode = "Active"
  }
  environment {
    variables = {
      LOG_LEVEL        = var.LOG_LEVEL
      USER_AGENT_EXTRA = var.USER_AGENT_EXTRA
      SCOPE            = local.SCOPE
      SOLUTION_ID      = var.SolutionID
      METRICS_URL      = var.MetricsURL
    }
  }
}

resource "aws_lambda_function" "LogParser" {
  count         = local.LogParser == "yes" ? 1 : 0
  function_name = "LogParser-Lambda-${random_id.server.hex}"
  description                    = "This function parses access logs to identify suspicious behavior, such as an abnormal amount of errors.It then blocks those IP addresses for a customer-defined period of time."
  role                           = aws_iam_role.LambdaRoleLogParser[0].arn
  handler                        = "log-parser.lambda_handler"
  s3_bucket                      = "${var.SourceBucket}-${data.aws_region.current.name}"
  s3_key                         = "${var.KeyPrefix}/log_parser.zip"
  runtime                        = "python3.8"
  timeout                        = 300
  memory_size                    = 512
  kms_key_arn                    = aws_kms_key.wafkey.arn
  reserved_concurrent_executions = 1
  tracing_config {
    mode = "Active"
  }
  environment {
    variables = {
      APP_ACCESS_LOG_BUCKET                          = local.AppLogBucket
      WAF_ACCESS_LOG_BUCKET                          = local.WafLogBucket
      LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION = 10000
      MAX_AGE_TO_UPDATE                              = 30
      LOG_LEVEL                                      = var.LOG_LEVEL
      SCOPE                                          = local.SCOPE
      USER_AGENT_EXTRA                               = var.USER_AGENT_EXTRA
      SEND_ANONYMOUS_USAGE_DATA                      = var.SEND_ANONYMOUS_USAGE_DATA
      REGION                                         = data.aws_region.current.name
      LOG_TYPE                                       = local.LOG_TYPE
      SOLUTION_ID                                    = var.SolutionID
      METRICS_URL                                    = var.MetricsURL
      IP_SET_ID_HTTP_FLOODV4                         = local.WAFHttpFloodSetIPV4arn
      IP_SET_ID_HTTP_FLOODV6                         = local.WAFHttpFloodSetIPV6arn
      IP_SET_NAME_HTTP_FLOODV4                       = local.WAFHttpFloodSetIPV4Name
      IP_SET_NAME_HTTP_FLOODV6                       = local.WAFHttpFloodSetIPV6Name
      IP_SET_ID_SCANNERS_PROBESV4                    = aws_wafv2_ip_set.WAFScannersProbesSetV4[0].arn
      IP_SET_ID_SCANNERS_PROBESV6                    = aws_wafv2_ip_set.WAFScannersProbesSetV6[0].arn
      IP_SET_NAME_SCANNERS_PROBESV4                  = aws_wafv2_ip_set.WAFScannersProbesSetV4[0].name
      IP_SET_NAME_SCANNERS_PROBESV6                  = aws_wafv2_ip_set.WAFScannersProbesSetV6[0].name
      WAF_BLOCK_PERIOD                               = var.WAFBlockPeriod
      ERROR_THRESHOLD                                = var.ErrorThreshold
      REQUEST_THRESHOLD                              = var.RequestThreshold
      STACK_NAME                                     = "custom-resources-stack-${random_id.server.hex}"
      METRIC_NAME_PREFIX                             = "customresourcesstack"
    }
  }
}

resource "aws_lambda_function" "AddAthenaPartitions" {
  count = local.AthenaLogParser == "yes" ? 1 : 0
  function_name                  = "AthenaLogParser-Lambda-${random_id.server.hex}"
  description                    = "This function adds a new hourly partition to athena table. It runs every hour, triggered by a CloudWatch event."
  role                           = aws_iam_role.LambdaRoleAddAthenaPartitions[0].arn
  handler                        = "add_athena_partitions.lambda_handler"
  s3_bucket                      = "${var.SourceBucket}-${data.aws_region.current.name}"
  s3_key                         = "${var.KeyPrefix}/log_parser.zip"
  runtime                        = "python3.8"
  timeout                        = 300
  memory_size                    = 512
  kms_key_arn                    = aws_kms_key.wafkey.arn
  reserved_concurrent_executions = 1
  tracing_config {
    mode = "Active"
  }
  environment {
    variables = {
      LOG_LEVEL        = var.LOG_LEVEL
      USER_AGENT_EXTRA = var.USER_AGENT_EXTRA
    }
  }
}

resource "aws_lambda_function" "RemoveExpiredIP" {
  count = var.IPRetentionPeriod == "yes" ? 1 : 0
  function_name                  = "RemoveExpiredIP-Lambda-${random_id.server.hex}"
  description                    = "This function adds a new hourly partition to athena table. It runs every hour, triggered by a CloudWatch event."
  role                           = aws_iam_role.LambdaRoleRemoveExpiredIP[0].arn
  handler                        = "add_athena_partitions.lambda_handler"
  s3_bucket                      = "${var.SourceBucket}-${data.aws_region.current.name}"
  s3_key                         = "${var.KeyPrefix}/ip_retention_handler.zip"
  runtime                        = "python3.8"
  timeout                        = 300
  memory_size                    = 512
  kms_key_arn                    = aws_kms_key.wafkey.arn
  reserved_concurrent_executions = 1
  tracing_config {
    mode = "Active"
  }
  environment {
    variables = {
      LOG_LEVEL                 = var.LOG_LEVEL
      USER_AGENT_EXTRA          = var.USER_AGENT_EXTRA
      METRICS_URL               = var.MetricsURL
      SOLUTION_ID               = var.SolutionID
      SEND_ANONYMOUS_USAGE_DATA = var.SEND_ANONYMOUS_USAGE_DATA
      SNS_EMAIL                 = local.SNSEmail
      SNS_TOPIC_ARN             = aws_sns_topic.user_updates[0].arn
    }
  }
}

resource "aws_lambda_function" "CustomTimer" {
  function_name = "CustomTimer-Lambda-${random_id.server.hex}"
  description                    = "This lambda function counts X seconds and can be used to slow down component creation in CloudFormation"
  role                           = aws_iam_role.LambdaRoleCustomTimer.arn
  handler                        = "timer.lambda_handler"
  s3_bucket                      = "${var.SourceBucket}-${data.aws_region.current.name}"
  s3_key                         = "${var.KeyPrefix}/timer.zip"
  runtime                        = "python3.8"
  timeout                        = 300
  memory_size                    = 128
  kms_key_arn                    = aws_kms_key.wafkey.arn
  reserved_concurrent_executions = 1
  tracing_config {
    mode = "Active"
  }
  environment {
    variables = {
      LOG_LEVEL = var.LOG_LEVEL
      SECONDS   = "2"
    }
  }
}

locals {
  MoveS3LogsForPartitionarn     = length(aws_lambda_function.MoveS3LogsForPartition) != 0 ? "${aws_lambda_function.MoveS3LogsForPartition[0].arn}" : "0"
  WAFHttpFloodSetIPV4           = length(aws_wafv2_ip_set.WAFHttpFloodSetV4) != 0 ? "${aws_wafv2_ip_set.WAFHttpFloodSetV4.id}" : "0"
  WAFScannersProbesSetIPV4      = length(aws_wafv2_ip_set.WAFScannersProbesSetV4) != 0 ? "${aws_wafv2_ip_set.WAFScannersProbesSetV4[0].id}" : "0"
  WAFReputationListsSetIPV4     = length(aws_wafv2_ip_set.WAFReputationListsSetV4) != 0 ? "${aws_wafv2_ip_set.WAFReputationListsSetV4[0].id}" : "0"
  WAFBadBotSetIPV4              = length(aws_wafv2_ip_set.WAFBadBotSetV4) != 0 ? "${aws_wafv2_ip_set.WAFBadBotSetV4[0].id}" : "0"
  WAFHttpFloodSetIPV6           = length(aws_wafv2_ip_set.WAFHttpFloodSetV6) != 0 ? "${aws_wafv2_ip_set.WAFHttpFloodSetV6.id}" : "0"
  WAFScannersProbesSetIPV6      = length(aws_wafv2_ip_set.WAFScannersProbesSetV6) != 0 ? "${aws_wafv2_ip_set.WAFScannersProbesSetV6[0].id}" : "0"
  WAFReputationListsSetIPV6     = length(aws_wafv2_ip_set.WAFReputationListsSetV6) != 0 ? "${aws_wafv2_ip_set.WAFReputationListsSetV6[0].id}" : "0"
  WAFBadBotSetIPV6              = length(aws_wafv2_ip_set.WAFBadBotSetV6) != 0 ? "${aws_wafv2_ip_set.WAFBadBotSetV6[0].id}" : "0"
  WAFHttpFloodSetIPV4Name       = length(aws_wafv2_ip_set.WAFHttpFloodSetV4) != 0 ? "${aws_wafv2_ip_set.WAFHttpFloodSetV4.name}" : "0"
  WAFScannersProbesSetIPV4Name  = length(aws_wafv2_ip_set.WAFScannersProbesSetV4) != 0 ? "${aws_wafv2_ip_set.WAFScannersProbesSetV4[0].name}" : "0"
  WAFReputationListsSetIPV4Name = length(aws_wafv2_ip_set.WAFReputationListsSetV4) != 0 ? "${aws_wafv2_ip_set.WAFReputationListsSetV4[0].name}" : "0"
  WAFBadBotSetIPV4Name          = length(aws_wafv2_ip_set.WAFBadBotSetV4) != 0 ? "${aws_wafv2_ip_set.WAFBadBotSetV4[0].name}" : "0"
  WAFHttpFloodSetIPV6Name       = length(aws_wafv2_ip_set.WAFHttpFloodSetV6) != 0 ? "${aws_wafv2_ip_set.WAFHttpFloodSetV6.name}" : "0"
  WAFScannersProbesSetIPV6Name  = length(aws_wafv2_ip_set.WAFScannersProbesSetV6) != 0 ? "${aws_wafv2_ip_set.WAFScannersProbesSetV6[0].name}" : "0"
  WAFReputationListsSetIPV6Name = length(aws_wafv2_ip_set.WAFReputationListsSetV6) != 0 ? "${aws_wafv2_ip_set.WAFReputationListsSetV6[0].name}" : "0"
  WAFBadBotSetIPV6Name          = length(aws_wafv2_ip_set.WAFBadBotSetV6) != 0 ? "${aws_wafv2_ip_set.WAFBadBotSetV6[0].name}" : "0"
  AddAthenaPartitionsLambdaarn  = length(aws_lambda_function.AddAthenaPartitions) != 0 ? "${aws_lambda_function.AddAthenaPartitions[0].arn}" : "0"
  LogParserarn                  = length(aws_lambda_function.LogParser) != 0 ? "${aws_lambda_function.LogParser[0].arn}" : "0"
  GlueAccessLogsDatabase        = length(aws_glue_catalog_database.mydatabase) != 0 ? "${aws_glue_catalog_database.mydatabase[0].name}" : "0"
  GlueWafAccessLogsTable        = length(aws_glue_catalog_table.waf_access_logs_table) != 0 ? "${aws_glue_catalog_table.waf_access_logs_table[0].name}" : "0"
  AthenaWorkGroup               = length(aws_athena_workgroup.WAFAddPartitionAthenaQueryWorkGroup) != 0 ? "${aws_athena_workgroup.WAFAddPartitionAthenaQueryWorkGroup[0].name}" : "0"
  AppAccessLogsTable            = (local.CloudFrontScannersProbesAthenaLogParser == "yes" ? "${aws_glue_catalog_table.cloudfrontGlueAppAccessLogsTable[0].name}" : (local.ALBScannersProbesAthenaLogParser == "yes" ? "${aws_glue_catalog_table.ALBGlueAppAccessLogsTable[0].name}" : "0"))
  WAFHttpFloodSetIPV4arn        = length(aws_wafv2_ip_set.WAFHttpFloodSetV4) != 0 ? "${aws_wafv2_ip_set.WAFHttpFloodSetV4.arn}" : "0"
  WAFHttpFloodSetIPV6arn        = length(aws_wafv2_ip_set.WAFHttpFloodSetV6) != 0 ? "${aws_wafv2_ip_set.WAFHttpFloodSetV6.arn}" : "0"
  DeliveryStreamArn             = length(aws_kinesis_firehose_delivery_stream.extended_s3_stream) != 0 ? "${aws_kinesis_firehose_delivery_stream.extended_s3_stream[0].arn}" : "0"
  WafLogBucket                  = length(aws_s3_bucket.WafLogBucket) != 0 ? "${aws_s3_bucket.WafLogBucket[0].bucket}" : "0"
}

# ----------------------------------------------------------------------------------------------------------------------
# Custom Resources
# ----------------------------------------------------------------------------------------------------------------------

resource "aws_cloudformation_stack" "trigger_codebuild_stack" {
  name = "custom-resources-stack-${random_id.server.hex}"
  parameters = {
    AthenaLogParser                           = local.AthenaLogParser
    Helperarn                                 = aws_lambda_function.helper.arn
    HttpFloodProtectionRateBasedRuleActivated = local.HttpFloodProtectionRateBasedRuleActivated
    HttpFloodProtectionLogParserActivated     = local.HttpFloodProtectionLogParserActivated
    ProtectionActivatedScannersProbes         = var.ScannersProbesProtectionActivated
    AppAccessLogBucket                        = local.AppLogBucket
    Region                                    = data.aws_region.current.name
    EndpointType                              = var.ENDPOINT
    RequestThreshold                          = var.RequestThreshold
    ReputationListsParserarn                  = aws_lambda_function.ReputationListsParser[0].arn
    ReputationListsProtectionActivated        = var.ReputationListsProtectionActivated
    CustomResourcearn                         = aws_lambda_function.CustomResource.arn
    WAFWebACLArn                              = aws_wafv2_web_acl.wafacl.arn
    DeliveryStreamArn                         = local.DeliveryStreamArn
    LogParser                                 = local.LogParserarn
    ScannersProbesAthenaLogParser             = local.ScannersProbesAthenaLogParser
    ScannersProbesLambdaLogParser             = local.ScannersProbesLambdaLogParser
    AccessLoggingBucket                       = aws_s3_bucket.accesslogbucket[0].bucket
    MoveS3LogsForPartitionarn                 = local.MoveS3LogsForPartitionarn
    ScannersProbesProtectionActivated         = var.ScannersProbesProtectionActivated
    BadBotProtectionActivated                 = var.BadBotProtectionActivated
    HttpFloodAthenaLogParser                  = local.HttpFloodAthenaLogParser
    HttpFloodLambdaLogParser                  = local.HttpFloodLambdaLogParser
    ScannersProbesLambdaLogParser             = local.ScannersProbesLambdaLogParser
    WafLogBucket                              = local.WafLogBucket
    WAFBlockPeriod                            = var.WAFBlockPeriod
    ActivateSqlInjectionProtectionParam       = var.ActivateSqlInjectionProtectionParam
    ActivateCrossSiteScriptingProtectionParam = var.ActivateCrossSiteScriptingProtectionParam
    ActivateHttpFloodProtectionParam          = var.ActivateHttpFloodProtectionParam
    ActivateScannersProbesProtectionParam     = var.ActivateScannersProbesProtectionParam
    ActivateReputationListsProtectionParam    = var.ActivateReputationListsProtectionParam
    ActivateBadBotProtectionParam             = var.ActivateBadBotProtectionParam
    ActivateAWSManagedRulesParam              = var.ActivateAWSManagedRulesParam
    KeepDataInOriginalS3Location              = var.KEEP_ORIGINAL_DATA
    IPRetentionPeriodAllowedParam             = var.IPRetentionPeriodAllowedParam
    IPRetentionPeriodDeniedParam              = var.IPRetentionPeriodDeniedParam
    SendAnonymousUsageData                    = var.SendAnonymousUsageData
    SNSEmailParam                             = var.SNSEmailParam
    version                                   = "v3.2.0"
    ErrorThreshold                            = var.ErrorThreshold
    WAFWhitelistSetIPV4                       = aws_wafv2_ip_set.WAFWhitelistSetV4.id
    WAFBlacklistSetIPV4                       = aws_wafv2_ip_set.WAFBlacklistSetV4.id
    WAFHttpFloodSetIPV4                       = local.WAFHttpFloodSetIPV4
    WAFScannersProbesSetIPV4                  = local.WAFScannersProbesSetIPV4
    WAFReputationListsSetIPV4                 = local.WAFReputationListsSetIPV4
    WAFBadBotSetIPV4                          = local.WAFBadBotSetIPV4
    WAFWhitelistSetIPV6                       = aws_wafv2_ip_set.WAFWhitelistSetV6.id
    WAFBlacklistSetIPV6                       = aws_wafv2_ip_set.WAFBlacklistSetV6.id
    WAFHttpFloodSetIPV6                       = local.WAFHttpFloodSetIPV6
    WAFScannersProbesSetIPV6                  = local.WAFScannersProbesSetIPV6
    WAFReputationListsSetIPV6                 = local.WAFReputationListsSetIPV6
    WAFBadBotSetIPV6                          = local.WAFBadBotSetIPV6
    WAFWhitelistSetIPV4Name                   = aws_wafv2_ip_set.WAFWhitelistSetV4.name
    WAFBlacklistSetIPV4Name                   = aws_wafv2_ip_set.WAFBlacklistSetV4.name
    WAFHttpFloodSetIPV4Name                   = local.WAFHttpFloodSetIPV4Name
    WAFScannersProbesSetIPV4Name              = local.WAFScannersProbesSetIPV4Name
    WAFReputationListsSetIPV4Name             = local.WAFReputationListsSetIPV4Name
    WAFBadBotSetIPV4Name                      = local.WAFBadBotSetIPV4Name
    WAFWhitelistSetIPV6Name                   = aws_wafv2_ip_set.WAFWhitelistSetV6.name
    WAFBlacklistSetIPV6Name                   = aws_wafv2_ip_set.WAFBlacklistSetV6.name
    WAFHttpFloodSetIPV6Name                   = local.WAFHttpFloodSetIPV6Name
    WAFScannersProbesSetIPV6Name              = local.WAFScannersProbesSetIPV6Name
    WAFReputationListsSetIPV6Name             = local.WAFReputationListsSetIPV6Name
    WAFBadBotSetIPV6Name                      = local.WAFBadBotSetIPV6Name
    wafwebacl                                 = aws_wafv2_web_acl.wafacl.name
    AddAthenaPartitionsLambdaarn              = local.AddAthenaPartitionsLambdaarn
    ResourceType                              = "CustomResource"
    GlueAccessLogsDatabase                    = local.GlueAccessLogsDatabase
    GlueAppAccessLogsTable                    = local.AppAccessLogsTable
    GlueWafAccessLogsTable                    = local.GlueWafAccessLogsTable
    AthenaWorkGroup                           = local.AthenaWorkGroup
  }

  template_body = <<STACK
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters" : {
    "Helperarn" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "ErrorThreshold" : {
      "Type" : "Number",
      "Description" : "IP Set names"
    },
    "version" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "SNSEmailParam" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "AthenaWorkGroup" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFWhitelistSetIPV4" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFBlacklistSetIPV4" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFHttpFloodSetIPV4" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFScannersProbesSetIPV4" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFReputationListsSetIPV4" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFBadBotSetIPV4" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFWhitelistSetIPV6" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFBlacklistSetIPV6" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFHttpFloodSetIPV6" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFScannersProbesSetIPV6" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFReputationListsSetIPV6" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "AddAthenaPartitionsLambdaarn" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "ResourceType" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "GlueAccessLogsDatabase" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "GlueAppAccessLogsTable" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "GlueWafAccessLogsTable" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFBadBotSetIPV6" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFWhitelistSetIPV4Name" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFBlacklistSetIPV4Name" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFHttpFloodSetIPV4Name" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFScannersProbesSetIPV4Name" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFReputationListsSetIPV4Name" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFBadBotSetIPV4Name" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFWhitelistSetIPV6Name" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFBlacklistSetIPV6Name" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFHttpFloodSetIPV6Name" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFScannersProbesSetIPV6Name" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFReputationListsSetIPV6Name" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFScannersProbesSetIPV6Name" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "AthenaLogParser" : {
      "Type" : "String",
      "Description" : "Code Build Project Name"
    },
    "WAFBlockPeriod" : {
      "Type" : "Number",
      "Description" : "Code Build Project Name"
    },
    "HttpFloodProtectionRateBasedRuleActivated" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "HttpFloodAthenaLogParser" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "WafLogBucket" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "HttpFloodLambdaLogParser" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "ScannersProbesLambdaLogParser" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "HttpFloodProtectionLogParserActivated" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "ScannersProbesProtectionActivated" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "BadBotProtectionActivated" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "ProtectionActivatedScannersProbes" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "AppAccessLogBucket" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "Region" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "EndpointType" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "RequestThreshold" : {
      "Type" : "Number",
      "Description" : "Lambda Function ARN"
    },
    "ReputationListsParserarn" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "ReputationListsProtectionActivated" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "ScannersProbesLambdaLogParser" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "LogParser" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "IPRetentionPeriodAllowedParam" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "IPRetentionPeriodDeniedParam" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "KeepDataInOriginalS3Location" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "ActivateHttpFloodProtectionParam" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "ActivateAWSManagedRulesParam" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "wafwebacl" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "ActivateSqlInjectionProtectionParam" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "WAFBadBotSetIPV6Name" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "SendAnonymousUsageData" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "ActivateReputationListsProtectionParam" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "ActivateBadBotProtectionParam" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "ActivateCrossSiteScriptingProtectionParam" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "ActivateScannersProbesProtectionParam" : {
      "Type" : "String",
      "Description" : "IP Set names"
    },
    "AccessLoggingBucket" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "ScannersProbesAthenaLogParser" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "MoveS3LogsForPartitionarn" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "WAFWebACLArn" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "DeliveryStreamArn" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    },
    "CustomResourcearn" : {
      "Type" : "String",
      "Description" : "Lambda Function ARN"
    }
  },
  "Conditions": {
        "HttpFloodProtectionLogParserActivated": {
            "Fn::Equals": [
                {
                    "Ref": "HttpFloodProtectionLogParserActivated"
                },
                "yes"
            ]
        },
          "HttpFloodLambdaLogParser": {
            "Fn::Equals": [
                {
                    "Ref": "HttpFloodLambdaLogParser"
                },
                "yes"
            ]
        },
          "ReputationListsProtectionActivated": {
            "Fn::Equals": [
                {
                    "Ref": "ReputationListsProtectionActivated"
                },
                "yes"
            ]
        },
          "ScannersProbesAthenaLogParser": {
            "Fn::Equals": [
                {
                    "Ref": "ScannersProbesAthenaLogParser"
                },
                "yes"
            ]
        },
          "ScannersProbesLambdaLogParser": {
            "Fn::Equals": [
                {
                    "Ref": "ScannersProbesLambdaLogParser"
                },
                "yes"
            ]
        },
          "ScannersProbesProtectionActivated": {
            "Fn::Equals": [
                {
                    "Ref": "ScannersProbesProtectionActivated"
                },
                "yes"
            ]
        },
          "BadBotProtectionActivated": {
            "Fn::Equals": [
                {
                    "Ref": "BadBotProtectionActivated"
                },
                "yes"
            ]
        },
          "AthenaLogParser": {
            "Fn::Equals": [
                {
                    "Ref": "AthenaLogParser"
                },
                "yes"
            ]
        }
    },
  "Resources" : {
    "CheckRequirements": {
      "Type" : "Custom::CheckRequirements",
      "Properties" : {
        "AthenaLogParser" : { "Ref" : "AthenaLogParser" },
        "ServiceToken" : { "Ref" : "Helperarn" },
        "HttpFloodProtectionRateBasedRuleActivated" : { "Ref" : "HttpFloodProtectionRateBasedRuleActivated" },
        "HttpFloodProtectionLogParserActivated" : { "Ref" : "HttpFloodProtectionLogParserActivated" },
        "ProtectionActivatedScannersProbes" : { "Ref" : "ProtectionActivatedScannersProbes" },
        "AppAccessLogBucket" : { "Ref" : "AppAccessLogBucket" },
        "Region" : { "Ref" : "Region" },
        "EndpointType" : { "Ref" : "EndpointType" },
        "RequestThreshold" : { "Ref" : "RequestThreshold" }
      }
    },
      "CreateUniqueID": {
        "Type" : "Custom::CreateUUID",
        "DependsOn" : "CheckRequirements",
        "Properties" : {
          "ServiceToken" : { "Ref" : "Helperarn" }
      }
    },
      "CreateDeliveryStreamName": {
        "Type" : "Custom::CreateDeliveryStreamName",
        "Condition" : "HttpFloodProtectionLogParserActivated",
        "DependsOn" : "CheckRequirements",
        "Properties" : {
          "ServiceToken" : { "Ref" : "Helperarn" },
          "StackName" : { "Ref" : "AWS::StackName" }
      }
    },
      "CreateGlueDatabaseName": {
        "Type" : "Custom::CreateGlueDatabaseName",
        "Condition" : "AthenaLogParser",
        "DependsOn" : "CheckRequirements",
        "Properties" : {
          "ServiceToken" : { "Ref" : "Helperarn" },
          "StackName" : { "Ref" : "AWS::StackName" }
      }
    },
      "UpdateReputationListsOnLoad": {
        "Type" : "Custom::UpdateReputationLists",
        "Condition" : "ReputationListsProtectionActivated",
        "Properties" : {
          "ServiceToken" : { "Ref" : "ReputationListsParserarn" }
      }
    },
      "ConfigureAWSWAFLogs": {
        "Type" : "Custom::ConfigureAWSWAFLogs",
        "Condition" : "HttpFloodProtectionLogParserActivated",
        "Properties" : {
          "ServiceToken" : { "Ref" : "CustomResourcearn" },
          "WAFWebACLArn" : { "Ref" : "WAFWebACLArn" },
          "DeliveryStreamArn" : { "Ref" : "DeliveryStreamArn" }
      }
    },
      "ConfigureAppAccessLogBucket": {
        "Type" : "Custom::ConfigureAppAccessLogBucket",
        "Condition" : "ScannersProbesProtectionActivated",
        "Properties" : {
          "ServiceToken" : { "Ref" : "CustomResourcearn" },
          "Region" : { "Ref" : "Region" },
          "AppAccessLogBucket" : { "Ref" : "AppAccessLogBucket" },
          "LogParser" : { "Ref" : "LogParser" },
          "ScannersProbesLambdaLogParser" : { "Ref" : "ScannersProbesLambdaLogParser" },
          "ScannersProbesAthenaLogParser" : { "Ref" : "ScannersProbesAthenaLogParser" },
          "MoveS3LogsForPartition" : { "Fn::If" : [
                                            "ScannersProbesAthenaLogParser",
                                            {"Ref" : "MoveS3LogsForPartitionarn"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "AccessLoggingBucket" : { "Fn::If" : [
                                            "ScannersProbesProtectionActivated",
                                            {"Ref" : "AccessLoggingBucket"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] }
      }
    },
      "ConfigureWafLogBucket": {
        "Type" : "Custom::ConfigureWafLogBucket",
        "Condition" : "HttpFloodProtectionLogParserActivated",
        "Properties" : {
          "ServiceToken" : { "Ref" : "CustomResourcearn" },
          "WafLogBucket" : { "Ref" : "WafLogBucket" },
          "LogParser" : { "Ref" : "LogParser" },
          "HttpFloodLambdaLogParser" : { "Ref" : "HttpFloodLambdaLogParser" },
          "HttpFloodAthenaLogParser" : { "Ref" : "HttpFloodAthenaLogParser" }
      }
    },
      "GenerateAppLogParserConfFile": {
        "Type" : "Custom::GenerateAppLogParserConfFile",
        "DependsOn" : "ConfigureAppAccessLogBucket",
        "Condition" : "ScannersProbesLambdaLogParser",
        "Properties" : {
          "ServiceToken" : { "Ref" : "CustomResourcearn" },
          "AppAccessLogBucket" : { "Ref" : "AppAccessLogBucket" },
          "StackName" : { "Ref" : "AWS::StackName" },
          "ErrorThreshold" : { "Ref" : "ErrorThreshold" },
          "WAFBlockPeriod" : { "Ref" : "WAFBlockPeriod" }
      }
    },
      "GenerateWafLogParserConfFile": {
        "Type" : "Custom::GenerateWafLogParserConfFil",
        "Condition" : "HttpFloodLambdaLogParser",
        "Properties" : {
          "ServiceToken" : { "Ref" : "CustomResourcearn" },
          "WafAccessLogBucket" : { "Ref" : "WafLogBucket" },
          "StackName" : { "Ref" : "AWS::StackName" },
          "RequestThreshold" : { "Ref" : "RequestThreshold" },
          "WAFBlockPeriod" : { "Ref" : "WAFBlockPeriod" }
      }
    },
      "ConfigureWebAcl": {
        "Type" : "Custom::ConfigureWebAcl",
        "Condition" : "HttpFloodLambdaLogParser",
        "Properties" : {
          "ServiceToken" : { "Ref" : "CustomResourcearn" },
          "ActivateSqlInjectionProtectionParam" : { "Ref" : "ActivateSqlInjectionProtectionParam" },
          "ActivateCrossSiteScriptingProtectionParam" : { "Ref" : "ActivateCrossSiteScriptingProtectionParam" },
          "ActivateHttpFloodProtectionParam" : { "Ref" : "ActivateHttpFloodProtectionParam" },
          "ActivateScannersProbesProtectionParam" : { "Ref" : "ActivateScannersProbesProtectionParam" },
          "ActivateReputationListsProtectionParam" : { "Ref" : "ActivateReputationListsProtectionParam" },
          "ActivateBadBotProtectionParam" : { "Ref" : "ActivateBadBotProtectionParam" },
          "ActivateAWSManagedRulesParam" : { "Ref" : "ActivateAWSManagedRulesParam" },
          "KeepDataInOriginalS3Location" : { "Ref" : "KeepDataInOriginalS3Location" },
          "IPRetentionPeriodAllowedParam" : { "Ref" : "IPRetentionPeriodAllowedParam" },
          "IPRetentionPeriodDeniedParam" : { "Ref" : "IPRetentionPeriodDeniedParam" },
          "SNSEmailParam" : { "Ref" : "SNSEmailParam" },
          "WAFWebACL" : { "Ref" : "wafwebacl" },
          "WAFWhitelistSetIPV4" : { "Ref" : "WAFWhitelistSetIPV4" },
          "WAFBlacklistSetIPV4" : { "Ref" : "WAFBlacklistSetIPV4" },
          "WAFHttpFloodSetIPV4" : { "Fn::If" : [
                                            "HttpFloodProtectionLogParserActivated",
                                            {"Ref" : "WAFHttpFloodSetIPV4"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "WAFScannersProbesSetIPV4" : { "Fn::If" : [
                                            "ScannersProbesProtectionActivated",
                                            {"Ref" : "WAFScannersProbesSetIPV4"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "WAFReputationListsSetIPV4" : { "Fn::If" : [
                                            "ReputationListsProtectionActivated",
                                            {"Ref" : "WAFReputationListsSetIPV4"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "WAFBadBotSetIPV4" : { "Fn::If" : [
                                            "BadBotProtectionActivated",
                                            {"Ref" : "WAFBadBotSetIPV4"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "WAFWhitelistSetIPV6" : { "Ref" : "WAFWhitelistSetIPV6" },
          "WAFBlacklistSetIPV6" : { "Ref" : "WAFBlacklistSetIPV6" },
          "WAFHttpFloodSetIPV6" : { "Fn::If" : [
                                            "HttpFloodProtectionLogParserActivated",
                                            {"Ref" : "WAFHttpFloodSetIPV6"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "WAFScannersProbesSetIPV6" : { "Fn::If" : [
                                            "ScannersProbesProtectionActivated",
                                            {"Ref" : "WAFHttpFloodSetIPV6"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "WAFReputationListsSetIPV6" : { "Fn::If" : [
                                            "ReputationListsProtectionActivated",
                                            {"Ref" : "WAFHttpFloodSetIPV6"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "WAFBadBotSetIPV6" : { "Fn::If" : [
                                            "BadBotProtectionActivated",
                                            {"Ref" : "WAFHttpFloodSetIPV6"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "WAFWhitelistSetIPV4Name" : { "Ref" : "WAFWhitelistSetIPV4Name" },
          "WAFBlacklistSetIPV4Name" : { "Ref" : "WAFBlacklistSetIPV4Name" },
          "WAFHttpFloodSetIPV4Name" : { "Fn::If" : [
                                            "HttpFloodProtectionLogParserActivated",
                                            {"Ref" : "WAFHttpFloodSetIPV6Name"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "WAFScannersProbesSetIPV4Name" : { "Fn::If" : [
                                            "ScannersProbesProtectionActivated",
                                            {"Ref" : "WAFHttpFloodSetIPV6Name"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "WAFReputationListsSetIPV4Name" : { "Fn::If" : [
                                            "ReputationListsProtectionActivated",
                                            {"Ref" : "WAFHttpFloodSetIPV6Name"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "WAFBadBotSetIPV4Name" : { "Fn::If" : [
                                            "BadBotProtectionActivated",
                                            {"Ref" : "WAFHttpFloodSetIPV6Name"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "WAFWhitelistSetIPV6Name" : { "Ref" : "WAFWhitelistSetIPV6Name" },
          "WAFBlacklistSetIPV6Name" : { "Ref" : "WAFBlacklistSetIPV6Name" },
          "WAFHttpFloodSetIPV6Name" : { "Fn::If" : [
                                            "HttpFloodProtectionLogParserActivated",
                                            {"Ref" : "WAFHttpFloodSetIPV6Name"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "WAFScannersProbesSetIPV6Name" : { "Fn::If" : [
                                            "ScannersProbesProtectionActivated",
                                            {"Ref" : "WAFHttpFloodSetIPV6Name"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "WAFReputationListsSetIPV6Name" : { "Fn::If" : [
                                            "ReputationListsProtectionActivated",
                                            {"Ref" : "WAFHttpFloodSetIPV6Name"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "WAFBadBotSetIPV6Name" : { "Fn::If" : [
                                            "BadBotProtectionActivated",
                                            {"Ref" : "WAFHttpFloodSetIPV6Name"},
                                            {"Ref" : "AWS::NoValue"}
                                          ] },
          "UUID" : { "Fn::GetAtt" : [ "CreateUniqueID", "UUID" ] },
          "Region" : { "Ref" : "Region" },
          "RequestThreshold" : { "Ref" : "RequestThreshold" },
          "ErrorThreshold" : { "Ref" : "ErrorThreshold" },
          "WAFBlockPeriod" : { "Ref" : "WAFBlockPeriod" },
          "Version" : { "Ref" : "version" },
          "SendAnonymousUsageData" : { "Ref" : "SendAnonymousUsageData" }
      }
    },
      "CustomAddAthenaPartitions": {
        "Type" : "Custom::AddAthenaPartition",
        "Condition" : "AthenaLogParser",
        "Properties" : {
          "ServiceToken" : { "Ref" : "CustomResourcearn" },
          "AddAthenaPartitionsLambda" : { "Ref" : "AddAthenaPartitionsLambdaarn" },
          "ResourceType" : { "Ref" : "ResourceType" },
          "GlueAccessLogsDatabase" : { "Ref" : "GlueAccessLogsDatabase" },
          "AppAccessLogBucket" : { "Ref" : "AppAccessLogBucket" },
          "GlueAppAccessLogsTable" : { "Ref" : "GlueAppAccessLogsTable" },
          "GlueWafAccessLogsTable" : { "Ref" : "GlueWafAccessLogsTable" },
          "WafLogBucket" : { "Ref" : "WafLogBucket" },
          "AthenaWorkGroup" : { "Ref" : "AthenaWorkGroup" }
      }
    }
  },
  "Outputs" : {
  
      "UUID" : {
  
        "Description" : "UUID of the newly created  instance",
  
        "Value" : { "Fn::GetAtt" : [ "CreateUniqueID", "UUID" ] }
  
    }
  }
}
STACK
  depends_on = [
    aws_iam_role_policy.CloudWatchAccessListsParser,
    aws_iam_role_policy.WAFGetAndUpdateIPListsParser,
    aws_iam_role_policy.CloudWatchLogsListsParser,
    aws_lambda_function.helper,
    aws_lambda_function.MoveS3LogsForPartition,
    aws_lambda_function.SetIPRetention,
    aws_lambda_function.ReputationListsParser,
    aws_lambda_function.CustomResource,
    aws_lambda_function.LogParser,
    aws_lambda_function.AddAthenaPartitions,
    aws_lambda_function.CustomTimer
  ]
}

# ----------------------------------------------------------------------------------------------------------------------
# Firehose Athena 
# ----------------------------------------------------------------------------------------------------------------------

resource "aws_iam_role" "FirehoseWAFLogsDeliveryStreamRole" {
  count = local.HttpFloodProtectionLogParserActivated == "yes" ? 1 : 0
  name  = "FirehoseWAFLogsDeliveryStreamRole1-${random_id.server.hex}"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "firehose.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "S3AccessFirehoseWAFLogs" {
  count  = local.HttpFloodProtectionLogParserActivated == "yes" ? 1 : 0
  name   = "S3Access1"
  role   = aws_iam_role.FirehoseWAFLogsDeliveryStreamRole[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:AbortMultipartUpload",
                "s3:ListBucketMultipartUploads",
                "s3:PutObject"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.WafLogBucket[0].bucket}",
                "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.WafLogBucket[0].bucket}/*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.FirehoseWAFLogsDeliveryStreamRole[0]
  ]
}

resource "aws_iam_role_policy" "KinesisAccess" {
  count  = local.HttpFloodProtectionLogParserActivated == "yes" ? 1 : 0
  name   = "KinesisAccess1"
  role   = aws_iam_role.FirehoseWAFLogsDeliveryStreamRole[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "kinesis:DescribeStream",
                "kinesis:GetShardIterator",
                "kinesis:GetRecords"
            ],
            "Resource": [
                  "arn:${data.aws_partition.current.partition}:kinesis:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:stream/${var.DeliveryStreamName}"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.FirehoseWAFLogsDeliveryStreamRole[0]
  ]
}

resource "aws_iam_role_policy" "CloudWatchAccess" {
  count  = local.HttpFloodProtectionLogParserActivated == "yes" ? 1 : 0
  name   = "CloudWatchAccess1"
  role   = aws_iam_role.FirehoseWAFLogsDeliveryStreamRole[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:PutLogEvents"
            ],
            "Resource": [
                  "arn:${data.aws_partition.current.partition}:kinesis:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/kinesisfirehose/${var.DeliveryStreamName}:*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.FirehoseWAFLogsDeliveryStreamRole[0]
  ]
}


resource "aws_kinesis_firehose_delivery_stream" "extended_s3_stream" {
  count       = local.HttpFloodProtectionLogParserActivated == "yes" ? 1 : 0
  name        = var.DeliveryStreamName
  destination = "extended_s3"
  server_side_encryption {
    key_type = "CUSTOMER_MANAGED_CMK"
    enabled  = "true"
    key_arn  = aws_kms_key.wafkey.arn
  }
  extended_s3_configuration {
    bucket_arn          = aws_s3_bucket.WafLogBucket[0].arn
    compression_format  = "GZIP"
    error_output_prefix = "AWSErrorLogs/result=!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/"
    role_arn            = aws_iam_role.FirehoseWAFLogsDeliveryStreamRole[0].arn
    buffer_size         = 5
    buffer_interval     = 300
  }
}


# ----------------------------------------------------------------------------------------------------------------------
# Glue Database and tables
# ----------------------------------------------------------------------------------------------------------------------

resource "aws_glue_catalog_database" "mydatabase" {
  count      = local.AthenaLogParser == "yes" ? 1 : 0
  name       = "mygluedatabase-${random_id.server.hex}"
  catalog_id = data.aws_caller_identity.current.account_id
}

resource "aws_glue_catalog_table" "waf_access_logs_table" {
  count         = local.HttpFloodAthenaLogParser == "yes" ? 1 : 0
  name          = "waf_access_logs-${random_id.server.hex}"
  database_name = aws_glue_catalog_database.mydatabase[0].name
  catalog_id    = data.aws_caller_identity.current.account_id
  parameters = {
    EXTERNAL = "TRUE"
  }
  partition_keys {
    name = "year"
    type = "int"
  }
  partition_keys {
    name = "month"
    type = "init"
  }
  partition_keys {
    name = "day"
    type = "int"
  }
  partition_keys {
    name = "hour"
    type = "int"
  }
  storage_descriptor {
    location      = "s3://${aws_s3_bucket.WafLogBucket[0].bucket}/AWSLogs/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.IgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"

      parameters = {
        "paths" = "action,formatVersion,httpRequest,httpSourceId,httpSourceName,nonTerminatingMatchingRules,rateBasedRuleList,ruleGroupList,terminatingRuleId,terminatingRuleType,timestamp,webaclId"
      }
    }
    compressed                = "true"
    stored_as_sub_directories = "false"
    dynamic "columns" {
      for_each = var.waf_access_logs_columns

      content {
        name = columns.key
        type = columns.value
      }
    }
  }
}


resource "aws_glue_catalog_table" "ALBGlueAppAccessLogsTable" {
  count         = local.AthenaLogParser == "yes" && local.ALBScannersProbesAthenaLogParser == "yes" ? 1 : 0
  name          = "app_access_logs-${random_id.server.hex}"
  database_name = aws_glue_catalog_database.mydatabase[0].name
  catalog_id    = data.aws_caller_identity.current.account_id
  parameters = {
    EXTERNAL = "TRUE"
  }
  partition_keys {
    name = "year"
    type = "int"
  }
  partition_keys {
    name = "month"
    type = "init"
  }
  partition_keys {
    name = "day"
    type = "int"
  }
  partition_keys {
    name = "hour"
    type = "int"
  }
  storage_descriptor {
    location      = "s3://${local.AppLogBucket}/AWSLogs-Partitioned/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.IgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.serde2.RegexSerDe"

      parameters = {
        "serialization.format" = "1",
        "input.regex"          = "([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) \"([^ ]*) ([^ ]*) (- |[^ ]*)\" \"([^\"]*)\" ([A-Z0-9-]+) ([A-Za-z0-9.-]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\" ([-.0-9]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\"($| \"[^ ]*\")(.*)"
      }
    }
    compressed                = "true"
    stored_as_sub_directories = "false"
    dynamic "columns" {
      for_each = var.app_access_logs_columns
      content {
        name = columns.key
        type = columns.value
      }
    }
  }
}

resource "aws_glue_catalog_table" "cloudfrontGlueAppAccessLogsTable" {
  count         = local.AthenaLogParser == "yes" && local.CloudFrontScannersProbesAthenaLogParser == "yes" ? 1 : 0
  name          = "app_access_logs-${random_id.server.hex}"
  database_name = aws_glue_catalog_database.mydatabase[0].name
  catalog_id    = data.aws_caller_identity.current.account_id
  parameters = {
    "skip.header.line.count" = "2",
    "EXTERNAL"               = "TRUE"
  }
  partition_keys {
    name = "year"
    type = "int"
  }
  partition_keys {
    name = "month"
    type = "init"
  }
  partition_keys {
    name = "day"
    type = "int"
  }
  partition_keys {
    name = "hour"
    type = "int"
  }
  storage_descriptor {
    location      = "s3://${local.AppLogBucket}/AWSLogs-Partitioned/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.IgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"

      parameters = {
        "serialization.format" = "\t",
        "field.delim"          = "\t"
      }
    }
    compressed                = "true"
    stored_as_sub_directories = "true"
    dynamic "columns" {
      for_each = var.cloudfront_app_access_logs_columns
      content {
        name = columns.key
        type = columns.value
      }
    }
  }
}


resource "aws_athena_workgroup" "WAFAddPartitionAthenaQueryWorkGroup" {
  count         = local.AthenaLogParser == "yes" ? 1 : 0
  name          = "WAFAddPartitionAthenaQueryWorkGroup-${random_id.server.hex}"
  description   = "Athena WorkGroup for adding Athena partition queries used by AWS WAF Security Automations Solution"
  state         = "ENABLED"
  force_destroy = "true"

  configuration {
    publish_cloudwatch_metrics_enabled = true
    result_configuration {
      output_location = "s3://${local.AppLogBucket}/outputWAFAppAccessLogAthenaQueryWorkGroup/"
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.wafkey.arn
      }
    }
  }
}

resource "aws_athena_workgroup" "WAFLogAthenaQueryWorkGroup" {
  count         = local.HttpFloodAthenaLogParser == "yes" ? 1 : 0
  name          = "WAFLogAthenaQueryWorkGroup-${random_id.server.hex}"
  description   = "Athena WorkGroup for adding Athena partition queries used by AWS WAF Security Automations Solution"
  state         = "ENABLED"
  force_destroy = "true"

  configuration {
    publish_cloudwatch_metrics_enabled = true
    result_configuration {
      output_location = "s3://${local.AppLogBucket}/outputWAFAppAccessLogAthenaQueryWorkGroup/"
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.wafkey.arn
      }
    }
  }
}

resource "aws_athena_workgroup" "WAFAppAccessLogAthenaQueryWorkGroup" {
  count         = local.ScannersProbesAthenaLogParser == "yes" ? 1 : 0
  name          = "WAFAppAccessLogAthenaQueryWorkGroup-${random_id.server.hex}"
  description   = "Athena WorkGroup for adding Athena partition queries used by AWS WAF Security Automations Solution"
  state         = "ENABLED"
  force_destroy = "true"

  configuration {
    publish_cloudwatch_metrics_enabled = true
    result_configuration {
      output_location = "s3://${local.AppLogBucket}/outputWAFAppAccessLogAthenaQueryWorkGroup/"
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.wafkey.arn
      }
    }
  }
}


# ----------------------------------------------------------------------------------------------------------------------
# CREATE A EVENT RULES
# ----------------------------------------------------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "LambdaAddAthenaPartitionsEventsRule" {
  count               = local.AthenaLogParser == "yes" ? 1 : 0
  name                = "LambdaAddAthenaPartitionsEventsRule-${random_id.server.hex}"
  description         = "Security Automations - Add partitions to Athena table"
  schedule_expression = "cron(* ? * * * *)"
  is_enabled          = true
}


resource "aws_cloudwatch_event_target" "LambdaAddAthenaPartitionstarget" {
  count     = local.AthenaLogParser == "yes" && local.ALBScannersProbesAthenaLogParser == "yes" ? 1 : 0
  target_id = "LambdaAddAthenaPartitions"
  arn       = aws_lambda_function.AddAthenaPartitions[0].arn
  rule      = aws_cloudwatch_event_rule.LambdaAddAthenaPartitionsEventsRule[0].name
  input     = <<EOF
                {
                "resourceType": "LambdaAddAthenaPartitionsEventsRule",
                "glueAccessLogsDatabase": "${aws_glue_catalog_database.mydatabase[0].name}",
                "accessLogBucket": "${local.AppLogBucket}",
                "glueAppAccessLogsTable": "${aws_glue_catalog_table.ALBGlueAppAccessLogsTable[0].name}",
                "glueWafAccessLogsTable": "${aws_glue_catalog_table.waf_access_logs_table[0].name}",
                "wafLogBucket": "${aws_s3_bucket.WafLogBucket[0].bucket}",
                "athenaWorkGroup": "${aws_athena_workgroup.WAFAddPartitionAthenaQueryWorkGroup[0].name}"
              }
EOF
  depends_on = [
    aws_cloudwatch_event_rule.LambdaAddAthenaPartitionsEventsRule
  ]
}

resource "aws_cloudwatch_event_rule" "LambdaAthenaWAFLogParserrule" {
  count               = local.HttpFloodAthenaLogParser == "yes" ? 1 : 0
  name                = "LambdaAthenaWAFLogParserrule-${random_id.server.hex}"
  description         = "Security Automations - WAF Logs Athena parser"
  schedule_expression = "rate(5 minutes)"
  is_enabled          = true
}

resource "aws_cloudwatch_event_target" "LogParsertarget" {
  count     = local.HttpFloodAthenaLogParser == "yes" ? 1 : 0
  target_id = "LogParser"
  arn       = aws_lambda_function.LogParser[0].arn
  rule      = aws_cloudwatch_event_rule.LambdaAthenaWAFLogParserrule[0].name
  input     = <<EOF
            {
              "resourceType": "LambdaAthenaWAFLogParser",
              "glueAccessLogsDatabase": "${aws_glue_catalog_database.mydatabase[0].name}",
              "accessLogBucket": "${local.AppLogBucket}",
              "glueWafAccessLogsTable": "${aws_glue_catalog_table.waf_access_logs_table[0].name}",
              "athenaWorkGroup":"${aws_athena_workgroup.WAFAppAccessLogAthenaQueryWorkGroup[0].name}"
            }
EOF
  depends_on = [
    aws_cloudwatch_event_rule.LambdaAthenaWAFLogParserrule
  ]
}

resource "aws_cloudwatch_event_rule" "LambdaAthenaAppLogParserrule" {
  count               = local.ScannersProbesAthenaLogParser == "yes" ? 1 : 0
  name                = "LambdaAthenaAppLogParserrule-${random_id.server.hex}"
  description         = "Security Automation - App Logs Athena parser"
  schedule_expression = "rate(5 minutes)"
  is_enabled          = true
}

resource "aws_cloudwatch_event_target" "LogParsertarget1" {
  count     = local.ScannersProbesAthenaLogParser == "yes" && local.ALBScannersProbesAthenaLogParser == "yes" ? 1 : 0
  target_id = "LogParser"
  arn       = aws_lambda_function.LogParser[0].arn
  rule      = aws_cloudwatch_event_rule.LambdaAthenaAppLogParserrule[0].name
  input     = <<EOF
            {
              "resourceType": "LambdaAthenaAppLogParser",
              "glueAccessLogsDatabase": "${aws_glue_catalog_database.mydatabase[0].name}",
              "accessLogBucket": "${local.AppLogBucket}",
              "glueAppAccessLogsTable": "${local.AppAccessLogsTable}",
              "athenaWorkGroup": "${aws_athena_workgroup.WAFAppAccessLogAthenaQueryWorkGroup[0].name}"
            }
EOF
  depends_on = [
    aws_cloudwatch_event_rule.LambdaAthenaAppLogParserrule[0]
  ]
}


resource "aws_cloudwatch_event_rule" "ReputationListsParserEventsRule" {
  count               = var.ReputationListsProtectionActivated == "yes" ? 1 : 0
  name                = "ReputationEventsRule-${random_id.server.hex}"
  description         = "Security Automation - WAF Reputation Lists"
  schedule_expression = "rate(1 hour)"
  is_enabled          = true
}

resource "aws_cloudwatch_event_target" "ReputationListsParsertarget" {
  target_id = "ReputationListsParser"
  arn       = aws_lambda_function.ReputationListsParser[0].arn
  rule      = aws_cloudwatch_event_rule.ReputationListsParserEventsRule[0].name
  input     = <<EOF
              {
                "URL_LIST": [
                  {"url":"https://www.spamhaus.org/drop/drop.txt"},
                  {"url":"https://www.spamhaus.org/drop/edrop.txt"},
                  {"url":"https://check.torproject.org/exit-addresses", "prefix":"ExitAddress"},
                  {"url":"https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"}
                ],
                "IP_SET_ID_REPUTATIONV4": "${aws_wafv2_ip_set.WAFReputationListsSetV4[0].arn}",
                "IP_SET_ID_REPUTATIONV6": "${aws_wafv2_ip_set.WAFReputationListsSetV6[0].arn}",
                "IP_SET_NAME_REPUTATIONV4": "${aws_wafv2_ip_set.WAFReputationListsSetV4[0].name}",
                "IP_SET_NAME_REPUTATIONV6": "${aws_wafv2_ip_set.WAFReputationListsSetV6[0].name}",
                "SCOPE": "${local.SCOPE}"
              }
EOF
  depends_on = [
    aws_cloudwatch_event_rule.ReputationListsParserEventsRule
  ]
}

resource "aws_cloudwatch_event_rule" "SetIPRetentionEventsRule" {
  count         = var.IPRetentionPeriod == "yes" ? 1 : 0
  name          = "IPRetentionPeriodsRule-${random_id.server.hex}"
  description   = "AWS WAF Security Automations - Events rule for setting IP retention"
  is_enabled    = true
  event_pattern = <<EOF
{
  "detail-type": ["AWS API Call via CloudTrail"],
  "source": ["aws.wafv2"],
  "detail": {
    "eventSource": ["wafv2.amazonaws.com"],
    "eventName": ["UpdateIPSet"],
    "requestParameters" : [
        "${aws_wafv2_ip_set.WAFWhitelistSetV4.name}",
        "${aws_wafv2_ip_set.WAFBlacklistSetV4.name}",
        "${aws_wafv2_ip_set.WAFWhitelistSetV6.name}",
        "${aws_wafv2_ip_set.WAFBlacklistSetV6.name}"
    ]

  }
}
  EOF
}

resource "aws_cloudwatch_event_target" "SetIPRetentionEventstarget" {
  count     = var.IPRetentionPeriod == "yes" ? 1 : 0
  target_id = "SetIPRetentionLambda"
  arn       = aws_lambda_function.SetIPRetention[0].arn
  rule      = aws_cloudwatch_event_rule.SetIPRetentionEventsRule[0].name
  depends_on = [
    aws_cloudwatch_event_rule.SetIPRetentionEventsRule[0]
  ]
}


# ----------------------------------------------------------------------------------------------------------------------
# CREATE A LAMBDA PERMISSION
# ----------------------------------------------------------------------------------------------------------------------

resource "aws_lambda_permission" "LambdaInvokePermissionAppLogParserS3" {
  count          = local.LogParser == "yes" ? 1 : 0
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.LogParser[0].function_name
  principal      = "s3.amazonaws.com"
  source_account = data.aws_caller_identity.current.account_id
}

resource "aws_lambda_permission" "LambdaInvokePermissionMoveS3LogsForPartition" {
  count          = local.ScannersProbesAthenaLogParser == "yes" ? 1 : 0
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.MoveS3LogsForPartition[0].function_name
  principal      = "s3.amazonaws.com"
  source_account = data.aws_caller_identity.current.account_id
}

resource "aws_lambda_permission" "LambdaPermissionAddAthenaPartitions" {
  count         = local.AthenaLogParser == "yes" ? 1 : 0
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.AddAthenaPartitions[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.LambdaAddAthenaPartitionsEventsRule[0].arn
}

resource "aws_lambda_permission" "LambdaInvokePermissionSetIPRetention" {
  count         = var.IPRetentionPeriod == "yes" ? 1 : 0
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.SetIPRetention[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.SetIPRetentionEventsRule[0].arn
}

resource "aws_lambda_permission" "LambdaInvokePermissionWafLogParserCloudWatch" {
  count         = local.HttpFloodAthenaLogParser == "yes" ? 1 : 0
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.LogParser[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.LambdaAthenaWAFLogParserrule[0].arn
}

resource "aws_lambda_permission" "LambdaInvokePermissionAppLogParserCloudWatch" {
  count         = local.ScannersProbesAthenaLogParser == "yes" ? 1 : 0
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.LogParser[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.LambdaAthenaAppLogParserrule[0].arn
}

resource "aws_lambda_permission" "LambdaInvokePermissionReputationListsParser" {
  count         = var.ReputationListsProtectionActivated == "yes" ? 1 : 0
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ReputationListsParser[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ReputationListsParserEventsRule[0].arn
}

resource "aws_lambda_permission" "LambdaInvokePermissionBadBot" {
  count         = var.BadBotProtectionActivated == "yes" ? 1 : 0
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.BadBotParser[0].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = aws_api_gateway_rest_api.api[0].arn
}

# ----------------------------------------------------------------------------------------------------------------------
# API gateway
# ----------------------------------------------------------------------------------------------------------------------

resource "aws_api_gateway_rest_api" "api" {
  count       = var.BadBotProtectionActivated == "yes" ? 1 : 0
  name        = "WAF Bad Bot API-${random_id.server.hex}"
  description = "API created by AWS WAF Security Automation CloudFormation template. This endpoint will be used to capture bad bots."
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_resource" "resource" {
  parent_id   = aws_api_gateway_rest_api.api[0].root_resource_id
  path_part   = "{proxy+}"
  rest_api_id = aws_api_gateway_rest_api.api[0].id
  depends_on = [
    aws_api_gateway_rest_api.api
  ]
}

resource "aws_api_gateway_method" "ApiGatewayBadBotMethodRoot" {
  authorization      = "NONE"
  http_method        = "ANY"
  api_key_required   = true
  resource_id        = aws_api_gateway_rest_api.api[0].root_resource_id
  rest_api_id        = aws_api_gateway_rest_api.api[0].id
  request_parameters = { "method.request.header.X-Forwarded-For" = false }
  depends_on = [
    aws_lambda_permission.LambdaInvokePermissionBadBot,
    aws_api_gateway_rest_api.api
  ]
}

resource "aws_api_gateway_integration" "integrationroot" {
  rest_api_id             = aws_api_gateway_rest_api.api[0].id
  resource_id             = aws_api_gateway_rest_api.api[0].root_resource_id
  http_method             = aws_api_gateway_method.ApiGatewayBadBotMethodRoot.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = "arn:${data.aws_partition.current.partition}:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/${aws_lambda_function.BadBotParser[0].arn}/invocations"
  depends_on = [
    aws_api_gateway_method.ApiGatewayBadBotMethodRoot,
    aws_api_gateway_rest_api.api
  ]
}



resource "aws_api_gateway_method" "ApiGatewayBadBotMethod" {
  authorization      = "NONE"
  http_method        = "ANY"
  api_key_required   = true
  resource_id        = aws_api_gateway_resource.resource.id
  rest_api_id        = aws_api_gateway_rest_api.api[0].id
  request_parameters = { "method.request.header.X-Forwarded-For" = false }
  depends_on = [
    aws_lambda_permission.LambdaInvokePermissionBadBot
  ]
}

resource "aws_api_gateway_integration" "integration" {
  rest_api_id             = aws_api_gateway_rest_api.api[0].id
  resource_id             = aws_api_gateway_resource.resource.id
  http_method             = aws_api_gateway_method.ApiGatewayBadBotMethod.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = "arn:${data.aws_partition.current.partition}:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/${aws_lambda_function.BadBotParser[0].arn}/invocations"
  depends_on = [
    aws_api_gateway_method.ApiGatewayBadBotMethod
  ]
}


resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.api[0].id
  stage_name  = "CFDeploymentStage-${random_id.server.hex}"
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    aws_api_gateway_method.ApiGatewayBadBotMethod,
    aws_api_gateway_integration.integration
    
  ]
}



resource "aws_cloudwatch_log_group" "ApiGatewayBadBotStageAccessLogGroup" {
  count             = var.BadBotProtectionActivated == "yes" ? 1 : 0
  name              = "ApiGatewayBadBotStageAccessLogGroup-${random_id.server.hex}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.wafkey.arn
}

resource "aws_api_gateway_stage" "stage" {
  count = var.BadBotProtectionActivated == "yes" ? 1 : 0
  deployment_id         = aws_api_gateway_deployment.deployment.id
  rest_api_id           = aws_api_gateway_rest_api.api[0].id
  stage_name            = "ProdStage"
  xray_tracing_enabled  = true
  cache_cluster_enabled = true
  cache_cluster_size    = 0.5
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.ApiGatewayBadBotStageAccessLogGroup[0].arn
    format = jsonencode({
      sourceIp       = "$context.identity.sourceIp"
      caller         = "$context.identity.caller"
      user           = "$context.identity.user"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      resourcePath   = "$context.resourcePath"
      protocol       = "$context.protocol"
      status         = "$context.status"
      responseLength = "$context.responseLength"
      requestId      = "$context.requestId"
      }
    )
  }
}


resource "aws_api_gateway_method_settings" "path_specific" {
  count       = var.BadBotProtectionActivated == "yes" ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.api[0].id
  stage_name  = aws_api_gateway_stage.stage[0].stage_name
  method_path = "*/*"

  settings {
    metrics_enabled = true
    logging_level   = "INFO"
    caching_enabled = true
  }
}


resource "aws_iam_role" "ApiGatewayBadBotCloudWatchRole" {
  count = var.BadBotProtectionActivated == "yes" ? 1 : 0
  name  = "BadBotRole1-${random_id.server.hex}"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "apigateway.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "ApiGatewayBadBotCloudWatchploicy" {
  name   = "ApiGatewayBadBotCloudWatchpolicy"
  role   = aws_iam_role.ApiGatewayBadBotCloudWatchRole[0].id
  policy = <<EOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:GetLogEvents",
                "logs:FilterLogEvents"
            ],
            "Resource": [
                "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOT
  depends_on = [
    aws_iam_role.ApiGatewayBadBotCloudWatchRole
  ]
}

resource "aws_api_gateway_account" "ApiGatewayBadBotAccount" {
  count               = var.BadBotProtectionActivated == "yes" ? 1 : 0
  cloudwatch_role_arn = aws_iam_role.ApiGatewayBadBotCloudWatchRole[0].arn
  depends_on = [
    aws_api_gateway_rest_api.api
  ]
}


# ----------------------------------------------------------------------------------------------------------------------
# CloudWatch Dashboard
# ----------------------------------------------------------------------------------------------------------------------


resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "MonitoringDashboard-${data.aws_region.current.name}"

  dashboard_body = <<EOF
{
  "widgets": [
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 15,
      "height": 10,
      "properties": {
        "metrics":[
                      ["WAF", "BlockedRequests", "WebACL", "WAFWebACLMetric", "Rule", "ALL", "Region", "${data.aws_region.current.name}" ],
                      ["WAF", "AllowedRequests", "WebACL", "WAFWebACLMetric", "Rule", "ALL", "Region", "${data.aws_region.current.name}" ]
            ],
        "view": "timeSeries",
        "stacked": false,
        "stat": "Sum",
        "period": 300,
        "region": "${data.aws_region.current.name}"
      }
    }
  ]
}
EOF
}