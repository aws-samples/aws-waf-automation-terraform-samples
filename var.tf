variable "AppAccessLogBucket" {
  description = "Application Access Log Bucket Name"
  type        = string
  default     = "myownbucket-tam"
}
variable "SourceBucket" {
  description = "Lambda source code bucket"
  type        = string
  default     = "solutions"
}
variable "KeyPrefix" {
  description = "Keyprefix values for the lambda source code"
  type        = string
  default     = "aws-waf-security-automations/v3.2.0"
}
variable "LOG_LEVEL" {
  description = "Log level"
  type        = string
  default     = "INFO"
}

variable "sse_algorithm" {
  description = "sse_algorithm"
  type        = string
  default     = "aws:kms"
}

#ELigible for switch case

variable "ENDPOINT" {
  description = "cloudfront or ALB"
  type        = string
  default     = "cloudFront"
  validation {
    condition     = contains(["cloudfront", "ALB"], var.ENDPOINT)
    error_message = "Invalid input, options: \"cloudfront\",\"ALB\"."
  }
}

locals {
  LOG_TYPE = var.ENDPOINT == "ALB" ? "alb" : "cloudFront"
}

locals {
  SCOPE = var.ENDPOINT == "ALB" ? "REGIONAL" : "CLOUDFRONT"
}

variable "USER_AGENT_EXTRA" {
  description = "UserAgent"
  type        = string
  default     = "AwsSolution/SO0006/v3.2.0"
}
variable "SEND_ANONYMOUS_USAGE_DATA" {
  description = "Data collection parameter"
  type        = string
  default     = "yes"
}
variable "MetricsURL" {
  description = "Metrics URL"
  type        = string
  default     = "https://metrics.awssolutionsbuilder.com/generic"
}
variable "SolutionID" {
  description = "UserAgent id value"
  type        = string
  default     = "SO0006"
}
variable "KEEP_ORIGINAL_DATA" {
  description = "S3 original data"
  type        = string
  default     = "No"
}
variable "SendAnonymousUsageData" {
  description = "Data collection parameter"
  type        = string
  default     = "yes"
}
variable "IPRetentionPeriodAllowedParam" {
  description = "IP Retention Settings allowed value"
  type        = number
  default     = -1
}
variable "IPRetentionPeriodDeniedParam" {
  description = "IP Retention Settings denied value"
  type        = number
  default     = -1
}
variable "RequestThreshold" {
  description = "request threshold for Log Monitoring Settings"
  type        = number
  default     = 100
}
variable "WAFBlockPeriod" {
  description = "block period for Log Monitoring Settings"
  type        = number
  default     = 240
}
variable "ErrorThreshold" {
  description = "error threshold for Log Monitoring Settings"
  type        = number
  default     = 50
}

variable "DeliveryStreamName" {
  description = "Name of the Delivery stream value"
  type        = string
  default     = "terraform-kinesis-firehose-extended-s3-test-stream"
}


variable "waf_access_logs_columns" {
  default = {
    timestamp                   = "bigint"
    formatversion               = "int"
    webaclid                    = "string"
    terminatingruleid           = "string"
    terminatingruletype         = "string"
    action                      = "string"
    httpsourcename              = "string"
    httpsourceid                = "string"
    rulegrouplist               = "array<string>"
    ratebasedrulelist           = "array<string>"
    nonterminatingmatchingrules = "array<string>"
    httprequest                 = "struct<clientip:string,country:string,headers:array<struct<name:string,value:string>>,uri:string,args:string,httpversion:string,httpmethod:string,requestid:string>"
  }
}

variable "app_access_logs_columns" {
  default = {
    type                     = "string"
    time                     = "string"
    elb                      = "string"
    client_ip                = "string"
    client_port              = "int"
    target_ip                = "string"
    target_port              = "int"
    request_processing_time  = "double"
    response_processing_time = "double"
    target_processing_time   = "double"
    elb_status_code          = "string"
    target_status_code       = "string"
    received_bytes           = "bigint"
    sent_bytes               = "bigint"
    request_verb             = "string"
    request_url              = "string"
    request_proto            = "string"
    user_agent               = "string"
    ssl_cipher               = "string"
    ssl_protocol             = "string"
    target_group_arn         = "string"
    trace_id                 = "string"
    domain_name              = "string"
    chosen_cert_arn          = "string"
    matched_rule_priority    = "string"
    request_creation_time    = "string"
    actions_executed         = "string"
    redirect_url             = "string"
    lambda_error_reason      = "string"
    new_field                = "string"
  }
}

variable "cloudfront_app_access_logs_columns" {
  default = {
    date               = "date"
    time               = "string"
    location           = "string"
    bytes              = "bigint"
    requestip          = "string"
    method             = "string"
    host               = "string"
    uri                = "string"
    status             = "int"
    referrer           = "string"
    useragent          = "string"
    querystring        = "string"
    cookie             = "string"
    resulttype         = "string"
    requestid          = "string"
    hostheader         = "string"
    requestprotocol    = "string"
    requestbytes       = "bigint"
    timetaken          = "float"
    xforwardedfor      = "string"
    sslprotocol        = "string"
    sslcipher          = "string"
    responseresulttype = "string"
    httpversion        = "string"
    filestatus         = "string"
    encryptedfields    = "int"
  }
}


variable "SNSEmailParam" {
  description = "SNS notification value"
  type        = string
  default     = ""
}

locals {
  SNSEmail = var.SNSEmailParam == "" ? "no" : "yes"
}



variable "ActivateHttpFloodProtectionParam" {
  type    = string
  default = "yes - AWS WAF rate based rule"

  # using contains()
  validation {
    condition     = contains(["yes - AWS Lambda log parser", "yes - Amazon Athena log parser", "yes - AWS WAF rate based rule", "no"], var.ActivateHttpFloodProtectionParam)
    error_message = "Invalid input, options: \"yes - AWS Lambda log parser\", \"yes - Amazon Athena log parser\",\"yes - AWS WAF rate based rule\", \"no\"."
  }
}

locals {
  HttpFloodProtectionRateBasedRuleActivated = var.ActivateHttpFloodProtectionParam == "yes - AWS WAF rate based rule" ? "yes" : "no"
}

locals {
  HttpFloodAthenaLogParser = var.ActivateHttpFloodProtectionParam == "yes - Amazon Athena log parser" ? "yes" : "no"
}

locals {
  HttpFloodLambdaLogParser = var.ActivateHttpFloodProtectionParam == "yes - AWS Lambda log parser" ? "yes" : "no"
}

locals {
  HttpFloodProtectionLogParserActivated = var.ActivateHttpFloodProtectionParam == "yes - AWS Lambda log parser" || var.ActivateHttpFloodProtectionParam == "yes - Amazon Athena log parser" ? "yes" : "no"
}

variable "ActivateAWSManagedRulesParam" {
  type    = string
  default = "no"

  # using contains()
  validation {
    condition     = contains(["yes", "no"], var.ActivateAWSManagedRulesParam)
    error_message = "Invalid input, options: \"yes\",\"no\"."
  }
}

variable "ActivateSqlInjectionProtectionParam" {
  type    = string
  default = "yes"

  # using contains()
  validation {
    condition     = contains(["yes", "no"], var.ActivateSqlInjectionProtectionParam)
    error_message = "Invalid input, options: \"yes\",\"no\"."
  }
}

variable "ActivateCrossSiteScriptingProtectionParam" {
  type    = string
  default = "yes"

  # using contains()
  validation {
    condition     = contains(["yes", "no"], var.ActivateCrossSiteScriptingProtectionParam)
    error_message = "Invalid input, options: \"yes\",\"no\"."
  }
}

variable "ActivateReputationListsProtectionParam" {
  type    = string
  default = "yes"

  # using contains()
  validation {
    condition     = contains(["yes", "no"], var.ActivateReputationListsProtectionParam)
    error_message = "Invalid input, options: \"yes\",\"no\"."
  }
}

variable "ActivateBadBotProtectionParam" {
  type    = string
  default = "yes"

  # using contains()
  validation {
    condition     = contains(["yes", "no"], var.ActivateBadBotProtectionParam)
    error_message = "Invalid input, options: \"yes\",\"no\"."
  }
}

variable "ActivateScannersProbesProtectionParam" {
  type    = string
  default = ""

  # using contains()
  validation {
    condition     = contains(["yes - AWS Lambda log parser", "yes - Amazon Athena log parser", "no"], var.ActivateScannersProbesProtectionParam)
    error_message = "Invalid input, options: \"yes - AWS Lambda log parser\", \"yes - Amazon Athena log parser\",\"no\"."
  }
}

locals {
  ScannersProbesAthenaLogParser = var.ActivateScannersProbesProtectionParam == "yes - Amazon Athena log parser" ? "yes" : "no"
}

locals {
  ScannersProbesLambdaLogParser = var.ActivateScannersProbesProtectionParam == "yes - AWS Lambda log parser" ? "yes" : "no"
}

variable "ScannersProbesProtectionActivated" {
  type        = string
  default     = "yes"
  description = ""
}

locals {
  AthenaLogParser = var.ActivateHttpFloodProtectionParam == "yes - Amazon Athena log parser" && var.ActivateScannersProbesProtectionParam == "yes - Amazon Athena log parser" ? "yes" : "no"
}

locals {
  LogParser = var.ActivateHttpFloodProtectionParam != "" && var.ActivateScannersProbesProtectionParam != "" ? "yes" : "no"
}

variable "BadBotProtectionActivated" {
  type        = string
  default     = "yes"
  description = ""
  validation {
    condition     = contains(["yes", "no"], var.BadBotProtectionActivated)
    error_message = "Invalid input, options: \"yes\",\"no\"."
  }
}

variable "ReputationListsProtectionActivated" {
  type        = string
  default     = "yes"
  description = ""
  validation {
    condition     = contains(["yes", "no"], var.ReputationListsProtectionActivated)
    error_message = "Invalid input, options: \"yes\",\"no\"."
  }
}

variable "IPRetentionPeriod" {
  type        = string
  default     = "no"
  description = ""
  validation {
    condition     = contains(["yes", "no"], var.IPRetentionPeriod)
    error_message = "Invalid input, options: \"yes\",\"no\"."
  }
}

locals {
  CustomResourceLambdaAccess = var.ReputationListsProtectionActivated == "yes" || local.AthenaLogParser == "yes" ? "yes" : "no"
}

locals {
  ALBScannersProbesAthenaLogParser = var.ActivateScannersProbesProtectionParam == "yes - Amazon Athena log parser" && var.ENDPOINT == "ALB" ? "yes" : "no"
}

locals {
  CloudFrontScannersProbesAthenaLogParser = var.ActivateScannersProbesProtectionParam == "yes - Amazon Athena log parser" && var.ENDPOINT == "cloudfront" ? "yes" : "no"
}

