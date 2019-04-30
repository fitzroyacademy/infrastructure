provider "aws" {
  region                  = "${var.region}"
  profile                 = "fitzroy-terraform-administrator"
  shared_credentials_file = "~/.aws/credentials"
}

terraform {
  backend "s3" {
    bucket         = "fitzroy-terraform-state"
    key            = "fitzroy/"
    region         = "us-east-2"
    dynamodb_table = "fitzroy-terraform-state-lock"
  }
}

resource "aws_s3_bucket" "terraform_state" {
  bucket = "fitzroy-terraform-state"
  acl    = "private"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags {
    cost-center = "aws-management"
  }
}

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "fitzroy-cloudtrail-logs"
  acl    = "private"

  versioning {
    enabled = false
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags {
    cost-center = "aws-management"
  }
}

resource "aws_s3_bucket" "config" {
  bucket = "fitzroy-aws-config"
  acl    = "private"

  versioning {
    enabled = false
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags {
    cost-center = "aws-management"
  }
}

resource "aws_dynamodb_table" "terraform_state_lock" {
  name           = "fitzroy-terraform-state-lock"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  lifecycle {
    prevent_destroy = true
  }

  tags {
    cost-center = "aws-management"
  }
}

resource "aws_cloudtrail" "organization_trail" {
  name                          = "cloudtrail-all-regions"
  s3_bucket_name                = "${aws_s3_bucket.cloudtrail_logs.bucket}"
  include_global_service_events = true
  is_organization_trail         = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3"]
    }
  }

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda"]
    }
  }

  tags {
    cost-center = "aws-management"
  }

  kms_key_id = "arn:aws:kms:us-east-2:937516216284:key/1e2a395b-5c3e-47c3-a0da-6fb633cc28e4"
}

resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = "${aws_s3_bucket.cloudtrail_logs.bucket}"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck20150319",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::fitzroy-cloudtrail-logs"
        },
        {
            "Sid": "AWSCloudTrailWrite20150319",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::fitzroy-cloudtrail-logs/AWSLogs/937516216284/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        },
        {
            "Sid": "AWSCloudTrailWrite20150319",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::fitzroy-cloudtrail-logs/AWSLogs/o-4b1zhzcs6n/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        },
        {
            "Sid": "DenyDeletesOfAnyKind",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:DeleteObject*",
            "Resource": "arn:aws:s3:::fitzroy-cloudtrail-logs/*"
        }
    ]
}
POLICY
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = "aws-config"
  is_enabled = true
  depends_on = ["aws_config_delivery_channel.main"]
}

resource "aws_config_delivery_channel" "main" {
  name           = "aws-config"
  s3_bucket_name = "${aws_s3_bucket.config.bucket}"
  s3_key_prefix  = ""

  snapshot_delivery_properties = {
    delivery_frequency = "Six_Hours"
  }

  depends_on = ["aws_config_configuration_recorder.main"]
}

resource "aws_config_configuration_recorder" "main" {
  name     = "aws-config"
  role_arn = "${aws_iam_role.main.arn}"

  recording_group = {
    all_supported                 = true
    include_global_resource_types = true
  }
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "aws-config-policy" {
  statement {
    actions   = ["s3:PutObject*"]
    resources = ["arn:aws:s3:::${aws_s3_bucket.config.bucket}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    actions   = ["s3:GetBucketAcl"]
    resources = ["arn:aws:s3:::${aws_s3_bucket.config.bucket}"]
  }
}

# Allow IAM policy to assume the role for AWS Config
data "aws_iam_policy_document" "aws-config-role-policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    effect = "Allow"
  }
}

#
# IAM
#

resource "aws_iam_role" "main" {
  name = "aws-config-role"

  assume_role_policy = "${data.aws_iam_policy_document.aws-config-role-policy.json}"
}

resource "aws_iam_policy_attachment" "managed-policy" {
  name       = "aws-config-managed-policy"
  roles      = ["${aws_iam_role.main.name}"]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}

resource "aws_iam_policy" "aws-config-policy" {
  name   = "aws-config-policy"
  policy = "${data.aws_iam_policy_document.aws-config-policy.json}"
}

resource "aws_iam_policy_attachment" "aws-config-policy" {
  name       = "aws-config-policy"
  roles      = ["${aws_iam_role.main.name}"]
  policy_arn = "${aws_iam_policy.aws-config-policy.arn}"
}
