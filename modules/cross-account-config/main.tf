# main.tf
locals {
  administrator_cross_account_role_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
  terraform_cross_account_role_policy_arns     = ["arn:aws:iam::aws:policy/IAMFullAccess", "arn:aws:iam::aws:policy/AdministratorAccess"]
}

data "aws_iam_policy_document" "cross_account_assume_role_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.main_account_number}:user/fitzroy-terraform-administrator"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "cross_account_assume_role" {
  name               = "TerraformCrossAccountRole"
  assume_role_policy = data.aws_iam_policy_document.cross_account_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "cross_account_assume_role" {
  count = length(local.terraform_cross_account_role_policy_arns)

  role       = aws_iam_role.cross_account_assume_role.name
  policy_arn = element(local.terraform_cross_account_role_policy_arns, count.index)
}

resource "aws_iam_role" "cross_account_administrator" {
  name               = "UserCrossAccountAdministrator"
  assume_role_policy = data.aws_iam_policy_document.cross_account_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "cross_account_administrator" {
  count = length(local.administrator_cross_account_role_policy_arns)

  role = aws_iam_role.cross_account_administrator.name
  policy_arn = element(
    local.administrator_cross_account_role_policy_arns,
    count.index,
  )
}

resource "aws_iam_role" "circleci_cross_account_assume_role" {
  name               = "CircleCICrossAccountRole"
  assume_role_policy = data.aws_iam_policy_document.circleci_cross_account_assume_role_policy[0].json
  count = var.enable_circleci ? 1 : 0
}

data "aws_iam_policy_document" "circleci_cross_account_assume_role_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.main_account_number}:user/circleci"]
    }

    actions = ["sts:AssumeRole"]
  }
  count = var.enable_circleci ? 1 : 0
}

data "aws_iam_policy_document" "circleci_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["ecr:PutImage"]
    resources = ["arn:aws:ecr:*:${var.account_number}:repository/*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage"]
    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["ecs:UpdateService"]
    resources = ["arn:aws:ecs:*"]
  }
  count = var.enable_circleci ? 1 : 0
}

resource "aws_iam_role_policy" "ci_policy" {
  name = "circleci_role_policy"
  role = aws_iam_role.circleci_cross_account_assume_role[0].id
  policy = data.aws_iam_policy_document.circleci_permissions[0].json
}

resource "aws_kms_key" "rds" {
  description         = "Key for RDS instance passwords"
  enable_key_rotation = true
  policy              = <<POLICY
{
  "Id": "key-policy",
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::${var.account_number}:root"
        ]
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow use of the key",
      "Effect": "Allow",
      "Principal": {"AWS": [
        "${module.alpha_env.web_app_task_role_arn}"
      ]},
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    }
  ]
}
POLICY

}

resource "aws_kms_alias" "rds" {
  name = "alias/rds"
  target_key_id = aws_kms_key.rds.key_id
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_ecs_cluster" "web-app-cluster" {
  name = "sandbox-web-app-cluster"
}

resource "aws_ecr_repository" "fitzroy-docker-image-repo" {
  name = "fitzroy-academy/web-app"
}

resource "aws_route53_zone" "ops" {
  name = "ops.fitzroyacademy.net"

  vpc {
    vpc_id = module.vpc.vpc_id
  }
}

data "aws_instance" "bastion" {
  instance_id = "i-07888c2029e2adacc"
  # this instance runs NAT:
  # chmod a+x /etc/rc.local
  # in rc.local:
  # echo 1 > /proc/sys/net/ipv4/ip_forward
  # iptables -t nat -A POSTROUTING -s 10.200.0.0/16 -j MASQUERADE
  # source/destination check on the instance must be off
}

resource "aws_route53_zone" "new" {
  name = "new.fitzroyacademy.com"
}

module "vpc" {
  source = "../vpc"
  name = "sandbox-vpc"
  cidr = "10.200.0.0/16"

  azs = [data.aws_availability_zones.available.names[0], data.aws_availability_zones.available.names[1], data.aws_availability_zones.available.names[2]]
  private_subnets = ["10.200.0.0/24", "10.200.1.0/24", "10.200.2.0/24"]
  public_subnets = ["10.200.3.0/24", "10.200.4.0/24", "10.200.5.0/24"]

  enable_vpn_gateway = false
  enable_nat_gateway = false
  enable_s3_endpoint = false
  single_nat_gateway = true
  enable_ecr_dkr_endpoint = true
  ecr_dkr_endpoint_private_dns_enabled = true
  ecr_dkr_endpoint_security_group_ids = [aws_security_group.dkr_sg.id]
  enable_dns_hostnames = true
  # enable_logs_endpoint = true
  # logs_endpoint_security_group_ids = ...
  # logs_endpoint_private_dns_enabled = true
}

resource "aws_security_group" "dkr_sg" {
  name = "ecs_dkr_sg"
  description = "Allow HTTPS inbound traffic to dkr private endpoint"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = [module.vpc.vpc_cidr_block]
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_route" "ec2_nat_gateway" {
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id = data.aws_instance.bastion.network_interface_id
  route_table_id = module.vpc.private_route_table_ids[count.index]
  count = length(module.vpc.private_route_table_ids)
}

# resource "aws_acm_certificate" "public_cert_new" {
#   domain_name = "new.fitzroyacademy.com"
#   validation_method = "DNS"

#   subject_alternative_names = ["*.new.fitzroyacademy.com", "*.alpha.new.fitzroyacademy.com"]

#   lifecycle {
#     create_before_destroy = true
#   }
# }

resource "aws_acm_certificate" "public_cert" {
  domain_name = "new.fitzroyacademy.com"
  validation_method = "DNS"

  subject_alternative_names = ["*.new.fitzroyacademy.com"]

  lifecycle {
    create_before_destroy = true
  }
}


resource "aws_acm_certificate" "public_cert_new" {
  domain_name = "new.fitzroyacademy.com"
  validation_method = "DNS"

  subject_alternative_names = ["*.new.fitzroyacademy.com", "*.alpha.new.fitzroyacademy.com"]

  lifecycle {
    create_before_destroy = true
  }
}




# resource "aws_route53_record" "public_cert_validation_new" {
#   name = "${aws_acm_certificate.public_cert_new.domain_validation_options.0.resource_record_name}"
#   type = "${aws_acm_certificate.public_cert_new.domain_validation_options.0.resource_record_type}"
#   zone_id = "${aws_route53_zone.new.id}"
#   records = ["${aws_acm_certificate.public_cert_new.domain_validation_options.0.resource_record_value}"]
#   ttl = 60
# }

# resource "aws_route53_record" "public_cert_validation_new_1" {
#   name = "${aws_acm_certificate.public_cert_new.domain_validation_options.1.resource_record_name}"
#   type = "${aws_acm_certificate.public_cert_new.domain_validation_options.1.resource_record_type}"
#   zone_id = "${aws_route53_zone.new.id}"
#   records = ["${aws_acm_certificate.public_cert_new.domain_validation_options.1.resource_record_value}"]
#   ttl = 60
# }

resource "aws_route53_record" "alpha" {
  name = "new.fitzroyacademy.com"
  type = "A"
  zone_id = "${aws_route53_zone.new.id}"
  alias {
    name = "alpha.new.fitzroyacademy.com"
    zone_id = "${aws_route53_zone.new.id}"
    evaluate_target_health = true
  }
}

# resource "aws_acm_certificate_validation" "cert" {
#   certificate_arn = "${aws_acm_certificate.public_cert.arn}"
#   validation_record_fqdns = ["${aws_route53_record.public_cert_validation_new.fqdn}","${aws_route53_record.public_cert_validation_new_1.fqdn}"]
# }

module "alpha_env" {
  source = "../web-app"
  environment = "alpha"
  region = var.region
  vpc_id = module.vpc.vpc_id
  docker_tag = var.docker_tag
  account_number = var.account_number
  public_subnets = module.vpc.public_subnets
  private_subnets = module.vpc.private_subnets
  cluster_id = aws_ecs_cluster.web-app-cluster.id
  bastion_private_ip = data.aws_instance.bastion.private_ip
  public_dns_zone_id = aws_route53_zone.new.zone_id
  private_dns_zone_id = aws_route53_zone.ops.zone_id
  public_dns_name = aws_route53_zone.new.name
  private_dns_zone_name = aws_route53_zone.ops.name
  rds_kms_key = aws_kms_key.rds.key_id
  public_cert_arn = aws_acm_certificate.public_cert.arn
  public_cert_us_east_1_arn = var.public_cert_us_east_1_arn
}