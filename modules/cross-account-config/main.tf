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
  count = var.enable_circleci ? 1 : 0
}

# resource "aws_route53_zone" "ops" {
#   name = "ops.fitzroyacademy.net"

#   vpc {
#     vpc_id = module.vpc.vpc_id
#   }
# }



# data "aws_instance" "bastion" {
#   instance_id = "i-07888c2029e2adacc"
#   # this instance runs NAT:
#   # chmod a+x /etc/rc.local
#   # in rc.local:
#   # echo 1 > /proc/sys/net/ipv4/ip_forward
#   # iptables -t nat -A POSTROUTING -s 10.200.0.0/16 -j MASQUERADE
#   # source/destination check on the instance must be off
# }

# resource "aws_route53_zone" "new" {
#   name = "new.fitzroyacademy.com"
# }

# resource "aws_route53_record" "alpha" {
#   name = "new.fitzroyacademy.com"
#   type = "A"
#   zone_id = "${aws_route53_zone.new.id}"
#   alias {
#     name = "alpha.new.fitzroyacademy.com"
#     zone_id = "${aws_route53_zone.new.id}"
#     evaluate_target_health = true
#   }
# }

module "web_app_core" {
  source = "../web-app"
  # bastion_instance_id = data.aws_instance.bastion.instance_id
  account_number = var.account_number
  public_dns_name = "fitzroy.academy"
  private_dns_name = "fitzroy.io"
}

# module "web_app_staging" {
#   source = "../web-app-environment"
#   environment = "staging"
#   region = var.region
#   docker_tag = var.docker_tag
#   account_number = var.account_number
#   cluster_id = module.web_app_core.cluster_id
#   bastion_private_ip = module.web_app_core.bastion_private_ip
#   public_dns_zone_id = module.web_app_core.public_dns_zone
#   private_dns_zone_id = module.web_app_core.private_dns_zone
#   # public_cert_arn = aws_acm_certificate.public_cert.arn
#   public_cert_us_east_1_arn = var.public_cert_us_east_1_arn
# }