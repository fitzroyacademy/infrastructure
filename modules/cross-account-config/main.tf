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
  assume_role_policy = data.aws_iam_policy_document.circleci_cross_account_assume_role_policy.json
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
}

data "aws_iam_policy_document" "circleci_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["ecr:PutImage"]
    resources = ["arn:aws:ecr:*:${var.account_number}:repository/fitzroy-academy/web-app"]
  }

  statement {
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "ci_policy" {
  name = "circleci_role_policy"
  role = aws_iam_role.circleci_cross_account_assume_role.id

  policy = data.aws_iam_policy_document.circleci_permissions.json
}

resource "aws_ecr_repository" "fitzroy-docker-image-repo" {
  name = "fitzroy-academy/web-app"
}

resource "aws_ecs_cluster" "web-app-cluster" {
  name = "${var.account_name}-web-app-cluster"
}

resource "aws_iam_role" "web_app_task_role" {
  name               = "WebAppECSTaskRole"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role_policy.json
}

resource "aws_iam_role" "xray_task_role" {
  name               = "XRayECSTaskRole"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role_policy.json
}

resource "aws_iam_role_policy" "web_app_ecs_task_policy" {
  name = "web_app_ecs_task_policy"
  role = aws_iam_role.web_app_task_role.id

  policy = data.aws_iam_policy_document.web_app_task_role_policy.json
}

resource "aws_iam_role_policy_attachment" "xray-attach" {
  role       = aws_iam_role.xray_task_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

data "aws_iam_policy_document" "ecs_assume_role_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

data "aws_iam_policy_document" "web_app_task_role_policy" {
  statement {
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    resources = ["*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:*:log-group:/ecs/*", "arn:aws:logs:*:*:log-group:/ecs/*:*:*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream"]
    resources = ["*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.stage-rds-password.arn,aws_secretsmanager_secret.prod-rds-password.arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["kms:Decrypt","kms:Encrypt","kms:ReEncryptTo","kms:GenerateDataKey","kms:DescribeKey","kms:ReEncryptFrom"]
    resources = [aws_kms_key.rds.arn]
  }
}

# data ""

resource "aws_ecs_task_definition" "web-app-service" {
  family                   = "web-app-tf"
  requires_compatibilities = ["FARGATE"]
  container_definitions    = file("${path.module}/files/task_definition.json")
  task_role_arn            = aws_iam_role.web_app_task_role.arn
  execution_role_arn       = aws_iam_role.web_app_task_role.arn
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
}

resource "aws_ecs_task_definition" "xray-service" {
  family                   = "xray-daemon"
  requires_compatibilities = ["FARGATE"]
  container_definitions    = file("${path.module}/files/xray_task_definition.json")
  task_role_arn            = aws_iam_role.xray_task_role.arn
  execution_role_arn       = aws_iam_role.xray_task_role.arn
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 1024
}

resource "aws_cloudwatch_log_group" "web-app-log-group" {
  name = "/ecs/web-app-tf"
}

resource "aws_cloudwatch_log_group" "xray-log-group" {
  name = "/ecs/web-app-tf/xray"
}

data "aws_availability_zones" "available" {
  state = "available"
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> v2.0"
  name    = "sandbox-vpc"
  cidr    = "10.200.0.0/16"

  azs             = [data.aws_availability_zones.available.names[0], data.aws_availability_zones.available.names[1], data.aws_availability_zones.available.names[2]]
  private_subnets = ["10.200.0.0/24", "10.200.1.0/24", "10.200.2.0/24"]
  public_subnets  = ["10.200.3.0/24", "10.200.4.0/24", "10.200.5.0/24"]

  enable_vpn_gateway                   = false
  enable_nat_gateway                   = true
  single_nat_gateway                   = true
  enable_s3_endpoint                   = true
  enable_ecr_dkr_endpoint              = true
  ecr_dkr_endpoint_private_dns_enabled = true
  ecr_dkr_endpoint_security_group_ids  = [aws_security_group.dkr_sg.id]
  enable_dns_hostnames                 = true
  # enable_logs_endpoint = true
  # logs_endpoint_security_group_ids = ...
  # logs_endpoint_private_dns_enabled = true
}

resource "aws_security_group" "dkr_sg" {
  name        = "ecs_dkr_sg"
  description = "Allow HTTPS inbound traffic"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    # TF-UPGRADE-TODO: In Terraform v0.10 and earlier, it was sometimes necessary to
    # force an interpolation expression to be interpreted as a list by wrapping it
    # in an extra set of list brackets. That form was supported for compatibilty in
    # v0.11, but is no longer supported in Terraform v0.12.
    #
    # If the expression in the following list itself returns a list, remove the
    # brackets to avoid interpretation as a list of lists. If the expression
    # returns a single list item then leave it as-is and remove this TODO comment.
    cidr_blocks = [module.vpc.vpc_cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "alb_sg" {
  name        = "web_app_alb_sg"
  description = "Allows public traffic to the web app ALB"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["67.186.135.213/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "xray_sg" {
  name        = "xray__container_sg"
  description = "Attached to the xray instances"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 2000
    to_port         = 2000
    protocol        = "tcp"
    security_groups = [aws_security_group.container_sg.id]
  }

    ingress {
    from_port       = 2000
    to_port         = 2000
    protocol        = "udp"
    security_groups = [aws_security_group.container_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "container_sg" {
  name        = "web_app_container_sg"
  description = "Attached to the container instances"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 5000
    to_port         = 5000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "web_app_alb" {
  name               = "web-app-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  # TF-UPGRADE-TODO: In Terraform v0.10 and earlier, it was sometimes necessary to
  # force an interpolation expression to be interpreted as a list by wrapping it
  # in an extra set of list brackets. That form was supported for compatibilty in
  # v0.11, but is no longer supported in Terraform v0.12.
  #
  # If the expression in the following list itself returns a list, remove the
  # brackets to avoid interpretation as a list of lists. If the expression
  # returns a single list item then leave it as-is and remove this TODO comment.
  subnets = module.vpc.public_subnets

  enable_deletion_protection = true
  # access_logs {
  #   bucket  = "${aws_s3_bucket.lb_logs.bucket}"
  #   prefix  = "test-lb"
  #   enabled = true
  # }

  # tags = {
  #   Environment = "production"
  # }
}

resource "aws_lb_target_group" "web-app" {
  name        = "web-app-tg"
  port        = 5000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = module.vpc.vpc_id
}

resource "aws_ecs_service" "web_app" {
  name            = "web-app"
  cluster         = aws_ecs_cluster.web-app-cluster.id
  task_definition = aws_ecs_task_definition.web-app-service.arn
  launch_type     = "FARGATE"
  desired_count   = 2
  depends_on = [
    aws_iam_role_policy.web_app_ecs_task_policy,
    aws_lb_listener.web_app_public,
    aws_iam_role.xray_task_role
  ]

  load_balancer {
    target_group_arn = aws_lb_target_group.web-app.arn
    container_name   = aws_ecs_task_definition.web-app-service.family
    container_port   = 5000
  }
  network_configuration {
    subnets          = module.vpc.private_subnets
    security_groups  = [aws_security_group.container_sg.id]
    assign_public_ip = false
  }
}

resource "aws_lb_listener" "web_app_public" {
  load_balancer_arn = aws_lb.web_app_alb.arn
  port              = "80"
  protocol          = "HTTP"

  # ssl_policy        = "ELBSecurityPolicy-2016-08"
  # certificate_arn   = "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web-app.arn
  }
}

resource "aws_security_group" "db_sg" {
  name        = "web_app_db_sg"
  description = "Allows local db traffic"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.container_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "stage_db" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = "postgres"
  engine_version       = "10.6"
  instance_class       = "db.t2.micro"
  name                 = "stagewebapp"
  identifier = "stagewebapp"
  username             = "fitzroyacademy"
  multi_az = false
  password = jsondecode(aws_secretsmanager_secret_version.stage-password.secret_string)["password"]
  parameter_group_name = "default.postgres10"
  db_subnet_group_name  = aws_db_subnet_group.web-app.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]
}

resource "aws_route53_zone" "ops" {
  name = "ops.fitzroyacademy.net"

  vpc {
    vpc_id = module.vpc.vpc_id
  }
}

resource "aws_route53_record" "stage-db" {
  zone_id = aws_route53_zone.ops.zone_id
  name    = "db.stage.ops.fitzroyacademy.net"
  type    = "CNAME"
  ttl     = "60"
  records        = [aws_db_instance.stage_db.address]
}


resource "aws_db_subnet_group" "web-app" {
  name       = "web_app"
  subnet_ids = [module.vpc.private_subnets[0], module.vpc.private_subnets[1], module.vpc.private_subnets[2]]
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
        "${aws_iam_role.web_app_task_role.arn}"
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

resource "aws_secretsmanager_secret" "prod-rds-password" {
  description = "web-app prod rds password"
  kms_key_id = aws_kms_key.rds.key_id
  name = "web-app-prod-db-password"
}

resource "aws_secretsmanager_secret" "stage-rds-password" {
  description = "web-app staging rds password"
  kms_key_id = aws_kms_key.rds.key_id
  name = "web-app-stage-db-password"
}

resource "random_string" "prod-password" {
  length = 16
  special = false
}

resource "random_string" "stage-password" {
  length = 16
  special = false
}

resource "aws_secretsmanager_secret_version" "stage-password" {
  lifecycle {
    ignore_changes = [secret_string]
  }
  secret_id = aws_secretsmanager_secret.stage-rds-password.id
  secret_string = <<EOF
{
  "password": "${random_string.stage-password.result}"
}
EOF

}

resource "aws_secretsmanager_secret_version" "prod-password" {
lifecycle {
ignore_changes = [secret_string]
}
secret_id     = aws_secretsmanager_secret.prod-rds-password.id
secret_string = <<EOF
{
  "password": "${random_string.prod-password.result}"
}
EOF

}

