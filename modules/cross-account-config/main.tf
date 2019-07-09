# main.tf
locals {
  administrator_cross_account_role_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
  terraform_cross_account_role_policy_arns = ["arn:aws:iam::aws:policy/IAMFullAccess", "arn:aws:iam::aws:policy/AdministratorAccess"]
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
  assume_role_policy = "${data.aws_iam_policy_document.cross_account_assume_role_policy.json}"
}

resource "aws_iam_role_policy_attachment" "cross_account_assume_role" {
  count = "${length(local.terraform_cross_account_role_policy_arns)}"

  role       = "${aws_iam_role.cross_account_assume_role.name}"
  policy_arn = "${element(local.terraform_cross_account_role_policy_arns, count.index)}"
}

resource "aws_iam_role" "cross_account_administrator" {
  name               = "UserCrossAccountAdministrator"
  assume_role_policy = "${data.aws_iam_policy_document.cross_account_assume_role_policy.json}"
}

resource "aws_iam_role_policy_attachment" "cross_account_administrator" {
  count = "${length(local.administrator_cross_account_role_policy_arns)}"

  role       = "${aws_iam_role.cross_account_administrator.name}"
  policy_arn = "${element(local.administrator_cross_account_role_policy_arns, count.index)}"
}

resource "aws_iam_role" "circleci_cross_account_assume_role" {
  name               = "CircleCICrossAccountRole"
  assume_role_policy = "${data.aws_iam_policy_document.circleci_cross_account_assume_role_policy.json}"
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
    effect = "Allow"
    actions = ["ecr:PutImage"]
    resources = ["arn:aws:ecr:*:${var.account_number}:repository/fitzroy-academy/web-app"]
  }

  statement {
    effect = "Allow"
    actions = ["ecr:GetAuthorizationToken", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload","ecr:BatchCheckLayerAvailability","ecr:BatchGetImage"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "ci_policy" {
  name = "circleci_role_policy"
  role = "${aws_iam_role.circleci_cross_account_assume_role.id}"

  policy = "${data.aws_iam_policy_document.circleci_permissions.json}"
}

resource "aws_ecr_repository" "fitzroy-docker-image-repo" {
  name = "fitzroy-academy/web-app"
}

resource "aws_ecs_cluster" "web-app-cluster" {
  name = "${var.account_name}-web-app-cluster"
}

resource "aws_iam_role" "web_app_task_role" {
  name               = "WebAppECSTaskRole"
  assume_role_policy = "${data.aws_iam_policy_document.web_app_task_role_assume_role_policy.json}"
}
resource "aws_iam_role_policy" "web_app_ecs_task_policy" {
  name = "web_app_ecs_task_policy"
  role = "${aws_iam_role.web_app_task_role.id}"

  policy = "${data.aws_iam_policy_document.web_app_task_role_policy.json}"
}
data "aws_iam_policy_document" "web_app_task_role_assume_role_policy" {
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
    effect = "Allow"
    actions = ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability","ecr:BatchGetImage","ecr:GetDownloadUrlForLayer"]
    resources = ["*"]
  }
  statement {
    effect = "Allow"
    actions = ["logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:*:log-group:/ecs/*","arn:aws:logs:*:*:log-group:/ecs/*:*:*"]
  }
  statement {
    effect = "Allow"
    actions = ["logs:CreateLogGroup","logs:CreateLogStream"]
    resources = ["*"]
  }
}

# data ""

resource "aws_ecs_task_definition" "web-app-service" {
  family                = "web-app-tf"
  requires_compatibilities = ["FARGATE"]
  container_definitions = "${file("${path.module}/files/task_definition.json")}"
  task_role_arn = "${aws_iam_role.web_app_task_role.arn}"
  execution_role_arn = "${aws_iam_role.web_app_task_role.arn}"
  network_mode = "awsvpc"
  cpu = 1024
  memory = 2048
}

resource "aws_cloudwatch_log_group" "web-app-log-group" {
  name = "/ecs/web-app-tf"
}

data "aws_availability_zones" "available" {
  state = "available"
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> v1.0"
  name = "sandbox-vpc"
  cidr = "10.200.0.0/16"

  azs             = ["${data.aws_availability_zones.available.names[0]}","${data.aws_availability_zones.available.names[1]}","${data.aws_availability_zones.available.names[2]}"]
  private_subnets = ["10.200.0.0/24", "10.200.1.0/24", "10.200.2.0/24"]
  public_subnets  = ["10.200.3.0/24", "10.200.4.0/24", "10.200.5.0/24"]

  enable_vpn_gateway = false
  enable_nat_gateway = true
  single_nat_gateway = true
  enable_s3_endpoint = true
  enable_ecr_dkr_endpoint = true
  ecr_dkr_endpoint_private_dns_enabled = true
  ecr_dkr_endpoint_security_group_ids = ["${aws_security_group.dkr_sg.id}"]
  enable_dns_hostnames = true
  # enable_logs_endpoint = true
  # logs_endpoint_security_group_ids = ...
  # logs_endpoint_private_dns_enabled = true
}

resource "aws_security_group" "dkr_sg" {
  name        = "ecs_dkr_sg"
  description = "Allow HTTPS inbound traffic"
  vpc_id      = "${module.vpc.vpc_id}"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["${module.vpc.vpc_cidr_block}"]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "alb_sg" {
  name        = "web_app_alb_sg"
  description = "Allows public traffic to the web app ALB"
  vpc_id      = "${module.vpc.vpc_id}"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["209.6.145.111/32"]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "container_sg" {
  name        = "web_app_container_sg"
  description = "Attached to the container instances"
  vpc_id      = "${module.vpc.vpc_id}"

  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    security_groups = ["${aws_security_group.alb_sg.id}"]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "web_app_alb" {
  name               = "web-app-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["${aws_security_group.alb_sg.id}"]
  subnets            = ["${module.vpc.public_subnets}"]

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
  name     = "web-app-tg"
  port     = 5000
  protocol = "HTTP"
  target_type = "ip"
  vpc_id   = "${module.vpc.vpc_id}"
}

resource "aws_ecs_service" "web_app" {
  name            = "web-app"
  cluster         = "${aws_ecs_cluster.web-app-cluster.id}"
  task_definition = "${aws_ecs_task_definition.web-app-service.arn}"
  launch_type = "FARGATE"
  desired_count   = 2
  depends_on      = ["aws_iam_role_policy.web_app_ecs_task_policy"]

  load_balancer {
    target_group_arn = "${aws_lb_target_group.web-app.arn}"
    container_name   = "${aws_ecs_task_definition.web-app-service.family}"
    container_port   = 5000
  }
  network_configuration {
    subnets = ["${module.vpc.private_subnets}"]
    security_groups = ["${aws_security_group.container_sg.id}"]
    assign_public_ip = false
  }
}

resource "aws_lb_listener" "web_app_public" {
  load_balancer_arn = "${aws_lb.web_app_alb.arn}"
  port              = "80"
  protocol          = "HTTP"
  # ssl_policy        = "ELBSecurityPolicy-2016-08"
  # certificate_arn   = "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4"

  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.web-app.arn}"
  }
}