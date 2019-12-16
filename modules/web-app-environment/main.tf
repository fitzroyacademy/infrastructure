data "aws_route53_zone" "public" {
  zone_id = var.public_zone_id
}

data "aws_route53_zone" "private" {
  zone_id = var.private_zone_id
}

data "aws_acm_certificate" "public" {
  domain = var.public_dns_name
}

data "vpc" "web-app" {
  tags = {
    tf-web-app-vpc = "true"
  }
}
data "aws_subnet_ids" "public" {
  tags = {
    tf-public-subnets = "true"
  }
}

data "aws_subnet_ids" "private" {
  tags = {
    tf-private-subnets = "true"
  }
}

data "aws_route53_zone" "public" {
  tags = {
    tf-web-app-public-zone = "true"
  }
}

data "aws_route53_zone" "private" {
  tags = {
    tf-web-app-private-zone = "true"
  }
}

data "aws_instance" "bastion" {
  tags = {
    tf-web-app-bastion = "true"
  }
}

locals {
  db_endpoint = "db.${var.environment}.${data.aws_route53_zone.private.name}"
  assets_dns_name = "assets.${var.public_dns_name}"
}

resource "aws_kms_key" "rds" {
  description         = "Key for ${var.environment} RDS instance passwords"
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

resource "aws_iam_role" "web_app_task_role" {
  name               = "${var.environment}-WebAppECSTaskRole"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role_policy.json
  tags {
    environment = var.environment
  }
}

resource "aws_iam_role_policy" "web_app_ecs_task_policy" {
  name   = "web_app_ecs_task_policy"
  role   = aws_iam_role.web_app_task_role.id
  policy = data.aws_iam_policy_document.web_app_task_role_policy.json
}

resource "aws_iam_role_policy_attachment" "xray-attach" {
  role       = aws_iam_role.web_app_task_role.name
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
    effect  = "Allow"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      "arn:aws:secretsmanager:${var.region}:${var.account_number}:secret:web-app-${var.environment}-db-password-??????",
      "arn:aws:secretsmanager:${var.region}:${var.account_number}:secret:web-app-${var.environment}-secret-key-??????",
      "arn:aws:secretsmanager:${var.region}:${var.account_number}:secret:web-app-mailgun-api-key-??????"
    ]
  }
  statement {
    effect  = "Allow"
    actions = ["ssm:GetParameter","ssm:GetParameters"]
    resources = [
      aws_ssm_parameter.mailgun_api_url.arn
    ]
  }
  statement {
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:ReEncryptTo", "kms:GenerateDataKey", "kms:DescribeKey", "kms:ReEncryptFrom"]
    resources = [aws_kms_key.rds.arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${aws_s3_bucket.static_assets.bucket}/*"]
  }
}

data "template_file" "web_app_task_definition" {
  template = file("${path.module}/files/task_definition.json")
  vars = {
    region          = var.region
    environment     = var.environment
    secret_key_arn  = aws_secretsmanager_secret.secret-key.arn
    db_password_arn = aws_secretsmanager_secret.rds-password.arn
    docker_image    = "${var.account_number}.dkr.ecr.${var.region}.amazonaws.com/fitzroy-academy/web-app:${var.docker_tag}"
    db_endpoint     = aws_route53_record.db.fqdn
    container_port  = var.container_port
    mailgun_api_key_arn = aws_secretsmanager_secret.mailgun-api-key.arn
    mailgun_url_arn = aws_ssm_parameter.mailgun_api_url.arn
    s3_bucket  = aws_s3_bucket.static_assets.bucket
  }
}

resource "aws_ecs_task_definition" "web-app-service" {
  family                   = "web-app-${var.environment}"
  requires_compatibilities = ["FARGATE"]
  container_definitions    = data.template_file.web_app_task_definition.rendered
  task_role_arn            = aws_iam_role.web_app_task_role.arn
  execution_role_arn       = aws_iam_role.web_app_task_role.arn
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  tags {
    environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "web-app-log-group" {
  name = "/ecs/web-app/${var.environment}"
    tags {
    environment = var.environment
  }
}

# resource "aws_cloudwatch_log_group" "xray-log-group" {
#   name = "/ecs/web-app/${var.environment}/xray"
#   tags {
#     environment = var.environment
#   }
# }

resource "aws_security_group" "alb_sg" {
  name        = "web_app_${var.environment}_alb_sg"
  description = "Allows public traffic to the ${var.environment} web app ALB"
  vpc_id      = var.vpc_id

  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  ingress {
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]

  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags {
    environment = var.environment
  }
}

# resource "aws_security_group" "xray_sg" {
#   name        = "xray_${var.environment}_container_sg"
#   description = "Attached to the xray instances"
#   vpc_id      = var.vpc_id

#   ingress {
#     from_port       = 2000
#     to_port         = 2000
#     protocol        = "tcp"
#     security_groups = [aws_security_group.container_sg.id]
#   }

#   ingress {
#     from_port       = 2000
#     to_port         = 2000
#     protocol        = "udp"
#     security_groups = [aws_security_group.container_sg.id]
#   }

#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = ["0.0.0.0/0"]
#   }
# }

resource "aws_security_group" "container_sg" {
  name        = "web_app_${var.environment}_container_sg"
  description = "Attached to the ${var.environment} container instances"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags {
    environment = var.environment
  }
}

resource "aws_lb" "web_app_alb" {
  name               = "web-app-${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = data.aws_subnet_ids.public

  enable_deletion_protection = true
  # access_logs {
  #   bucket  = "${aws_s3_bucket.lb_logs.bucket}"
  #   prefix  = "test-lb"
  #   enabled = true
  # }

  tags = {
    environment = var.environment
  }
}

resource "aws_alb_target_group" "web-app" {
  name        = "web-app-${var.environment}-tg"
  port        = var.container_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id
}

resource "aws_ecs_service" "web_app" {
  name                              = "web-app-${var.environment}"
  cluster                           = var.cluster_id
  task_definition                   = aws_ecs_task_definition.web-app-service.arn
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 30
  desired_count                     = 1
  depends_on = [
    aws_iam_role_policy.web_app_ecs_task_policy,
    aws_lb_listener.web_app_public
  ]

  load_balancer {
    target_group_arn = aws_alb_target_group.web-app.arn
    container_name   = aws_ecs_task_definition.web-app-service.family
    container_port   = var.container_port
  }
  network_configuration {
    subnets          = data.aws_subnet_ids.private
    security_groups  = [aws_security_group.container_sg.id]
    assign_public_ip = false
  }
  tags {
    environment = var.environment
  }
}

resource "aws_lb_listener" "web_app_public" {
  load_balancer_arn = aws_lb.web_app_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      host        = "#{host}"
      path        = "/#{path}"
      port        = "443"
      protocol    = "HTTPS"
      query       = "#{query}"
      status_code = "HTTP_301"
    }
    target_group_arn = aws_alb_target_group.web-app.arn
  }
}

resource "aws_lb_listener" "web_app_public_https" {
  load_balancer_arn = aws_lb.web_app_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = data.aws_acm_certificate.public.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.web-app.arn
  }
}

resource "aws_security_group" "db_sg" {
  name        = "web_app_${var.environment}_db_sg"
  description = "Allows ${var.environment} db traffic"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.container_sg.id]
  }

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["${var.bastion_private_ip}/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
      tags {
    environment = var.environment
  }
}

resource "aws_db_instance" "db" {
  allocated_storage      = 20
  storage_type           = "gp2"
  engine                 = "postgres"
  engine_version         = "10.6"
  skip_final_snapshot    = true
  instance_class         = "db.t2.micro"
  name                   = "fitzroyacademy"
  identifier             = "${var.environment}webapp"
  username               = "fitzroyacademy"
  multi_az               = false
  password               = aws_secretsmanager_secret_version.db-password.secret_string
  parameter_group_name   = "default.postgres10"
  db_subnet_group_name   = aws_db_subnet_group.web-app.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  tags = {
    environment = var.environment
  }
}


resource "aws_route53_record" "app" {
  zone_id = var.public_dns_zone_id
  name    = "${var.public_dns_name}"
  type    = "A"
  alias {
    name                   = aws_lb.web_app_alb.dns_name
    zone_id                = aws_lb.web_app_alb.zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "db" {
  zone_id = var.private_dns_zone_id
  name    = local.db_endpoint
  type    = "CNAME"
  ttl     = "60"
  records = [aws_db_instance.db.address]
}


resource "aws_db_subnet_group" "web-app" {
  name       = "web_app_${var.environment}"
  subnet_ids = data.aws_subnet_ids.private
}


resource "aws_secretsmanager_secret" "rds-password" {
  description = "web-app ${var.environment} rds password"
  kms_key_id  = aws_kms_key.rds
  name        = "web-app-${var.environment}-db-password"
}



resource "aws_secretsmanager_secret" "secret-key" {
  description = "web-app ${var.environment} secret key"
  name        = "web-app-${var.environment}-secret-key"
}

resource "random_string" "db-password" {
  length  = 16
  special = false
}


resource "random_string" "secret-key" {
  length  = 16
  special = false
}


resource "aws_secretsmanager_secret_version" "db-password" {
  lifecycle {
    ignore_changes = [secret_string]
  }
  secret_id     = aws_secretsmanager_secret.rds-password.id
  secret_string = chomp(random_string.db-password.result)
}

resource "aws_secretsmanager_secret_version" "secret-key" {
  lifecycle {
    ignore_changes = [secret_string]
  }
  secret_id     = aws_secretsmanager_secret.secret-key.id
  secret_string = random_string.secret-key.result
}

resource "aws_s3_bucket" "static_assets" {
  bucket = "${var.environment}-web-app-static-assets"
  policy = "${data.aws_iam_policy_document.static_assets.json}"
    cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "HEAD"]
    allowed_origins = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

data "aws_iam_policy_document" "static_assets" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${var.environment}-web-app-static-assets/*"]

    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
  }

  statement {
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.environment}-web-app-static-assets"]

    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
  }
}


resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "Origin Identity for ${var.environment} static assets"
}

resource "aws_cloudfront_distribution" "static_assets" {
  origin {
      s3_origin_config {
    origin_access_identity = "${aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path}"
  }
    domain_name = aws_s3_bucket.static_assets.bucket_regional_domain_name
    origin_id   = "${var.environment}-web-app-static-assets"
  }
  enabled             = true
  default_cache_behavior {
    viewer_protocol_policy = "redirect-to-https"
    compress               = true
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD", "OPTIONS"]
    target_origin_id       = "${var.environment}-web-app-static-assets"
    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
      headers = [
        "Origin",
        "Access-Control-Request-Headers",
        "Access-Control-Request-Method",
      ]
    }
  }
  restrictions {
    geo_restriction{
    restriction_type = "none"
  }
  }
  aliases = [local.assets_dns_name]

  viewer_certificate {
    # cloudfront_default_certificate = true
    acm_certificate_arn = var.public_cert_us_east_1_arn
    ssl_support_method  = "sni-only"
  }
}


resource "aws_route53_record" "static_assets" {
  zone_id = var.public_dns_zone_id
  name    = local.assets_dns_name
  type    = "A"

  alias {
    name                   = "${aws_cloudfront_distribution.static_assets.domain_name}"
    zone_id                = "${aws_cloudfront_distribution.static_assets.hosted_zone_id}"
    evaluate_target_health = false
  }
}