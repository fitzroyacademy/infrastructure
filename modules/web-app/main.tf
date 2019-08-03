resource "aws_iam_role" "web_app_task_role" {
  name               = "${var.environment}-WebAppECSTaskRole"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role_policy.json
}

resource "aws_iam_role_policy" "web_app_ecs_task_policy" {
  name = "web_app_ecs_task_policy"
  role = aws_iam_role.web_app_task_role.id
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
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [
    "arn:aws:secretsmanager:${var.region}:${var.account_number}:secret:web-app-${var.environment}-db-password-??????",
    "arn:aws:secretsmanager:${var.region}:${var.account_number}:secret:web-app-${var.environment}-secret-key-??????"
    ]
  }
  statement {
    effect    = "Allow"
    actions   = ["kms:Decrypt","kms:Encrypt","kms:ReEncryptTo","kms:GenerateDataKey","kms:DescribeKey","kms:ReEncryptFrom"]
    resources = ["arn:aws:kms:${var.region}:${var.account_number}:key/${var.rds_kms_key}"]
  }
}

data "template_file" "web_app_task_definition" {
  template = file("${path.module}/files/task_definition.json")
  vars = {
    region = var.region
    environment = var.environment
    secret_key_arn = aws_secretsmanager_secret.secret-key.arn
    db_password_arn = aws_secretsmanager_secret.rds-password.arn
    docker_image = "${var.account_number}.dkr.ecr.${var.region}.amazonaws.com/fitzroy-academy/web-app:${var.docker_tag}"
    db_endpoint = "db.${var.environment}.ops.fitzroyacademy.net"
    container_port = var.container_port
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
}

resource "aws_cloudwatch_log_group" "web-app-log-group" {
  name = "/ecs/web-app/${var.environment}"
}

resource "aws_cloudwatch_log_group" "xray-log-group" {
  name = "/ecs/web-app/${var.environment}/xray"
}

resource "aws_security_group" "alb_sg" {
  name        = "web_app_${var.environment}_alb_sg"
  description = "Allows public traffic to the ${var.environment} web app ALB"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443 
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]

  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "xray_sg" {
  name        = "xray_${var.environment}_container_sg"
  description = "Attached to the xray instances"
  vpc_id      = var.vpc_id

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
  name        = "web_app_${var.environment}_container_sg"
  description = "Attached to the container instances"
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
}

resource "aws_lb" "web_app_alb" {
  name               = "web-app-${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets = var.public_subnets

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
  name            = "web-app-${var.environment}"
  cluster         = var.cluster_id
  task_definition = aws_ecs_task_definition.web-app-service.arn
  launch_type     = "FARGATE"
  health_check_grace_period_seconds  = 30
  desired_count   = 1
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
    subnets          = var.private_subnets
    security_groups  = [aws_security_group.container_sg.id]
    assign_public_ip = false
  }
}

resource "aws_lb_listener" "web_app_public" {
  load_balancer_arn = aws_lb.web_app_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "redirect"
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
  ssl_policy =      "ELBSecurityPolicy-2016-08"
  certificate_arn = var.public_cert_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.web-app.arn
  }
}

resource "aws_security_group" "db_sg" {
  name        = "web_app_${var.environment}_db_sg"
  description = "Allows local db traffic"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
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
}

resource "aws_db_instance" "db" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = "postgres"
  engine_version       = "10.6"
  skip_final_snapshot = true
  instance_class       = "db.t2.micro"
  name                 = "fitzroyacademy"
  identifier = "${var.environment}webapp"
  username             = "fitzroyacademy"
  multi_az = false
  password = aws_secretsmanager_secret_version.db-password.secret_string
  parameter_group_name = "default.postgres10"
  db_subnet_group_name  = aws_db_subnet_group.web-app.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  tags = {
    environment = var.environment
  }
}


resource "aws_route53_record" "app" {
  zone_id = var.public_dns_zone_id
  name = "${var.environment}.${var.public_dns_name}"
  type = "A"
  alias {
    name = aws_lb.web_app_alb.dns_name
    zone_id = aws_lb.web_app_alb.zone_id
    evaluate_target_health = false
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

resource "aws_route53_record" "db" {
  zone_id = var.private_dns_zone_id
  name    = "db.${var.environment}.${var.private_dns_zone_name}"
  type    = "CNAME"
  ttl     = "60"
  records        = [aws_db_instance.db.address]
}


resource "aws_db_subnet_group" "web-app" {
  name       = "web_app_${var.environment}"
  subnet_ids = var.private_subnets
}


resource "aws_secretsmanager_secret" "rds-password" {
  description = "web-app ${var.environment} rds password"
  kms_key_id = var.rds_kms_key
  name = "web-app-${var.environment}-db-password"
}


resource "aws_secretsmanager_secret" "secret-key" {
  description = "web-app ${var.environment} secret key"
  name = "web-app-${var.environment}-secret-key"
}

resource "random_string" "db-password" {
  length = 16
  special = false
}


resource "random_string" "secret-key" {
  length = 16
  special = false
}


resource "aws_secretsmanager_secret_version" "db-password" {
    lifecycle {
    ignore_changes = [secret_string]
  }
  secret_id = aws_secretsmanager_secret.rds-password.id
  secret_string = chomp(random_string.db-password.result)
}
resource "aws_secretsmanager_secret_version" "secret-key" {
    lifecycle {
    ignore_changes = [secret_string]
  }
  secret_id = aws_secretsmanager_secret.secret-key.id
  secret_string = random_string.secret-key.result
}