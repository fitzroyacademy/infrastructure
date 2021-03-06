resource "aws_ecs_cluster" "web-app-cluster" {
  name = "web-app"
  tags = {
    cost-tracking          = "web-app"
    tf-web-app-ecs-cluster = "true"
  }
}

resource "aws_kms_alias" "rds" {
  name          = "alias/rds"
  target_key_id = aws_kms_key.rds.key_id
}


resource "aws_ecr_repository" "fitzroy-docker-image-repo" {
  name = "fitzroy-academy/web-app"
  tags = {
    cost-tracking = "web-app"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# data "aws_ami" "amazon-linux-2" {
#  most_recent = true

#  filter {
#    name   = "owner-alias"
#    values = ["amazon"]
#  }

#  filter {
#    name   = "name"
#    values = ["amzn2-ami-hvm*"]
#  }
# }

resource "aws_eip" "bastion" {
  instance   = aws_instance.bastion.id
  vpc        = true
  depends_on = [module.vpc]
  tags = {
    cost-tracking = "web-app"
  }
}

resource "aws_iam_role" "bastion" {
  name = "bastion"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
  tags = {
    cost-tracking = "web-app"
  }
}

resource "aws_iam_role_policy_attachment" "bastion" {
  role = aws_iam_role.bastion.name
  policy_arn = aws_iam_policy.bastion.arn
}

resource "aws_iam_policy" "bastion" {
  name        = "bastion"
  description = "Bastion instance permissions"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ecr:GetAuthorizationToken",
                    "ecr:BatchGetImage",
            "ecr:GetDownloadUrlForLayer",
            "ecr:GetRepositoryPolicy",
            "ecr:ListImages",
            "ecr:DescribeRepositories"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_instance_profile" "bastion" {
  name = "bastion"
  role = aws_iam_role.bastion.name
}
resource "aws_key_pair" "rsavage" {
  key_name = "rsavage"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGABR1H00bSoRk6iC9AGbGbA1MJI+l1tU75NllU81KRqLz9cd+kpznw+vyd5fJQDevwbSAlE3ga5al+koP7F3QY0W4uLtLSYnPyVxVnU1R7kL5jgPnTTWDLXK3cDtTHiLIp/qm+KGT2FPJ4iTO7bxGPPFxJsK04qREHK4GRcTCODQACAu6omiaUpw+LV/wv/P6spxvObyCG/FD5gPTW/cgCwEgrfM2xcUlfVmEoLvNRz/rJlJLpDm32104XeUvDCKtUYFeU+PmCVogKduMzy10gbCRlDlYvcY1ctJq165i9qcsTMBkZN1ij1/st6IaDDN95izSS9Nlh9NrEGrv9hdt"
}

resource "aws_security_group" "bastion" {
  name = "bastion"
  description = "Allow bastion traffic"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = [module.vpc.vpc_cidr_block]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  tags = {
    Name = "bastion"
    cost-tracking = "web-app"
  }
}

resource "aws_instance" "bastion" {
  # ami                         = data.aws_ami.amazon-linux-2.id
  ami = "ami-059d92a736f307c9c"
  instance_type = "t2.nano"
  subnet_id = module.vpc.public_subnets[0]
  key_name = aws_key_pair.rsavage.key_name
  vpc_security_group_ids = [aws_security_group.bastion.id]
  source_dest_check = false
  iam_instance_profile = aws_iam_instance_profile.bastion.name
  tags = {
    tf-web-app-bastion = "true"
    cost-tracking = "web-app"
  }
  # user_data = "chmod a+x /etc/rc.local; echo 'echo 1 > /proc/sys/net/ipv4/ip_forward' >> /etc/rc.local; echo 'iptables -t nat -A POSTROUTING -s 10.200.0.0/16 -j MASQUERADE' >> /etc/rc.local"
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
  tags = {
    cost-tracking = "web-app"
  }
}

resource "aws_route" "ec2_nat_gateway" {
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id = aws_instance.bastion.primary_network_interface_id
  route_table_id = module.vpc.private_route_table_ids[count.index]
  count = length(module.vpc.private_route_table_ids)
}

module "vpc" {
  source = "../vpc"
  name = "web-app"
  cidr = "10.200.0.0/16"

  azs = [data.aws_availability_zones.available.names[0], data.aws_availability_zones.available.names[1], data.aws_availability_zones.available.names[2]]
  private_subnets = ["10.200.0.0/24", "10.200.1.0/24", "10.200.2.0/24"]
  public_subnets = ["10.200.3.0/24", "10.200.4.0/24", "10.200.5.0/24"]

  public_subnet_tags = {
    tf-public-subnet = "true"
  }
  private_subnet_tags = {
    tf-private-subnet = "true"
  }
  vpc_tags = {
    tf-web-app-vpc = "true"
  }
  tags = {
    cost-tracking = "web-app"
  }

  enable_vpn_gateway = false
  enable_nat_gateway = false
  enable_s3_endpoint = false
  single_nat_gateway = true
  enable_ecr_dkr_endpoint = true
  ecr_dkr_endpoint_private_dns_enabled = true
  ecr_dkr_endpoint_security_group_ids = [aws_security_group.dkr_sg.id]
  enable_dns_hostnames = true
}


resource "aws_kms_key" "rds" {
  description = "Key for RDS instance passwords"
  enable_key_rotation = true
  policy = <<POLICY
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
    }
  ]
}
POLICY
  tags = {
    cost-tracking = "web-app"
  }
}


resource "aws_secretsmanager_secret" "mailgun-api-key" {
  description = "mailgun api key"
  name        = "mailgun-api-key"
  tags = {
    cost-tracking = "web-app"
  }
}

resource "aws_secretsmanager_secret_version" "mailgun-api-key" {
  lifecycle {
    ignore_changes = [secret_string]
  }
  secret_id     = aws_secretsmanager_secret.mailgun-api-key.id
  secret_string = "initial"
}


resource "aws_ssm_parameter" "mailgun_api_url" {
  name  = "mailgun-api-url"
  type  = "String"
  value = "initial"
  lifecycle {
    ignore_changes = [value]
  }
  tags = {
    cost-tracking = "web-app"
  }
}

resource "aws_route53_zone" "private" {
  name = var.private_dns_name
  tags = {
    cost-tracking           = "web-app"
    tf-web-app-private-zone = "true"
  }
  vpc {
    vpc_id = module.vpc.vpc_id
  }
}

resource "aws_route53_record" "bastion" {
  zone_id = aws_route53_zone.private_reserve.zone_id
  name = "bastion.${aws_route53_zone.private_reserve.name}"
  type = "A"
  ttl = "900"
  records = [aws_eip.bastion.public_ip]
}

# Create a zone for the "private" zone, but don't put any records in it.
# This will ensure nobody can hit us in case private DNS resolution ever
# fails.
resource "aws_route53_zone" "private_reserve" {
  name = var.private_dns_name
  tags = {
    cost-tracking = "web-app"
  }
}

resource "aws_s3_bucket" "deploy_artifacts" {
  bucket = "web-app-deploy-artifacts"
  acl    = "private"
  tags = {
    cost-tracking = "web-app"
  }
}
