provider "aws" {
  region                  = "${var.region}"
  profile                 = "fitzroy-terraform-administrator"
  shared_credentials_file = "~/.aws/credentials"
}

data "terraform_remote_state" "main_state" {
  backend = "s3"

  config {
    bucket = "fitzroy-terraform-state"
    key    = "fitzroy/"
    region = "us-east-2"
  }
}

provider "aws" {
  region = "${var.region}"
  alias  = "subaccount"

  assume_role {
    role_arn     = "arn:aws:iam::${var.account_number}:role/TerraformCrossAccountRole"
    session_name = "terraform"
  }
}

module "cross_account_config" {
  source = "../../../modules/cross-account-config"

  providers {
    aws = "aws.subaccount"
  }

  main_account_number = "${data.terraform_remote_state.main_state.account_number}"
  account_number      = "${var.account_number}"
  account_name        = "${var.account_name}"
}

resource "aws_ecr_repository" "fitzroy-docker-image-repo" {
  name = "${var.account_name}-repo"
}

resource "aws_ecs_cluster" "web-app-cluster" {
  name = "${var.account_name}-web-app-cluster"
}

# resource "aws_ecs_task_definition" "web-app-service" {
#   family                = "web-app-service"
#   requires_compatibilities = "FARGATE"

#   cpu = 1
#   memory = 32
# }