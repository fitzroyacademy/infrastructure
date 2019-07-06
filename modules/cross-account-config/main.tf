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
    resources = ["arn:aws:ecr:*:${var.account_number}:repository/web-app"]
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
  name = "web-app"
}

resource "aws_ecs_cluster" "web-app-cluster" {
  name = "${var.account_name}-web-app-cluster"
}