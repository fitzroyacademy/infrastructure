# main.tf
locals {
  administrator_cross_account_role_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
  terraform_cross_account_role_policy_arns = ["arn:aws:iam::aws:policy/IAMFullAccess", "arn:aws:iam::aws:policy/ReadOnlyAccess",
  "arn:aws:iam::aws:policy/CloudFrontFullAccess"]
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