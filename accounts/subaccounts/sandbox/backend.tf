terraform {
  backend "s3" {
    bucket         = "fitzroy-terraform-state"
    key            = "subaccounts/sandbox"
    region         = "us-east-2"
    dynamodb_table = "fitzroy-terraform-state-lock"
  }
}
