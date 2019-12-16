variable "environment" {}
variable "account_number" {}
variable "region" {}
variable "vpc_id" {}
variable "container_port" {
  default = 5000
}
variable "docker_tag" {
  default = "latest"
}
variable "cluster_id" {}
variable "public_cert_arn" {}
variable "public_cert_us_east_1_arn" {}