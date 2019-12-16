variable "environment" {}
variable "account_number" {}
variable "region" {}
variable "container_port" {
  default = 5000
}
variable "docker_tag" {
  default = "latest"
}
variable "public_dns_name" {}
variable "private_dns_name" {}