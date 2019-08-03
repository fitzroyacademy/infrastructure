variable "environment" {
}

variable "account_number" {

}

variable "region" {

}

variable "vpc_id" {

}

variable "container_port" {
  default = 5000
}

variable "docker_tag" {
  default = "latest"
}

variable "public_subnets" {
  type = "list"
}

variable "private_subnets" {
  type = "list"
}

variable "cluster_id" {}

variable "bastion_private_ip" {}

variable "public_dns_zone_id" {
}

variable "private_dns_zone_id" {}

variable "public_dns_name" {}

variable "private_dns_zone_name" {}

variable "rds_kms_key" {

}

variable "public_cert_arn" {}