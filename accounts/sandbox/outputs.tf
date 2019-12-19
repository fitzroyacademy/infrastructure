output "public_ns_records" {
  value = module.cross_account_config.public_ns_records
}

output "private_ns_records" {
  value = module.cross_account_config.private_ns_records
}

output "bastion_public_ip" {
  value = module.cross_account_config.bastion_public_ip
}