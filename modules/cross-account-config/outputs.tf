output "public_ns_records" {
  value = module.web_app_live.public_ns_records
}

output "private_ns_records" {
  value = module.web_app_core.private_ns_records
}