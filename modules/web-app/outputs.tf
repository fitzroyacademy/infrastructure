# output "public_ns_records" {
#   value = aws_route53_zone.public.name_servers
# }

output "private_ns_records" {
  value = aws_route53_zone.private_reserve.name_servers
}

output "bastion_public_ip" {
  value = aws_eip.bastion.public_ip
}