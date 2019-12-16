# output "web_app_task_role_arn" {
#   value = aws_iam_role.web_app_task_role.arn
# }

output "public_ns_records" {
  value = aws_route53_zone.public.name_servers
}