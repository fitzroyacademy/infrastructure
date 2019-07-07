# infrastructure

Provides automation to ensure that security controls are activated, the required cross-account roles are active, and infrastructure is configured in Fitzroy AWS accounts. For now, this includes "static" application infrastructure, making this a small monolith.

## Development

You need a working version of [Terraform](https://terraform.io) with the correct version; it is currently 0.11.3.

## Contributing

You will need official Fitzroy Academy credentials in order to complete these steps.

1. Install Terraform
2. Configure your [AWS credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)
3. Create a branch for your changes
4. Test locally using `terraform plan` to ensure there are no compilation errors
5. Create a PR to master, which will execute a `terraform plan` on CircleCI
6. If your changes are accepted, the work will be merged into master and applied
7. If there is an error, the repository will be rolled back