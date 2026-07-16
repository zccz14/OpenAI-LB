#!/usr/bin/env bash
set -euo pipefail

instance_id="${1:?EC2 instance ID is required}"
tag="${2:?release tag is required}"
script_path="deploy/deploy-release.sh"

script_base64="$(base64 < "$script_path" | tr -d '\n')"
printf -v quoted_tag '%q' "$tag"
install_command="printf '%s' '$script_base64' | base64 -d > /tmp/openai-lb-deploy.sh"
run_command="bash /tmp/openai-lb-deploy.sh $quoted_tag"
parameters="$(jq -cn \
  --arg install "$install_command" \
  --arg run "$run_command" \
  '{commands:[$install,$run]}')"

command_id="$(aws ssm send-command \
  --instance-ids "$instance_id" \
  --document-name AWS-RunShellScript \
  --comment "Deploy OpenAI-LB $tag" \
  --parameters "$parameters" \
  --query 'Command.CommandId' \
  --output text)"

wait_status=0
aws ssm wait command-executed \
  --command-id "$command_id" \
  --instance-id "$instance_id" || wait_status=$?

aws ssm get-command-invocation \
  --command-id "$command_id" \
  --instance-id "$instance_id" \
  --query '{Status:Status,StandardOutput:StandardOutputContent,StandardError:StandardErrorContent}'

exit "$wait_status"
