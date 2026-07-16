#!/usr/bin/env bash
set -euo pipefail

instance_id="${1:?EC2 instance ID is required}"
tag="${2:?release tag is required}"
repository="${GITHUB_REPOSITORY:?GitHub repository is required}"
github_token="${GITHUB_TOKEN:?GitHub token is required}"
github_api_url="${GITHUB_API_URL:-https://api.github.com}"
archive="openai-lb-x86_64-unknown-linux-gnu.tar.gz"
script_path="deploy/deploy-release.sh"
release_json="$(mktemp)"
response_headers="$(mktemp)"

cleanup() {
  rm -f "$release_json" "$response_headers"
}
trap cleanup EXIT

curl --fail --silent --show-error \
  --header "Accept: application/vnd.github+json" \
  --header "Authorization: Bearer $github_token" \
  --header "X-GitHub-Api-Version: 2022-11-28" \
  --output "$release_json" \
  "$github_api_url/repos/$repository/releases/tags/$tag"

resolve_asset_url() {
  local asset_name="$1"
  local asset_count
  local asset_id
  local http_status
  local location

  asset_count="$(jq --arg name "$asset_name" \
    '[.assets[] | select(.name == $name)] | length' "$release_json")"
  if [ "$asset_count" -ne 1 ]; then
    echo "Expected exactly one release asset named '$asset_name'; found $asset_count." >&2
    return 1
  fi

  asset_id="$(jq -r --arg name "$asset_name" \
    '.assets[] | select(.name == $name) | .id' "$release_json")"
  : > "$response_headers"
  http_status="$(curl --silent --show-error \
    --request GET \
    --max-redirs 0 \
    --header "Accept: application/octet-stream" \
    --header "Authorization: Bearer $github_token" \
    --header "X-GitHub-Api-Version: 2022-11-28" \
    --dump-header "$response_headers" \
    --output /dev/null \
    --write-out '%{http_code}' \
    "$github_api_url/repos/$repository/releases/assets/$asset_id")"

  if [ "$http_status" != 302 ]; then
    echo "GitHub did not return a download redirect for '$asset_name' (HTTP $http_status)." >&2
    return 1
  fi

  location="$(awk '
    tolower(substr($0, 1, 9)) == "location:" {
      sub(/^[^:]*:[[:space:]]*/, "")
      sub(/\r$/, "")
      print
      exit
    }
  ' "$response_headers")"
  if [ -z "$location" ]; then
    echo "GitHub returned a redirect without a Location header for '$asset_name'." >&2
    return 1
  fi

  printf '%s' "$location"
}

archive_url="$(resolve_asset_url "$archive")"
checksum_url="$(resolve_asset_url "$archive.sha256")"

# The token is only needed to exchange authenticated API requests for short-lived URLs.
unset GITHUB_TOKEN github_token

script_base64="$(base64 < "$script_path" | tr -d '\n')"
printf -v quoted_tag '%q' "$tag"
printf -v quoted_archive_url '%q' "$archive_url"
printf -v quoted_checksum_url '%q' "$checksum_url"
install_command="printf '%s' '$script_base64' | base64 -d > /tmp/openai-lb-deploy.sh"
run_command="bash /tmp/openai-lb-deploy.sh $quoted_tag $quoted_archive_url $quoted_checksum_url"
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
