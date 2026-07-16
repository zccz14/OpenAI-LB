#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
temporary_dir="$(mktemp -d)"
fixture_dir="$temporary_dir/fixture"
mock_bin="$temporary_dir/bin"
captured_arguments="$temporary_dir/deploy-arguments"
ssm_parameters="$temporary_dir/ssm-parameters"
injection_marker="$temporary_dir/injected"

cleanup() {
  rm -rf "$temporary_dir"
  rm -f /tmp/openai-lb-deploy.sh
}
trap cleanup EXIT

mkdir -p "$fixture_dir/.github/scripts" "$fixture_dir/deploy" "$mock_bin"
cp "$repository_root/.github/scripts/send-deploy.sh" "$fixture_dir/.github/scripts/send-deploy.sh"

cat > "$fixture_dir/deploy/deploy-release.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > "$CAPTURED_ARGUMENTS"
EOF

cat > "$mock_bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

output=""
headers=""
accept=""
authorization=""
url=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      output="$2"
      shift 2
      ;;
    --dump-header)
      headers="$2"
      shift 2
      ;;
    --header)
      case "$2" in
        Accept:*) accept="$2" ;;
        Authorization:*) authorization="$2" ;;
      esac
      shift 2
      ;;
    --request|--max-redirs|--write-out)
      shift 2
      ;;
    --fail|--silent|--show-error)
      shift
      ;;
    *)
      url="$1"
      shift
      ;;
  esac
done

[ "$authorization" = "Authorization: Bearer short-lived-test-token" ]

case "$url" in
  */releases/tags/*)
    [ "$accept" = "Accept: application/vnd.github+json" ]
    if [ "$MOCK_SCENARIO" = "missing-checksum" ]; then
      printf '{"assets":[{"id":101,"name":"openai-lb-x86_64-unknown-linux-gnu.tar.gz"}]}' > "$output"
    else
      printf '{"assets":[{"id":101,"name":"openai-lb-x86_64-unknown-linux-gnu.tar.gz"},{"id":102,"name":"openai-lb-x86_64-unknown-linux-gnu.tar.gz.sha256"}]}' > "$output"
    fi
    ;;
  */releases/assets/101)
    [ "$accept" = "Accept: application/octet-stream" ]
    if [ "$MOCK_SCENARIO" = "missing-redirect" ]; then
      printf 'HTTP/2 200 OK\r\n\r\n' > "$headers"
      printf '200'
    elif [ "$MOCK_SCENARIO" = "missing-location" ]; then
      printf 'HTTP/2 302 Found\r\n\r\n' > "$headers"
      printf '302'
    else
      printf 'HTTP/2 302 Found\r\nLocation: %s\r\n\r\n' "$ARCHIVE_URL" > "$headers"
      printf '302'
    fi
    ;;
  */releases/assets/102)
    [ "$accept" = "Accept: application/octet-stream" ]
    printf 'HTTP/2 302 Found\r\nlocation: %s\r\n\r\n' "$CHECKSUM_URL" > "$headers"
    printf '302'
    ;;
  *)
    echo "Unexpected curl URL" >&2
    exit 1
    ;;
esac
EOF

cat > "$mock_bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "${GITHUB_TOKEN+x}" = x ]; then
  echo "GITHUB_TOKEN reached the AWS command" >&2
  exit 1
fi

operation="$1 $2"
shift 2

case "$operation" in
  "ssm send-command")
    parameters=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--parameters" ]; then
        parameters="$2"
        break
      fi
      shift
    done
    printf '%s' "$parameters" > "$SSM_PARAMETERS"
    while IFS= read -r command; do
      sh -c "$command"
    done < <(jq -r '.commands[]' <<< "$parameters")
    printf 'test-command-id\n'
    ;;
  "ssm wait")
    ;;
  "ssm get-command-invocation")
    printf '{"Status":"Success"}\n'
    ;;
  *)
    echo "Unexpected AWS operation: $operation" >&2
    exit 1
    ;;
esac
EOF

chmod +x "$fixture_dir/.github/scripts/send-deploy.sh" "$mock_bin/curl" "$mock_bin/aws"

archive_url="https://signed.example/archive?sig=val'ue&next=1;touch\${IFS}$injection_marker"
checksum_url="https://signed.example/checksum?sig=other&next=2"

run_send_deploy() {
  (
    cd "$fixture_dir"
    PATH="$mock_bin:$PATH" \
      CAPTURED_ARGUMENTS="$captured_arguments" \
      SSM_PARAMETERS="$ssm_parameters" \
      MOCK_SCENARIO="$1" \
      ARCHIVE_URL="$archive_url" \
      CHECKSUM_URL="$checksum_url" \
      GITHUB_REPOSITORY="zccz14/OpenAI-LB" \
      GITHUB_API_URL="https://api.github.test" \
      GITHUB_TOKEN="short-lived-test-token" \
      .github/scripts/send-deploy.sh "i-test" "v0.2.6"
  )
}

success_stdout="$temporary_dir/success.stdout"
success_stderr="$temporary_dir/success.stderr"
run_send_deploy success > "$success_stdout" 2> "$success_stderr"
printf 'v0.2.6\n%s\n%s\n' "$archive_url" "$checksum_url" > "$temporary_dir/expected-arguments"
if ! cmp -s "$temporary_dir/expected-arguments" "$captured_arguments"; then
  diff -u "$temporary_dir/expected-arguments" "$captured_arguments"
  exit 1
fi
if [ -e "$injection_marker" ]; then
  echo "Signed URL was evaluated as shell code" >&2
  exit 1
fi
if grep -q 'short-lived-test-token' "$ssm_parameters"; then
  echo "GITHUB_TOKEN was written into SSM parameters" >&2
  exit 1
fi

for sensitive_value in "short-lived-test-token" "$archive_url" "$checksum_url"; do
  if grep -Fq -- "$sensitive_value" "$success_stdout" || \
    grep -Fq -- "$sensitive_value" "$success_stderr"; then
    echo "Sensitive deployment value was written to send-deploy output" >&2
    exit 1
  fi
done

if run_send_deploy missing-checksum > /dev/null 2> "$temporary_dir/missing-checksum.err"; then
  echo "Missing checksum asset unexpectedly succeeded" >&2
  exit 1
fi
grep -q "Expected exactly one release asset named 'openai-lb-x86_64-unknown-linux-gnu.tar.gz.sha256'; found 0." \
  "$temporary_dir/missing-checksum.err"

if run_send_deploy missing-redirect > /dev/null 2> "$temporary_dir/missing-redirect.err"; then
  echo "Missing redirect unexpectedly succeeded" >&2
  exit 1
fi
grep -q "GitHub did not return a download redirect for 'openai-lb-x86_64-unknown-linux-gnu.tar.gz' (HTTP 200)." \
  "$temporary_dir/missing-redirect.err"

if run_send_deploy missing-location > /dev/null 2> "$temporary_dir/missing-location.err"; then
  echo "Redirect without Location unexpectedly succeeded" >&2
  exit 1
fi
grep -q "GitHub returned a redirect without a Location header for 'openai-lb-x86_64-unknown-linux-gnu.tar.gz'." \
  "$temporary_dir/missing-location.err"

echo "deploy script tests passed"
