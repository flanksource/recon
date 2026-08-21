#!/bin/sh
set -eu

root=${0%/*}
args_log=$root/argv.log
environment_log=$root/environment.log
report=$root/findings.ocsf.json

printf '%s\n' __invocation__ >> "$args_log"
if [ "${CLOUDFLARE_API_TOKEN+x}" = x ]; then token=set; else token=unset; fi
if [ "${CLOUDFLARE_API_KEY+x}" = x ]; then key=set; else key=unset; fi
if [ "${CLOUDFLARE_API_EMAIL+x}" = x ]; then email=set; else email=unset; fi
if [ "${PROWLER_UNRELATED+x}" = x ]; then unrelated=set; else unrelated=unset; fi
if [ "${PROVIDER_TOKEN+x}" = x ]; then provider_token=set; else provider_token=unset; fi
printf '%s\n' "cloudflare-token=$token cloudflare-key=$key cloudflare-email=$email unrelated=$unrelated provider-token=$provider_token" >> "$environment_log"
if [ "$provider_token" = set ]
then
  printf 'credential output %s\n' "$PROVIDER_TOKEN"
fi
if [ "$token" = set ]
then
  printf 'credential output %s\n' "$CLOUDFLARE_API_TOKEN"
fi

output_directory=
while [ "$#" -gt 0 ]
do
  argument=$1
  shift
  printf '%s\n' "$argument" >> "$args_log"
  if [ "$argument" = "--output-directory" ]
  then
    output_directory=$1
    shift
    printf '%s\n' "$output_directory" >> "$args_log"
  fi
done

if [ -z "$output_directory" ]
then
  printf '%s\n' "missing --output-directory" >&2
  exit 2
fi

mkdir -p "$output_directory"
cp "$report" "$output_directory/report.ocsf.json"
printf '%s\n' "provider output" > "$output_directory/report.csv"
printf '%s\n' "<html>provider output</html>" > "$output_directory/report.html"
printf '%s\n' "completed provider audit"
exit_code=3
if [ -f "$root/exit-code" ]
then
  IFS= read -r exit_code < "$root/exit-code"
fi
exit "$exit_code"
