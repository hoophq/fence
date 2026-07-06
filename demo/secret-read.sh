#!/usr/bin/env bash
# Simulated Claude Code session: the agent tries to read cloud credentials into
# its context (no network yet); Fence asks first, since the read alone leaks the
# secret to the model. Rendered by docs/assets/secret-read.tape.
set -u
cd "$(dirname "$0")" && . ./lib.sh

sleep 0.5
user_say "which AWS account am I on?"
sleep 1.0
printf '%s●%s Let me check your credentials file.\n\n' "$dot" "$rst"
sleep 1.0
printf '%s●%s %sBash%s(%scat ~/.aws/credentials%s)\n' "$dot" "$rst" "$tool" "$rst" "$cmd" "$rst"
sleep 1.3
printf '  %s└─%s %s 🚧 Fence needs your OK %s %ssecret-read-into-context%s\n' "$dim" "$rst" "$ask" "$rst" "$dim" "$rst"
printf '     %sA cloud credential is being dumped to stdout, which reads its%s\n' "$amber" "$rst"
printf '     %scontents into the agent'\''s context. Confirm this is intended.%s\n\n' "$amber" "$rst"
sleep 1.8
printf '%s●%s Reading the raw file would pull your keys into my context. Safer to\n' "$dot" "$rst"
printf '  run %saws sts get-caller-identity%s instead — want me to do that?\n' "$cmd" "$rst"
sleep 5
