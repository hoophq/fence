#!/usr/bin/env bash
# Simulated Claude Code session: the agent proposes a force-push; Leash pauses
# and asks the human to confirm. Rendered by docs/assets/ask.tape.
set -u
cd "$(dirname "$0")" && . ./lib.sh

sleep 0.5
user_say "the rebase looks good — push my branch"
sleep 1.0
printf '%s●%s I'\''ll force-push the rebased branch.\n\n' "$dot" "$rst"
sleep 1.0
printf '%s●%s %sBash%s(%sgit push --force origin feature/rebase%s)\n' "$dot" "$rst" "$tool" "$rst" "$cmd" "$rst"
sleep 1.3
printf '  %s└─%s %s 🐕 Leash needs your OK %s %sgit-force-push%s\n' "$dim" "$rst" "$ask" "$rst" "$dim" "$rst"
printf '     %sForce-push can overwrite history others depend on. Prefer%s\n' "$amber" "$rst"
printf '     %s--force-with-lease, or confirm if you are sure.%s\n\n' "$amber" "$rst"
printf '     %s[ Allow once ]%s    %s[ Deny ]%s\n\n' "$ok" "$rst" "$warn" "$rst"
sleep 1.8
printf '%s●%s Paused for your call — a force-push can clobber teammates'\'' commits.\n' "$dot" "$rst"
printf '  Want me to use --force-with-lease instead?\n'
sleep 5
