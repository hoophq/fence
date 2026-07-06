#!/usr/bin/env bash
# Simulated Claude Code session: everyday commands pass without Fence stepping
# in — the near-zero-false-positive promise. Rendered by docs/assets/safe.tape.
set -u
cd "$(dirname "$0")" && . ./lib.sh

sleep 0.5
user_say "deps are stale — reinstall them from scratch"
sleep 1.0
printf '%s●%s Cleaning and reinstalling.\n\n' "$dot" "$rst"
sleep 1.0
printf '%s●%s %sBash%s(%srm -rf node_modules && npm install%s)\n' "$dot" "$rst" "$tool" "$rst" "$cmd" "$rst"
sleep 1.5
printf '  %s└─%s added 1043 packages in 12s     %s🚧 allowed%s\n\n' "$dim" "$rst" "$ok" "$rst"
sleep 1.4
printf '%s●%s Done. Fence stayed out of the way — wiping node_modules is\n' "$dot" "$rst"
printf '  workspace-local and routine, so there'\''s no prompt to slow you down.\n'
sleep 5
