# Shared styling + helpers for the Leash demo players (demo/*.sh), rendered to
# GIFs by docs/assets/*.tape via VHS. 24-bit color keeps contrast consistent
# regardless of the terminal theme.
e=$'\e'
rst="${e}[0m"
dim="${e}[38;2;127;132;156m"        # muted gray
usr="${e}[38;2;205;214;244m"        # user text
dot="${e}[38;2;235;160;110m"        # Claude turn bullet
tool="${e}[1;38;2;203;166;247m"     # tool name (bold mauve)
cmd="${e}[38;2;137;180;250m"        # command (blue)
warn="${e}[38;2;243;139;168m"       # deny reason (soft red)
amber="${e}[38;2;249;226;175m"      # ask reason (soft yellow)
ok="${e}[38;2;166;227;161m"         # allowed (green)
deny="${e}[48;2;210;45;55m${e}[38;2;255;255;255m${e}[1m"   # white on red
ask="${e}[48;2;240;175;60m${e}[38;2;24;24;37m${e}[1m"      # dark on amber

type_out() { local s=$1 i; for ((i = 0; i < ${#s}; i++)); do printf '%s' "${s:i:1}"; sleep 0.022; done; }
user_say() { printf '%s>%s ' "$dim" "$usr"; type_out "$1"; printf '%s\n\n' "$rst"; }
