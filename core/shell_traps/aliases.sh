#!/usr/bin/env bash
#
# ---------------------------------------------------------------------------
# ISOL8R :: Project Sandtrap - Anti-Automation Layer
# ---------------------------------------------------------------------------
# README (please read before cursing at your terminal):
#   This file defines a delightful collection of aliases and shell functions
#   whose sole purpose is to frustrate lazy recon scripts, punish reflexive
#   copy/pasters, and generally convince intruders that automation is a bad
#   life choice. Every trap logs to the central bait ledger so the incident
#   response team can admire failed attempts in chronological order.
#
#   Highlights:
#     * Common commands (cat/ls/strings) emit sarcasm and tattletale logs.
#     * Clipboard helpers are overridden to shame anyone trying to yoink flags.
#     * The log path is configurable via $ISOL8R_BAIT_LOG, defaulting to the
#       project's canonical /app/logs/bait.log location.
#     * Commands remain recoverable through fully qualified paths or by
#       unsetting the aliases--assuming you figure that out before rage quitting.
# ---------------------------------------------------------------------------

__isol8r_bait_log="${ISOL8R_BAIT_LOG:-/app/logs/bait.log}"
__isol8r_bait_dir="$(dirname "${__isol8r_bait_log}")"
mkdir -p "${__isol8r_bait_dir}" 2>/dev/null || true

__isol8r_log_attempt() {
  local invoked="$1"; shift || true
  local timestamp
  timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
  local pieces=("${invoked}")
  if (($# > 0)); then
    local arg
    for arg in "$@"; do
      pieces+=("$(printf "%q" "${arg}")")
    done
  fi
  local assembled="${pieces[0]}"
  if ((${#pieces[@]} > 1)); then
    assembled="${pieces[*]}"
  fi
  printf "[TRAP] User tried '%s' at %s\n" "${assembled}" "${timestamp}" >> "${__isol8r_bait_log}"
}

__isol8r_alias_cat() {
  __isol8r_log_attempt "cat" "$@"
  echo "nice try, file predator"
  return 1
}

__isol8r_alias_ls() {
  __isol8r_log_attempt "ls" "$@"
  echo "In this house... we use find."
  return 1
}

__isol8r_alias_strings() {
  __isol8r_log_attempt "strings" "$@"
  echo "Nope, you'll find nothing but suffering."
  return 1
}

__isol8r_alias_pbcopy() {
  __isol8r_log_attempt "pbcopy" "$@"
  echo "Copying flags is for quitters."
  return 1
}

__isol8r_alias_xclip() {
  __isol8r_log_attempt "xclip" "$@"
  echo "This ain't Windows, chief."
  return 1
}

alias cat='__isol8r_alias_cat '
alias ls='__isol8r_alias_ls '
alias strings='__isol8r_alias_strings '
alias pbcopy='__isol8r_alias_pbcopy '
alias xclip='__isol8r_alias_xclip '

# Bonus annoyance: warn on habitual clipboard shortcuts
__isol8r_clipboard_notice() {
  local last_cmd="${BASH_COMMAND:-unknown}"
  case "${last_cmd}" in
    *copy*|*paste* )
      __isol8r_log_attempt "clipboard-automation" "${last_cmd}"
      ;;
  esac
}

if [[ -n "${BASH_VERSION:-}" ]]; then
  trap '__isol8r_clipboard_notice' DEBUG
fi
