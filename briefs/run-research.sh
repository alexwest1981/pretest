#!/usr/bin/env bash
# Read the brief from a file so nothing re-quotes it. Orca already starts us in the worktree.
set -u
brief="$1"
exec codex exec -s danger-full-access --skip-git-repo-check "$(cat "$brief")"
