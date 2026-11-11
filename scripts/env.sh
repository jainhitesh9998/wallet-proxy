#!/bin/sh
# Toolchains installed under ~/.local/tools (JDK 21, Maven, Node 22), when there are any: elsewhere the tools on the
# PATH are used. Sourced by the other scripts, which run with "set -e": this must succeed without that directory.
if [ -f "$HOME/.local/tools/env.sh" ]; then
  . "$HOME/.local/tools/env.sh"
fi
